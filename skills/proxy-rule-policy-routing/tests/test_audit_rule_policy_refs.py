from __future__ import annotations

import contextlib
import io
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SKILL = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "audit_rule_policy_refs", SKILL / "scripts" / "audit_rule_policy_refs.py"
)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class RulePolicyAuditTests(unittest.TestCase):
    ACTIVE_PROFILES = (
        "Egern/AutoEgern.yaml", "Egern/AutoEgernLite.yaml",
        "Mihomo/AutoMihomo.Mobile.yaml", "Mihomo/AutoMihomo.OpenWrt.yaml",
        "Mihomo/SafeMihomo.yaml", "Stash/AutoStash.yaml",
    )

    def make_repo(self, repo: Path) -> None:
        for relative in self.ACTIVE_PROFILES:
            path = repo / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text("rules: []\n", encoding="utf-8")

    def test_six_canonical_profiles_complete_coverage_without_loon(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.make_repo(repo)
            payload = audit.audit(repo, [])
            self.assertEqual({item["path"] for item in payload["checked"]}, set(self.ACTIVE_PROFILES))
            self.assertEqual(payload["missing"], [])
            self.assertEqual(payload["skipped"], [])

    def test_each_active_canonical_profile_remains_required(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.make_repo(repo)
            for relative in self.ACTIVE_PROFILES:
                with self.subTest(profile=relative):
                    path = repo / relative
                    original = path.read_bytes()
                    path.unlink()
                    payload = audit.audit(repo, [])
                    self.assertEqual([item["path"] for item in payload["missing"]], [relative])
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(audit.main([str(repo), "--json"]), 2)
                    path.write_bytes(original)

    def test_leftover_loon_profiles_never_enter_active_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.make_repo(repo)
            before = audit.audit(repo, [])
            (repo / "Loon").mkdir()
            for relative in ("Loon/AutoLoon.conf", "Loon/AutoLoonLite.conf", "Loon/Extra.conf"):
                (repo / relative).write_bytes(b"\xff")
            after = audit.audit(repo, [])
            self.assertEqual({item["path"] for item in after["skipped"]}, {"Loon/AutoLoon.conf", "Loon/AutoLoonLite.conf"})
            self.assertTrue(all(item["reason"] == "retired-profile" for item in after["skipped"]))
            self.assertEqual({key: value for key, value in before.items() if key != "skipped"},
                             {key: value for key, value in after.items() if key != "skipped"})

    def test_egern_lite_unknown_policy_is_checked_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "Egern/AutoEgernLite.yaml"
            path.parent.mkdir()
            path.write_text("rules:\n  - domain:\n      match: fixture.invalid\n      policy: LiteGhost\n", encoding="utf-8")
            payload = audit.audit(repo, [])
            self.assertEqual([item["path"] for item in payload["checked"]], ["Egern/AutoEgernLite.yaml"])
            self.assertEqual([item["policy"] for item in payload["undefined_rule_policies"]], ["LiteGhost"])
            self.assertEqual(payload["undefined_rule_policies"][0]["file"], "Egern/AutoEgernLite.yaml")

    def test_missing_profiles_do_not_pass_and_retired_lite_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "Loon/AutoLoonLite.conf"
            path.parent.mkdir()
            path.write_text("[Rule]\nFINAL,RetiredGhost\n", encoding="utf-8")
            payload = audit.audit(repo, [])
            self.assertEqual(payload["checked"], [])
            self.assertEqual(payload["rule_references"], [])
            self.assertEqual(len(payload["missing"]), 6)
            self.assertIn({"client": "Loon", "path": "Loon/AutoLoonLite.conf", "reason": "retired-profile"}, payload["skipped"])
            self.assertIn("Egern/AutoEgernLite.yaml", {item["path"] for item in payload["missing"]})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main([str(repo), "--json"]), 2)

    def test_retired_client_directory_is_not_a_policy_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "Surge/AutoSurge.conf"
            path.parent.mkdir()
            path.write_text("[Rule]\nFINAL,RetiredGhost\n", encoding="utf-8")
            payload = audit.audit(repo, [])
            self.assertEqual(payload["rule_references"], [])
            self.assertEqual(payload["undefined_rule_policies"], [])


    def test_loon_reads_only_active_rule_sections(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "Loon" / "AutoLoon.conf"
            path.parent.mkdir(parents=True)
            path.write_text(
                """[Proxy Group]
Proxy = select,DIRECT

[Rule]
FINAL,Proxy

[Remote Rule]
https://example.test/Active.list, policy=Proxy, enabled=true
https://example.test/Disabled.list, policy=Ghost, enabled=false

[Plugin]
https://example.test/Plugin.plugin, policy=Ghost, enabled=true
""",
                encoding="utf-8",
            )
            refs = audit.extract_loon_rules(repo, path)
            self.assertEqual(
                [item.rule for item in refs],
                ["https://example.test/Active.list", "FINAL"],
            )
            self.assertEqual([item.policy for item in refs], ["Proxy", "Proxy"])

    def test_yaml_provider_parser_resolves_anchor_and_flow_styles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "Mihomo" / "Test.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(
                """templates:
  rp-domain: &rp-domain
    type: http
    behavior: domain
    format: mrs

rule-providers:
  Flow: { <<: *rp-domain, url: \"https://example.test/Flow.mrs\" }
  Block:
    <<: *rp-domain
    url: \"https://example.test/Block.mrs\"
""",
                encoding="utf-8",
            )
            providers = audit.extract_yaml_provider_defs(repo, "Mihomo", path)
            self.assertEqual([item.name for item in providers], ["Flow", "Block"])
            self.assertTrue(all(item.behavior == "domain" for item in providers))
            self.assertTrue(all(item.format == "mrs" for item in providers))

    def test_github_raw_host_is_not_a_github_service_rule(self) -> None:
        item = audit.RuleRef(
            "Loon",
            "Loon/Test.conf",
            1,
            "Asian TV",
            "https://raw.githubusercontent.com/example/rules/Bahamut.list",
            "REMOTE-RULE",
            "https://raw.githubusercontent.com/example/rules/Bahamut.list, policy=Asian TV",
        )
        self.assertEqual(audit.classify_rule(item), (90, "AsianTV"))

    def test_cn_guard_requires_domestic(self) -> None:
        item = audit.RuleRef(
            "Mihomo",
            "Mihomo/Test.yaml",
            1,
            "Proxy",
            "MicrosoftCN",
            "RULE-SET",
            "- RULE-SET,MicrosoftCN,Proxy",
        )
        violations = audit.audit_cn_guards([item])
        self.assertEqual(len(violations), 1)
        self.assertIn("Domestic", violations[0].reason)

    def test_ip_path_requires_ipcidr_behavior(self) -> None:
        provider = audit.ProviderDef(
            "Mihomo",
            "Mihomo/Test.yaml",
            1,
            "TelegramIP",
            "domain",
            "mrs",
            "https://raw.githubusercontent.com/SchweppesSoda/CustomRules/refs/heads/auto-build/Mihomo/IP/Telegram.mrs",
            "TelegramIP:",
        )
        violations = audit.audit_provider_types([provider], [])
        self.assertEqual(len(violations), 1)
        self.assertIn("ipcidr", violations[0].reason)

    def test_egern_comments_do_not_change_rule_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "Egern" / "AutoEgern.yaml"
            path.parent.mkdir(parents=True)
            path.write_text(
                """rules:
  - rule_set:
      match: \"https://example.test/Domestic.list\"
      policy: Domestic
      update_interval: 86400
  # --- service IP before broad CN IP ---
  - rule_set:
      match: \"https://raw.githubusercontent.com/SchweppesSoda/CustomRules/refs/heads/auto-build/Surge/IP/Telegram.list\"
      policy: Telegram
""",
                encoding="utf-8",
            )
            refs = audit.extract_egern_rules(repo, path)
            self.assertFalse(audit.is_ip_rule(refs[0]))
            self.assertTrue(audit.is_ip_rule(refs[1]))

    def test_china_asn_is_a_cn_ip_rule(self) -> None:
        item = audit.RuleRef(
            "Loon",
            "Loon/Test.conf",
            1,
            "Domestic",
            "https://example.test/ASN.China.list",
            "REMOTE-RULE",
            "https://example.test/ASN.China.list, policy=Domestic",
        )
        self.assertEqual(audit.classify_rule(item), (160, "ChinaIP"))


if __name__ == "__main__":
    unittest.main()
