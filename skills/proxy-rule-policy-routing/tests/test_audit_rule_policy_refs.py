from __future__ import annotations

import contextlib
import hashlib
import io
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace


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

    def test_inline_proxy_target_and_local_composite_are_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.make_repo(repo)
            path = repo / "Mihomo/AutoMihomo.Mobile.yaml"
            path.write_text("""proxies:
  - name: LocalFixture
    type: socks5
proxy-groups:
  - name: Final
    type: select
rules:
  - AND,((NETWORK,TCP),(DST-PORT,7443),(IP-CIDR,10.23.45.6/32,no-resolve)),LocalFixture
  - MATCH,Final
""", encoding="utf-8")
            refs = audit.extract_mihomo_rules(repo, "Mihomo", path)
            self.assertEqual(len(refs), 2)
            self.assertEqual(refs[0].policy, "LocalFixture")
            self.assertEqual(audit.classify_rule(refs[0]), (10, "HardLocal"))
            self.assertEqual(audit.audit(repo, [])["undefined_rule_policies"], [])

    def test_wan2_derivative_remains_outside_canonical_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            self.make_repo(repo)
            relative = "Mihomo/AutoMihomo.OpenWrt-WAN2.yaml"
            (repo / relative).write_text("rules:\n  - MATCH,DerivativeGhost\n", encoding="utf-8")
            payload = audit.audit(repo, [])
            self.assertEqual(len(payload["checked"]), 6)
            self.assertEqual([item["path"] for item in payload["skipped"]], [relative])
            self.assertEqual(payload["undefined_rule_policies"], [])
            self.assertEqual(payload["validation_scope"]["mode"], "references-only")


class ArtifactContentAuditTests(unittest.TestCase):
    BASE = "https://raw.githubusercontent.com/SchweppesSoda/CustomRules/refs/heads/auto-build/"

    def ref(self, name: str, policy: str, line: int = 1, *, client: str = "Egern", file: str | None = None, kind: str | None = None) -> object:
        file = file or ("Stash/AutoStash.yaml" if client == "Stash" else "Egern/AutoEgern.yaml")
        kind = kind or ("RULE-SET" if client == "Stash" else "RULE_SET")
        return audit.RuleRef(client, file, line, policy, self.BASE + "Surge/" + name + ".list", kind, "fixture")

    def order_repo(self, root: Path, file: str = "Egern/AutoEgern.yaml") -> Path:
        path = root / "repo" / file
        path.parent.mkdir(parents=True)
        path.write_text("rules: []\n", encoding="utf-8")
        return root / "repo"

    def write_set(self, root: Path, name: str, rules: list[str], behavior: str = "classical", *, mrs: bool = False) -> None:
        list_path = root / "Surge" / (name + ".list")
        yaml_path = root / "Mihomo" / (name + ".yaml")
        for path in (list_path, yaml_path):
            path.parent.mkdir(parents=True, exist_ok=True)
        list_rules = [rule + ",no-resolve" for rule in rules] if behavior == "ipcidr" else rules
        list_path.write_text("# fixture\n" + "\n".join(list_rules) + "\n", encoding="utf-8")
        yaml_rules = rules
        if behavior == "domain":
            yaml_rules = [("+." if rule.startswith("DOMAIN-SUFFIX,") else "") + rule.split(",", 1)[1] for rule in rules]
        elif behavior == "ipcidr":
            yaml_rules = [rule.split(",", 1)[1] for rule in rules]
        yaml_path.write_text("payload:\n" + "".join("  - " + rule + "\n" for rule in yaml_rules) if rules else "payload: []\n", encoding="utf-8")
        manifest_path = root / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"schema": 2, "sets": {}}
        info = {"behavior": behavior, "formats": ["yaml", "list"], "rule_count": len(rules),
            "rules_sha256": hashlib.sha256("\n".join(rules).encode()).hexdigest()}
        if name.startswith(("NonIP/", "Address/")):
            prefix, original = name.split("/", 1)
            info["partition"] = {"source": original, "part": "non_ip" if prefix == "NonIP" else "address", "clients": ["Egern"]}
        if mrs:
            info["formats"].append("mrs")
            info["mrs_behavior"] = behavior
            yaml_path.with_suffix(".mrs").write_bytes(b"fixture-mrs-verified-by-separate-build-gate")
        manifest["sets"][name] = info
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_claude_ip_policy_does_not_reenter_ai_finance_segment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.order_repo(Path(temporary))
            refs = [self.ref("AI", "AI Suite", 1), self.ref("AppleIntelligence", "AI Suite", 2),
                self.ref("Classical/PayPal", "Proxy", 3), self.ref("Banking", "Proxy", 4),
                self.ref("Crypto", "Proxy", 5), self.ref("IP/Claude", "AI Suite", 6)]
            self.assertEqual(audit.classify_rule(refs[-1]), (150, "ClaudeIP"))
            self.assertEqual(audit.logical_service(refs[-1]), "ClaudeIP")
            self.assertEqual(audit.audit_finance_order(repo, refs), [])
            for name in ("ClaudeIP", "Custom-Claude-IP"):
                item = replace(refs[-1], rule=name, source="", kind="RULE-SET")
                self.assertTrue(audit.is_ip_rule(item))
                self.assertNotEqual(audit.logical_service(item), "AI Suite")

    def test_true_finance_interruption_still_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.order_repo(Path(temporary))
            refs = [self.ref("AI", "AI Suite", 1), self.ref("PayPal", "Proxy", 2),
                self.ref("Banking", "Proxy", 3), self.ref("Unlisted", "Proxy", 4), self.ref("Crypto", "Proxy", 5)]
            self.assertEqual(len(audit.audit_finance_order(repo, refs)), 1)

    def test_unknown_non_address_identity_and_geosite_cannot_follow_ip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.order_repo(root)
            ip = self.ref("IP/Claude", "AI Suite", 1)
            for kind, policy in (("DOMAIN", "DIRECT"), ("DOMAIN-SUFFIX", "FixtureGroup"), ("GEOSITE", "FixtureGroup")):
                with self.subTest(kind=kind):
                    domain = audit.RuleRef("Egern", "Egern/AutoEgern.yaml", 2, policy, "unlisted.fixture.invalid", kind, "fixture")
                    self.assertIsNone(audit.classify_rule(domain))
                    self.assertTrue(audit.audit_canonical_order(repo, [ip, domain]))
            provider = self.ref("NonIP/Classical/Unlisted", "FixtureGroup", 2)
            self.write_set(root, "IP/Claude", ["IP-CIDR,8.8.8.0/24"], "ipcidr")
            self.write_set(root, "NonIP/Classical/Unlisted", ["DOMAIN,unlisted.fixture.invalid"])
            expanded, _, incomplete, violations = audit.audit_artifact_contents([ip, provider], root)
            self.assertEqual((incomplete, violations), ([], []))
            self.assertTrue(audit.audit_canonical_order(repo, expanded))

    def test_mixed_classical_early_address_cannot_hide_in_business_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.order_repo(root)
            self.write_set(root, "Classical/Telegram", ["DOMAIN,chat.fixture.invalid", "IP-CIDR,8.8.8.0/24", "USER-AGENT,FixtureAgent*"])
            self.write_set(root, "Apple", ["DOMAIN,apple.fixture.invalid"])
            refs = [self.ref("Classical/Telegram", "Telegram", 1), self.ref("Apple", "Apple", 2)]
            self.assertEqual(audit.audit_canonical_order(repo, refs), [])
            expanded, _, incomplete, violations = audit.audit_artifact_contents(refs, root)
            self.assertEqual(incomplete, [])
            self.assertTrue(any("non-address block" in item.reason for item in violations))
            self.assertTrue(audit.audit_canonical_order(repo, expanded))

    def test_partition_content_type_contract_is_observed_not_inferred_from_path(self) -> None:
        cases = {
            "Address/Classical/Telegram": ["DOMAIN,hidden.fixture.invalid"],
            "NonIP/Classical/Telegram": ["IP-ASN,64512"],
        }
        for name, rules in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_set(root, name, rules)
                _, _, incomplete, violations = audit.audit_artifact_contents([self.ref(name, "Telegram")], root)
                self.assertEqual(incomplete, [])
                self.assertTrue(violations)

    def test_non_ip_kinds_and_asn_remain_literal_and_lossless(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rules = ["DOMAIN,fixture.invalid", "DOMAIN-SUFFIX,suffix.invalid", "DOMAIN-KEYWORD,fixture",
                "DOMAIN-WILDCARD,*.fixture.invalid", "USER-AGENT,Fixture%20Agent*",
                "PROCESS-NAME,fixture-process", "URL-REGEX,^https://fixture.invalid/.*"]
            self.write_set(root, "NonIP/Classical/OpenAI", rules)
            path = root / "Surge/NonIP/Classical/OpenAI.list"
            self.assertEqual([item.canonical for item in audit.load_artifact_rules(path)], rules)
            _, checked, incomplete, violations = audit.audit_artifact_contents([self.ref("NonIP/Classical/OpenAI", "Proxy")], root)
            self.assertEqual((incomplete, violations), ([], []))
            self.assertEqual(checked[0]["rule_count"], len(rules))
            self.write_set(root, "Address/Classical/WeChat", ["IP-ASN,64512 // fixture, annotation"])
            item = self.ref("Address/Classical/WeChat", "Domestic")
            self.assertEqual(audit.classify_rule(item), (150, "ServiceAddress"))
            _, _, incomplete, violations = audit.audit_artifact_contents([item], root)
            self.assertEqual((incomplete, violations), ([], []))

    def test_broad_proxy_and_cn_address_paths_keep_tail_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.order_repo(Path(temporary))
            service = self.ref("Address/Classical/WeChat", "Domestic", 1)
            proxy = self.ref("Address/Classical/Proxy", "Proxy", 2)
            china = self.ref("Address/Classical/China", "Domestic", 3)
            self.assertEqual(audit.classify_rule(proxy), (157, "ProxyIP"))
            self.assertEqual(audit.classify_rule(china), (160, "ChinaIP"))
            self.assertEqual(audit.audit_canonical_order(repo, [service, proxy, china]), [])
            self.assertTrue(audit.audit_canonical_order(repo, [china, service, proxy]))
            self.assertTrue(audit.audit_canonical_order(repo, [proxy, service, china]))
            self.assertEqual(audit.classify_rule(self.ref("Address/Classical/Unlisted", "Google FCM")), (150, "ServiceAddress"))

    def test_known_address_subsequence_is_retained_without_inventing_new_service_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.order_repo(Path(temporary))
            refs = [self.ref("IP/Claude", "AI Suite", 1), self.ref("Address/Classical/Apple", "Apple", 2),
                self.ref("IP/ApplePush", "Apple Push", 3), self.ref("Address/Classical/WeChat", "Domestic", 4),
                self.ref("IP/Telegram", "Telegram", 5)]
            self.assertEqual(audit.audit_canonical_order(repo, refs), [])
            self.assertTrue(audit.audit_canonical_order(repo, [refs[-1], *refs[:-1]]))

    def test_private_and_special_address_exceptions_are_precise(self) -> None:
        cases = (
            ("Classical/Private", "IP-CIDR,10.0.0.0/8,no-resolve", "Egern/AutoEgern.yaml", False),
            ("Classical/Private", "IP-CIDR,8.8.8.0/24", "Egern/AutoEgern.yaml", True),
            ("Classical/Private", "IP-ASN,64512", "Egern/AutoEgern.yaml", True),
            ("Classical/Special", "IP-CIDR,100.64.0.0/10,no-resolve", "Egern/AutoEgern.yaml", False),
            ("Classical/Special", "IP-CIDR,100.64.0.0/11", "Egern/AutoEgern.yaml", True),
            ("Classical/Special", "IP-CIDR,8.8.8.0/24", "Egern/AutoEgern.yaml", True),
            ("Classical/Special", "IP-CIDR,100.64.0.0/10", "Egern/AutoEgernLite.yaml", True),
            ("Classical/UnreviewedPrivate", "IP-CIDR,8.8.8.0/24", "Egern/AutoEgern.yaml", True),
        )
        for name, rule, file, should_fail in cases:
            with self.subTest(name=name, rule=rule, file=file), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_set(root, name, [rule])
                _, _, incomplete, violations = audit.audit_artifact_contents([self.ref(name, "DIRECT", file=file)], root)
                self.assertEqual(incomplete, [])
                self.assertEqual(bool(violations), should_fail)
        arbitrary = audit.RuleRef("Mihomo", "Mihomo/AutoMihomo.Mobile.yaml", 1, "DIRECT", "8.8.8.0/24", "IP-CIDR", "fixture")
        self.assertEqual(audit.classify_rule(arbitrary), (150, "ServiceAddress"))

    def test_httpdns_snapshot_exception_requires_exact_identity_source_and_policy(self) -> None:
        for name, url in audit.HTTPDNS_SOURCES.items():
            with self.subTest(provider=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "manifest.json").write_text('{"schema":2,"sets":{}}', encoding="utf-8")
                path = root / "httpdns.list"
                path.write_text("DOMAIN,dns.fixture.invalid\nIP-CIDR,8.8.8.0/24,no-resolve\nURL-REGEX,^https://dns.fixture.invalid/.*\n", encoding="utf-8")
                mapping = root / "external.json"
                info = {"path": path.name, "format": "text", "behavior": "classical", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                mapping.write_text(json.dumps({"schema": 1, "artifacts": {url: info}}), encoding="utf-8")
                ref = audit.RuleRef("Stash", "Stash/AutoStash.yaml", 1, "HTTPDNS", name, "RULE-SET", "fixture", source=url, behavior="classical", format="text")
                _, checked, incomplete, violations = audit.audit_artifact_contents([ref], root, mapping)
                self.assertEqual((incomplete, violations), ([], []))
                self.assertEqual(audit.classify_rule(replace(ref, content_kind="IP-CIDR")), (31, "HTTPDNS"))
                self.assertEqual(checked[0]["text_sha256"], info["sha256"])
                for altered in (replace(ref, rule="UnreviewedHTTPDNS"), replace(ref, policy="Proxy"), replace(ref, client="Mihomo")):
                    _, _, incomplete, violations = audit.audit_artifact_contents([altered], root, mapping)
                    self.assertEqual(incomplete, [])
                    self.assertTrue(violations)
                _, _, incomplete, _ = audit.audit_artifact_contents([replace(ref, source="https://unknown.invalid/httpdns.list")], root, mapping)
                self.assertTrue(incomplete)
                _, _, incomplete, _ = audit.audit_artifact_contents([ref], root)
                self.assertTrue(incomplete)
                info["sha256"] = "0" * 64
                mapping.write_text(json.dumps({"schema": 1, "artifacts": {url: info}}), encoding="utf-8")
                _, _, incomplete, violations = audit.audit_artifact_contents([ref], root, mapping)
                self.assertEqual(incomplete, [])
                self.assertTrue(violations)
                path.write_text("# fixture upstream unavailable\n", encoding="utf-8")
                info["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                mapping.write_text(json.dumps({"schema": 1, "artifacts": {url: info}}), encoding="utf-8")
                _, _, incomplete, _ = audit.audit_artifact_contents([ref], root, mapping)
                self.assertTrue(incomplete)

    def test_only_manifest_declared_partition_empty_sides_are_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = "Address/Classical/OpenAI"
            self.write_set(root, name, [])
            _, checked, incomplete, violations = audit.audit_artifact_contents([self.ref(name, "AI Suite")], root)
            self.assertEqual((incomplete, violations), ([], []))
            self.assertEqual(checked[0]["rule_count"], 0)
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["sets"][name].pop("partition")
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            _, _, incomplete, _ = audit.audit_artifact_contents([self.ref(name, "AI Suite")], root)
            self.assertTrue(incomplete)
            self.write_set(root, "Classical/OpenAI", [])
            _, _, incomplete, _ = audit.audit_artifact_contents([self.ref("Classical/OpenAI", "AI Suite")], root)
            self.assertTrue(incomplete)

    def test_unknown_or_compound_artifact_syntax_is_incomplete(self) -> None:
        for rule in ("UNKNOWN,fixture", "AND,((DOMAIN,fixture.invalid),(IP-CIDR,8.8.8.0/24))"):
            with self.subTest(rule=rule), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.write_set(root, "NonIP/Classical/OpenAI", [rule])
                _, _, incomplete, _ = audit.audit_artifact_contents([self.ref("NonIP/Classical/OpenAI", "AI Suite")], root)
                self.assertTrue(incomplete)

    def test_generated_branch_must_match_local_artifact_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_set(root, "AI", ["DOMAIN,fixture.invalid"])
            for branch in ("master", "refs/heads/master", "refs/tags/frozen", "refs/heads/unreviewed"):
                with self.subTest(branch=branch):
                    url = f"https://raw.githubusercontent.com/SchweppesSoda/CustomRules/{branch}/Surge/AI.list"
                    item = replace(self.ref("AI", "AI Suite"), rule=url)
                    _, _, incomplete, _ = audit.audit_artifact_contents([item], root)
                    self.assertTrue(incomplete)
                    self.assertTrue(audit.audit_provider_types([], [item]))

    def test_missing_artifact_and_mrs_text_companion_are_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_set(root, "IP/Claude", ["IP-CIDR,8.8.8.0/24"], "ipcidr", mrs=True)
            ref = audit.RuleRef("Mihomo", "Mihomo/AutoMihomo.Mobile.yaml", 1, "AI Suite", "ClaudeIP", "RULE-SET", "fixture", source=self.BASE + "Mihomo/IP/Claude.mrs", behavior="ipcidr")
            _, _, incomplete, violations = audit.audit_artifact_contents([ref], root)
            self.assertEqual((incomplete, violations), ([], []))
            (root / "Mihomo/IP/Claude.yaml").unlink()
            _, _, incomplete, _ = audit.audit_artifact_contents([ref], root)
            self.assertTrue(incomplete)
            _, _, incomplete, _ = audit.audit_artifact_contents([self.ref("Absent", "Proxy")], root)
            self.assertTrue(incomplete)

    def test_yaml_behavior_and_format_must_match_encoding_not_only_member_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_set(root, "MyDirect", ["DOMAIN-SUFFIX,fixture.invalid"])
            ref = audit.RuleRef("Mihomo", "Mihomo/AutoMihomo.Mobile.yaml", 1, "MyDirect", "MyDirect", "RULE-SET", "fixture", source=self.BASE + "Mihomo/MyDirect.yaml", behavior="classical", format="yaml")
            _, _, incomplete, violations = audit.audit_artifact_contents([ref], root)
            self.assertEqual((incomplete, violations), ([], []))
            for altered in (replace(ref, behavior="domain"), replace(ref, format="text")):
                _, _, incomplete, violations = audit.audit_artifact_contents([altered], root)
                self.assertEqual(incomplete, [])
                self.assertTrue(violations)

    def test_local_composite_exception_requires_supported_leaves_and_only_local_addresses(self) -> None:
        safe = audit.RuleRef("Mihomo", "Mihomo/AutoMihomo.Mobile.yaml", 1, "FixtureGroup",
            "((NETWORK,TCP),(DST-PORT,7443),(IP-CIDR,10.23.45.6/32,no-resolve))", "AND", "fixture")
        self.assertTrue(audit.is_local_composite(safe))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text('{"schema":2,"sets":{}}', encoding="utf-8")
            for expression in (
                "((NETWORK,TCP),(DST-PORT,7443),(IP-CIDR,8.8.8.0/24))",
                "((NETWORK,TCP),(IP-CIDR,10.0.0.0/8),(IP-CIDR,8.8.8.0/24))",
                "((UNKNOWN,fixture),(IP-CIDR,10.0.0.0/8))",
                "((OR,((DOMAIN,fixture.invalid),(IP-CIDR,10.0.0.0/8))))",
                "((NOT,(IP-CIDR,10.0.0.0/8)))",
            ):
                with self.subTest(expression=expression):
                    item = replace(safe, rule=expression)
                    self.assertFalse(audit.is_local_composite(item))
                    _, _, incomplete, _ = audit.audit_artifact_contents([item], root)
                    self.assertTrue(incomplete)

    def test_requested_content_validation_cannot_return_zero_for_missing_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            RulePolicyAuditTests().make_repo(repo)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main([str(repo), "--artifact-root", str(root / "absent"), "--json"]), 2)

    def test_malformed_active_entries_are_retained_and_make_content_incomplete(self) -> None:
        cases = (
            ("Egern", "Egern/AutoEgern.yaml", "rules:\n  - unknown_type: { match: fixture.invalid }\n"),
            ("Egern", "Egern/AutoEgern.yaml", "rules:\n  - domain:\n      policy: DIRECT\n"),
            ("Mihomo", "Mihomo/AutoMihomo.Mobile.yaml", "rules:\n  - UNKNOWN\n"),
        )
        for client, file, text in cases:
            with self.subTest(client=client, text=text), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo = self.order_repo(root, file)
                path = repo / file
                path.write_text(text, encoding="utf-8")
                (root / "manifest.json").write_text('{"schema":2,"sets":{}}', encoding="utf-8")
                refs = audit.extract_egern_rules(repo, path) if client == "Egern" else audit.extract_mihomo_rules(repo, client, path)
                self.assertEqual(len(refs), 1)
                _, _, incomplete, _ = audit.audit_artifact_contents(refs, root)
                self.assertTrue(incomplete)

    def test_disabled_egern_entry_with_comment_remains_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.order_repo(root)
            path = repo / "Egern/AutoEgern.yaml"
            path.write_text("""rules:
  - unknown_type:
      match: inactive.invalid
      disabled: true # historical entry
  - domain:
      match: active.invalid
      policy: DIRECT
      disabled: false # current entry
""", encoding="utf-8")
            refs = audit.extract_egern_rules(repo, path)
            self.assertEqual([item.rule for item in refs], ["active.invalid"])

    def test_final_catch_all_must_be_last_and_target_final(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = self.order_repo(Path(temporary))
            final = audit.RuleRef("Egern", "Egern/AutoEgern.yaml", 1, "Final", "*", "DEFAULT", "fixture")
            domain = audit.RuleRef("Egern", "Egern/AutoEgern.yaml", 2, "DIRECT", "unlisted.invalid", "DOMAIN", "fixture")
            self.assertTrue(audit.audit_canonical_order(repo, [final, domain]))
            self.assertTrue(audit.audit_provider_types([], [replace(final, policy="Proxy")]))
            self.assertTrue(audit.audit_final_catchalls(repo, [domain]))
            self.assertTrue(audit.audit_final_catchalls(repo, [final, final]))
            self.assertEqual(audit.audit_final_catchalls(repo, [domain, final]), [])


if __name__ == "__main__":
    unittest.main()
