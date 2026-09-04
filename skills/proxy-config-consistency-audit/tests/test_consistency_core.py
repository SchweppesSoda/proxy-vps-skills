from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))

import consistency_core as audit  # noqa: E402

WRAPPER_PATH = SCRIPT_DIR / "audit_proxy_consistency.py"
WRAPPER_SPEC = importlib.util.spec_from_file_location("audit_proxy_consistency_public", WRAPPER_PATH)
assert WRAPPER_SPEC and WRAPPER_SPEC.loader
WRAPPER = importlib.util.module_from_spec(WRAPPER_SPEC)
WRAPPER_SPEC.loader.exec_module(WRAPPER)


class ConsistencyCoreTests(unittest.TestCase):
    def test_public_wrapper_exports_only_redacted_audit(self) -> None:
        self.assertIs(WRAPPER.audit, audit.audit)
        secret = "socks5://user:WRAPPER_SECRET@host.example:1080"
        self.assertNotIn("WRAPPER_SECRET", WRAPPER.redact_value({"value": secret})["value"])

    def test_dotfile_paths_are_preserved(self) -> None:
        self.assertEqual(audit.clean_repo_path(".github/workflows/sync.yml"), ".github/workflows/sync.yml")
        self.assertEqual(audit.clean_repo_path(".gitattributes"), ".gitattributes")
        uuid = "00000000-0000-7000-8000-000000000001"
        self.assertNotIn(uuid, audit.redact_text(uuid))
        samples = {
            "socks5://user:SOCKS_SECRET@host.example:1080",
            "wireguard://WG_SECRET@host.example:51820",
            "ssh://user:SSH_SECRET@host.example:22",
            "ws://user:WS_SECRET@host.example/path",
            "wss://user:WSS_SECRET@host.example/path",
            "quic://QUIC_SECRET@host.example:443",
            "httpdns://HTTPDNS_SECRET@host.example/query",
            '{"client_secret":"CLIENT_SECRET","access_key":"ACCESS_SECRET"}',
            "authorization: Bearer AUTH_SECRET",
            "proxy-authorization = Basic BASIC_SECRET",
        }
        rendered = json.dumps(audit.redact_value({sample: sample for sample in samples}))
        for forbidden in (
            "SOCKS_SECRET",
            "WG_SECRET",
            "SSH_SECRET",
            "WS_SECRET",
            "WSS_SECRET",
            "QUIC_SECRET",
            "HTTPDNS_SECRET",
            "CLIENT_SECRET",
            "ACCESS_SECRET",
            "AUTH_SECRET",
            "BASIC_SECRET",
        ):
            self.assertNotIn(forbidden, rendered)
        structured = audit.redact_value(
            {
                "password": "short-password",
                "authorization": "Bearer short-auth",
                "nested": {
                    "token": 12345,
                    "client_secret": ["short-secret"],
                },
            }
        )
        self.assertEqual(structured["password"], "<redacted>")
        self.assertEqual(structured["authorization"], "<redacted>")
        self.assertEqual(structured["nested"]["token"], "<redacted>")
        self.assertEqual(structured["nested"]["client_secret"], "<redacted>")
        self.assertIn("password", structured)
        self.assertIn("authorization", structured)

    def make_repo(self, root: Path) -> Path:
        repo = root / "ProxyConfig"
        for client in ("Egern", "Mihomo", "Surge", "Loon", "Stash"):
            (repo / client).mkdir(parents=True, exist_ok=True)
        (repo / ".github/workflows").mkdir(parents=True)
        (repo / "Sub-Store/scripts").mkdir(parents=True)
        (repo / "Sub-Store/config").mkdir(parents=True)

        yaml_config = """proxy-providers:
  TAG:
    type: http
proxy-groups:
  - name: TAG-HK
  - name: TAG-TW
  - name: TAG-SG
  - name: TAG-JP
  - name: TAG-US
  - name: Service
rules:
  - MATCH,Service
"""
        for path in (
            repo / "Egern/AutoEgern.yaml",
            repo / "Mihomo/AutoMihomo.Mobile.yaml",
            repo / "Stash/AutoStash.yaml",
        ):
            path.write_text(yaml_config, encoding="utf-8")

        ini_config = """[Proxy Group]
TAG-Provider = select,DIRECT
TAG-HK = select,DIRECT
TAG-TW = select,DIRECT
TAG-SG = select,DIRECT
TAG-JP = select,DIRECT
TAG-US = select,DIRECT
Service = select,DIRECT
[Rule]
FINAL,Service
"""
        (repo / "Surge/AutoSurge.conf").write_text(ini_config, encoding="utf-8")
        (repo / "Loon/AutoLoon.conf").write_text(ini_config, encoding="utf-8")

        marker_text = """# BEGIN AUTO-GENERATED TEST
token: https://example.invalid/sub?token=top-secret
# END AUTO-GENERATED TEST
"""
        (repo / "Stash/Mixed.yaml").write_text(marker_text, encoding="utf-8")
        (repo / "Mihomo/Generated.yaml").write_text("generated: true\n", encoding="utf-8")
        (repo / "Sub-Store/scripts/generate.py").write_text("# fixture\n", encoding="utf-8")
        (repo / ".github/workflows/generate.yml").write_text(
            "concurrency:\n  group: generated-file-writers-main\n",
            encoding="utf-8",
        )
        contract = {
            "schema": 1,
            "writers": [
                {
                    "id": "mixed",
                    "inputs": [
                        {"repository": "owner/ProxyConfig", "path": "Egern/AutoEgern.yaml"}
                    ],
                    "entrypoint": "Sub-Store/scripts/generate.py",
                    "workflow": ".github/workflows/generate.yml",
                    "concurrency_group": "generated-file-writers-main",
                    "targets": [
                        {
                            "repository": "owner/ProxyConfig",
                            "branch": "main",
                            "path": "Stash/Mixed.yaml",
                            "scope": "marker-pair",
                            "selector": "AUTO-GENERATED TEST",
                        },
                        {
                            "repository": "owner/ProxyConfig",
                            "branch": "main",
                            "path": "Mihomo/Generated.yaml",
                            "scope": "whole-file",
                        },
                    ],
                    "delegates_to": [],
                    "validators": ["Sub-Store/scripts/generate.py"],
                    "intentional_exclusions": [],
                }
            ],
        }
        (repo / "Sub-Store/config/generated-writers.json").write_text(
            json.dumps(contract), encoding="utf-8"
        )
        return repo

    def test_clean_fixture_discovers_five_clients_and_skips_whole_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = self.make_repo(Path(temp))
            payload = audit.audit(repo, [])
            self.assertEqual(payload["environment_errors"], [])
            self.assertEqual(payload["issues"], [])
            self.assertEqual({item["client"] for item in payload["scanned"]}, {"Egern", "Mihomo", "Surge", "Loon", "Stash"})
            self.assertIn("Mihomo/Generated.yaml", {item["path"] for item in payload["skipped"]})
            self.assertEqual(payload["summary"]["generated"], 2)

    def test_contract_overlap_is_a_configuration_issue(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = self.make_repo(Path(temp))
            contract_path = repo / "Sub-Store/config/generated-writers.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            duplicate = dict(contract["writers"][0])
            duplicate["id"] = "duplicate"
            duplicate["concurrency_group"] = "different-lock"
            duplicate["targets"] = [dict(contract["writers"][0]["targets"][0])]
            contract["writers"].append(duplicate)
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            payload = audit.audit(repo, [])
            kinds = {item["kind"] for item in payload["issues"]}
            self.assertIn("shared-target-lock-mismatch", kinds)
            self.assertIn("selector-owner-overlap", kinds)

    def test_missing_input_and_validator_locators_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = self.make_repo(Path(temp))
            contract_path = repo / "Sub-Store/config/generated-writers.json"
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
            writer = contract["writers"][0]
            writer["inputs"] = [
                {"repository": "owner/ProxyConfig", "path": "missing/input.json"},
                {"repository": "owner/External", "path": "source.json"},
            ]
            writer["validators"] = ["missing/test_validator.py"]
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            payload = audit.audit(repo, [])
            kinds = {item["kind"] for item in payload["issues"]}
            self.assertIn("missing-input", kinds)
            self.assertIn("missing-external-input-branch", kinds)
            self.assertIn("missing-validator", kinds)

    def test_missing_contract_is_environment_error_and_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "ProxyConfig"
            repo.mkdir()
            payload = audit.audit(repo, [])
            self.assertEqual(payload["summary"]["environment_errors"], 1)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(audit.main([str(repo), "--json"]), 2)

    def test_malformed_utf8_contract_is_environment_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "ProxyConfig"
            contract = repo / "Sub-Store/config/generated-writers.json"
            contract.parent.mkdir(parents=True)
            contract.write_bytes(b"\xff\xfe\x00")
            payload = audit.audit(repo, [])
            self.assertEqual(payload["summary"]["environment_errors"], 1)

    def test_json_output_redacts_urls_tokens_and_uuids(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            repo = self.make_repo(Path(temp))
            workflow = repo / ".github/workflows/generate.yml"
            workflow.write_text(
                "# https://example.invalid/00000000-0000-4000-8000-000000000001?token=top-secret\n"
                "concurrency:\n  group: wrong\n",
                encoding="utf-8",
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = audit.main([str(repo), "--json"])
            rendered = output.getvalue()
            self.assertEqual(code, 1)
            self.assertNotIn("top-secret", rendered)
            self.assertNotIn("00000000-0000-4000-8000-000000000001", rendered)
            self.assertNotIn("https://example.invalid", rendered)

    def test_bad_repo_is_exit_two_without_echoing_path(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = audit.main(["missing-token=top-secret"])
        self.assertEqual(code, 2)
        self.assertNotIn("top-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
