from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_proxy_refs.py"
SPEC = importlib.util.spec_from_file_location("audit_proxy_refs_under_test", SCRIPT)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


CAPABILITY = "0123456789abcdef" * 4
UUID = "00000000-0000-7000-8000-000000000001"


def write_config(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run_report(root: Path, *arguments: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = AUDIT.main([str(root), *arguments])
    return code, stdout.getvalue(), stderr.getvalue()


class AuditProxyRefsTests(unittest.TestCase):
    def test_scans_all_client_directories_and_preserves_unicode_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            yaml = """proxy-groups:
  - name: "核心-JP"
    type: select
"""
            write_config(root, "Mihomo/Auto.yaml", yaml)
            write_config(
                root,
                "Surge/Auto.conf",
                """[Proxy Group]
核心-JP=select, DIRECT
""",
            )
            write_config(
                root,
                "Egern/Auto.yaml",
                """policy_groups:
  - name: 核心-JP
    type: select
""",
            )
            write_config(
                root,
                "Stash/AutoStash.yaml",
                """proxy-providers:
  中文机场:
    url: https://example.invalid/source
proxy-groups:
  - name: 核心-JP
    type: select
""",
            )
            write_config(
                root,
                "Loon/AutoLoon.conf",
                """[Proxy Group]
核心-JP=select, DIRECT
""",
            )

            code, text, error = run_report(root, "--target", "🇯🇵 核心 JP")

            self.assertEqual(code, 0, error)
            self.assertEqual(error, "")
            self.assertEqual(AUDIT.normalize("🇯🇵 核心-JP_二"), "核心jp二")
            for client in ("Mihomo", "Surge", "Egern", "Stash", "Loon"):
                self.assertIn(client, text)
            portable_text = text.replace("\\", "/")
            self.assertIn("Stash/AutoStash.yaml", portable_text)
            self.assertIn("Loon/AutoLoon.conf", portable_text)

            code, output, error = run_report(root, "--target", "核心 JP", "--json")

            self.assertEqual(code, 0, error)
            payload = json.loads(output)
            scanned = payload["scanned_files"]
            self.assertEqual(len(scanned), 5)
            self.assertTrue(any(path.startswith("Stash") for path in scanned))
            self.assertTrue(any(path.startswith("Loon") for path in scanned))
            self.assertIn("核心jp", AUDIT.normalize("核心 JP"))

    def test_redacts_text_and_json_reports_but_keeps_safe_context(self) -> None:
        unquoted = AUDIT.redact_text(
            "Authorization: Bearer AUTH_VALUE\n"
            "password: PASSWORD_VALUE\n"
            "secret=SECRET_VALUE"
        )
        self.assertNotIn("AUTH_VALUE", unquoted)
        self.assertNotIn("PASSWORD_VALUE", unquoted)
        self.assertNotIn("SECRET_VALUE", unquoted)
        self.assertNotIn(UUID, AUDIT.redact_text(UUID))
        for value in (
            "ssr://SSRSECRET",
            "socks5://user:SOCKS_SECRET@host.example:1080",
            "tuic://TUIC_SECRET@host.example:443",
            "wireguard://WG_SECRET@host.example:51820",
            "ssh://user:SSH_SECRET@host.example:22",
            "ws://user:WS_SECRET@host.example/path",
            "wss://user:WSS_SECRET@host.example/path",
            "quic://QUIC_SECRET@host.example:443",
            "httpdns://HTTPDNS_SECRET@host.example/query",
        ):
            self.assertNotIn(value.split("://", 1)[1], AUDIT.redact_text(value))
        wss = AUDIT.redact_text("wss://user:WSS_SECRET@host.example/path")
        self.assertIn("scheme=wss", wss)
        self.assertNotIn("w[REDACTED_URL scheme=ss]", wss)
        key_sample = (
            'access_key: ACCESS_KEY_VALUE\n'
            'client_secret: CLIENT_SECRET_VALUE\n'
            'refresh_token: REFRESH_TOKEN_VALUE'
        )
        safe_keys = AUDIT.redact_text(key_sample)
        for forbidden in ("ACCESS_KEY_VALUE", "CLIENT_SECRET_VALUE", "REFRESH_TOKEN_VALUE"):
            self.assertNotIn(forbidden, safe_keys)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            line = (
                '{"name":"中文别名","url":"https://user:URL_PASSWORD@example.com/provider/'
                + CAPABILITY
                + '?token=query-value#fragment","secret":"SECRET_VALUE",'
                + '"password":"PASSWORD_VALUE","Authorization":"Bearer AUTH_VALUE",'
                + '"note":"'
                + CAPABILITY
                + '"}'
            )
            write_config(root, "Stash/Sensitive.json", line + "\n")

            code, text, error = run_report(root, "--target", "中文别名")

            self.assertEqual(code, 0, error)
            self.assertEqual(error, "")
            for forbidden in (
                "https://user:URL_PASSWORD@example.com/provider/",
                "URL_PASSWORD",
                "query-value",
                "fragment",
                "SECRET_VALUE",
                "PASSWORD_VALUE",
                "AUTH_VALUE",
                CAPABILITY,
            ):
                self.assertNotIn(forbidden, text)
            self.assertIn("中文别名", text)
            self.assertIn("[REDACTED_URL", text)
            self.assertIn("[REDACTED_TOKEN]", text)

            code, output, error = run_report(root, "--target", "中文别名", "--json")

            self.assertEqual(code, 0, error)
            payload = json.loads(output)
            encoded = json.dumps(payload, ensure_ascii=False)
            for forbidden in (
                "https://user:URL_PASSWORD@example.com/provider/",
                "URL_PASSWORD",
                "query-value",
                "fragment",
                "SECRET_VALUE",
                "PASSWORD_VALUE",
                "AUTH_VALUE",
                CAPABILITY,
            ):
                self.assertNotIn(forbidden, encoded)
            self.assertIn("中文别名", encoded)
            self.assertIn("[REDACTED_URL", encoded)
            self.assertIn("[REDACTED_TOKEN]", encoded)

    def test_missing_repo_and_target_are_argument_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"

            code, output, error = run_report(missing, "--target", "anything")
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertIn("repo directory does not exist", error)

            code, output, error = run_report(root)
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertIn("provide at least one --target", error)

            code, output, error = run_report(root, "--target", "   ")
            self.assertEqual(code, 2)
            self.assertEqual(output, "")
            self.assertIn("each --target", error)


if __name__ == "__main__":
    unittest.main()
