from __future__ import annotations

import importlib.util
import sys
import unittest
import tempfile
from unittest import mock
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_mihomo_configs.py"
SPEC = importlib.util.spec_from_file_location("validate_mihomo_configs_under_test", SCRIPT)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class ValidateMihomoConfigsTests(unittest.TestCase):
    def test_defaults_include_legacy_profile_only_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            expected = [Path("Mihomo/AutoMihomo.Mobile.yaml"), Path("Mihomo/AutoMihomo.OpenWrt.yaml")]
            self.assertEqual(VALIDATOR.default_configs(repo), expected)
            optional = repo / "Mihomo/SafeMihomo.yaml"
            optional.parent.mkdir()
            optional.write_text("rules: []", encoding="utf-8")
            self.assertEqual(VALIDATOR.default_configs(repo), expected + [optional.relative_to(repo)])

    def test_cli_preserves_explicit_missing_profile_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            requested = Path("Mihomo/SafeMihomo.yaml")
            argv = [str(SCRIPT), str(repo), "--mihomo", "kernel", "--geosite", "data", "--config", str(requested)]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(VALIDATOR, "validate_configs", return_value=2) as validate:
                self.assertEqual(VALIDATOR.main(), 2)
            self.assertEqual(validate.call_args.args[3], [requested])

    def test_unquoted_auth_headers_hide_scheme_and_credential(self) -> None:
        for prefix in ("Authorization: Bearer", "Proxy-Authorization: Basic", "authorization=Bearer"):
            with self.subTest(prefix=prefix):
                rendered = VALIDATOR.redact_text(prefix + " fixture-key\nnext: visible")
                self.assertNotIn("fixture-key", rendered)
                self.assertIn("<redacted>", rendered)
                self.assertIn("next: visible", rendered)

    def test_kernel_output_is_redacted(self) -> None:
        sample = (
            "socks5://user:SOCKS_SECRET@host.example:1080\n"
            "uuid: 00000000-0000-7000-8000-000000000001\n"
            'client_secret: "CLIENT_SECRET"\n'
            "access_key=ACCESS_SECRET"
        )
        rendered = VALIDATOR.redact_text(sample)
        for forbidden in (
            "SOCKS_SECRET",
            "00000000-0000-7000-8000-000000000001",
            "CLIENT_SECRET",
            "ACCESS_SECRET",
        ):
            self.assertNotIn(forbidden, rendered)


if __name__ == "__main__":
    unittest.main()
