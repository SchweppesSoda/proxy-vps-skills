from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_mihomo_configs.py"
SPEC = importlib.util.spec_from_file_location("validate_mihomo_configs_under_test", SCRIPT)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class ValidateMihomoConfigsTests(unittest.TestCase):
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
