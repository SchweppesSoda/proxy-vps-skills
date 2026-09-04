#!/usr/bin/env python3
"""Public entrypoint for the contract-aware ProxyConfig consistency audit."""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)
from consistency_core import audit, main, print_report, redact_text, redact_value

__all__ = ["audit", "main", "print_report", "redact_text", "redact_value"]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
