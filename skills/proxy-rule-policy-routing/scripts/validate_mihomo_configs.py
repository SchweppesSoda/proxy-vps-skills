#!/usr/bin/env python3
"""Load every maintained Mihomo profile with a real Mihomo kernel."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path


DEFAULT_CONFIGS = (
    Path("Mihomo/AutoMihomo.Mobile.yaml"),
    Path("Mihomo/AutoMihomo.OpenWrt.yaml"),
    Path("Mihomo/SafeMihomo.yaml"),
)


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )


def validate_configs(
    repo: Path,
    mihomo: Path,
    geosite: Path,
    configs: list[Path],
) -> int:
    repo = repo.resolve()
    mihomo = mihomo.resolve()
    geosite = geosite.resolve()

    for label, path in (("repository", repo), ("Mihomo executable", mihomo), ("GeoSite.dat", geosite)):
        expected = path.is_dir() if label == "repository" else path.is_file()
        if not expected:
            raise FileNotFoundError(f"{label} not found: {path}")

    version = run_command([str(mihomo), "-v"])
    if version.returncode != 0:
        raise RuntimeError(f"Mihomo version check failed:\n{version.stdout}{version.stderr}")
    print((version.stdout or version.stderr).strip())

    failures = 0
    for relative in configs:
        config = relative if relative.is_absolute() else repo / relative
        config = config.resolve()
        if not config.is_file():
            raise FileNotFoundError(f"Mihomo config not found: {config}")

        with tempfile.TemporaryDirectory(prefix="proxyconfig-mihomo-test-") as temporary:
            work_dir = Path(temporary)
            shutil.copy2(geosite, work_dir / "GeoSite.dat")
            result = run_command(
                [str(mihomo), "-d", str(work_dir), "-t", "-f", str(config)]
            )

        output = f"{result.stdout}{result.stderr}".strip()
        if result.returncode == 0:
            print(f"[PASS] {config.relative_to(repo).as_posix()}")
        else:
            failures += 1
            print(f"[FAIL] {config.relative_to(repo).as_posix()} (exit {result.returncode})")
            if output:
                print(output)

    print(f"Mihomo config validation: {len(configs) - failures} passed, {failures} failed")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate ProxyConfig Mihomo profiles with `mihomo -t`."
    )
    parser.add_argument("repo", type=Path, help="ProxyConfig repository root")
    parser.add_argument("--mihomo", type=Path, required=True, help="Verified Mihomo executable")
    parser.add_argument("--geosite", type=Path, required=True, help="GeoSite.dat used by fake-ip filters")
    parser.add_argument(
        "--config",
        type=Path,
        action="append",
        dest="configs",
        help="Profile relative to the repository; repeat to override the defaults",
    )
    args = parser.parse_args()
    return validate_configs(
        args.repo,
        args.mihomo,
        args.geosite,
        args.configs or list(DEFAULT_CONFIGS),
    )


if __name__ == "__main__":
    raise SystemExit(main())
