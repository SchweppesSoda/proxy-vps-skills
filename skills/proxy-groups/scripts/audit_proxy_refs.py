#!/usr/bin/env python3
"""Audit proxy group definitions and references in ProxyConfig.

The script is intentionally dependency-free. It does not validate full YAML or
Surge syntax; it finds definitions and occurrences so an agent can reason about
the edit surface before touching MIHOMO, Surge, or Egern config files.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


CONFIG_SUFFIXES = {".yaml", ".yml", ".conf", ".dconf"}
DEFAULT_DIRS = ("Mihomo", "Surge", "Egern")
DEFINITION_WINDOW = 12


def configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


@dataclass
class Hit:
    file: str
    line: int
    kind: str
    text: str


@dataclass
class Definition:
    name: str
    file: str
    line: int
    kind: str
    text: str


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_name_from_yaml(line: str) -> str | None:
    flow = re.search(r"\bname\s*:\s*([^,}#]+)", line)
    if flow:
        return strip_quotes(flow.group(1))

    block = re.search(r"^\s*name\s*:\s*(.+?)\s*(?:#.*)?$", line)
    if block:
        return strip_quotes(block.group(1))
    return None


def infer_yaml_kind(lines: list[str], index: int) -> str:
    current_type = re.search(r"\btype\s*:\s*([A-Za-z0-9_-]+)", lines[index])
    if current_type:
        return current_type.group(1)

    for back in range(index, max(-1, index - DEFINITION_WINDOW), -1):
        item = re.match(r"^\s*-\s*([A-Za-z_][\w-]*)\s*:\s*$", lines[back])
        if item:
            return item.group(1)

    for ahead in range(index + 1, min(len(lines), index + DEFINITION_WINDOW)):
        inline_type = re.search(r"\btype\s*:\s*([A-Za-z0-9_-]+)", lines[ahead])
        if inline_type:
            return inline_type.group(1)
    return "yaml-name"


def is_mihomo_provider_key(lines: list[str], index: int) -> bool:
    seen_proxy_providers = False
    for back in range(index, -1, -1):
        line = lines[back]
        if re.match(r"^[A-Za-z0-9_-]+:\s*$", line):
            if line.startswith("proxy-providers:"):
                seen_proxy_providers = True
            elif seen_proxy_providers:
                return False
        if line.startswith("proxy-providers:"):
            return True
        if line.startswith("proxy-groups:"):
            return False
    return False


def extract_definitions(path: Path, repo: Path) -> list[Definition]:
    rel = str(path.relative_to(repo))
    lines = read_text(path).splitlines()
    defs: list[Definition] = []

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        surge = re.match(r"^([^=\[\]#][^=]*?)\s*=\s*([^,\s]+)", line)
        if surge and path.suffix.lower() in {".conf", ".dconf"}:
            name = surge.group(1).strip()
            kind = surge.group(2).strip()
            defs.append(Definition(name=name, file=rel, line=idx + 1, kind=kind, text=stripped))
            continue

        provider_key = re.match(r"^\s{2}([A-Za-z][\w-]*)\s*:\s*$", line)
        if provider_key and "Mihomo" in path.parts and is_mihomo_provider_key(lines, idx):
            name = provider_key.group(1)
            defs.append(Definition(name=name, file=rel, line=idx + 1, kind="mihomo-provider", text=stripped))
            continue

        name = parse_name_from_yaml(line)
        if name:
            kind = infer_yaml_kind(lines, idx)
            defs.append(Definition(name=name, file=rel, line=idx + 1, kind=kind, text=stripped))

    return defs


def find_config_files(repo: Path) -> list[Path]:
    files: list[Path] = []
    for dirname in DEFAULT_DIRS:
        base = repo / dirname
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_file() and path.suffix.lower() in CONFIG_SUFFIXES:
                files.append(path)
    return sorted(files)


def target_matches_line(target_norm: str, line_norm: str) -> bool:
    return bool(target_norm and target_norm in line_norm)


def target_matches_name(target_norm: str, name: str) -> bool:
    name_norm = normalize(name)
    return bool(target_norm and name_norm and (target_norm in name_norm or name_norm in target_norm))


def find_hits(repo: Path, files: Iterable[Path], targets: list[str], definitions: list[Definition]) -> dict[str, dict[str, list]]:
    results: dict[str, dict[str, list]] = {}

    for target in targets:
        target_norm = normalize(target)
        target_defs = [d for d in definitions if target_matches_name(target_norm, d.name)]
        target_definition_keys = {(d.file, d.line) for d in target_defs}
        hits: list[Hit] = []

        for path in files:
            rel = str(path.relative_to(repo))
            for idx, line in enumerate(read_text(path).splitlines(), start=1):
                if not target_matches_line(target_norm, normalize(line)):
                    continue
                kind = "definition" if (rel, idx) in target_definition_keys else "reference"
                hits.append(Hit(file=rel, line=idx, kind=kind, text=line.strip()))

        results[target] = {
            "definitions": target_defs,
            "hits": hits,
        }

    return results


def print_text_report(repo: Path, files: list[Path], results: dict[str, dict[str, list]]) -> None:
    print(f"Repo: {repo}")
    print("Scanned files:")
    for path in files:
        print(f"  - {path.relative_to(repo)}")

    for target, data in results.items():
        print()
        print(f"=== Target: {target} ===")
        definitions: list[Definition] = data["definitions"]
        hits: list[Hit] = data["hits"]

        print(f"Definitions: {len(definitions)}")
        for item in definitions:
            print(f"  {item.file}:{item.line} [{item.kind}] {item.name} :: {item.text}")

        print(f"Occurrences: {len(hits)}")
        for item in hits:
            print(f"  {item.file}:{item.line} [{item.kind}] {item.text}")

        if not hits:
            print("  (none)")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit ProxyConfig group definitions and references.")
    parser.add_argument("repo", type=Path, help="Path to ProxyConfig repository")
    parser.add_argument("--target", action="append", default=[], help="Group/provider/name fragment to audit; repeatable")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    repo = args.repo.resolve()
    if not repo.exists():
        print(f"error: repo does not exist: {repo}", file=sys.stderr)
        return 2
    if not args.target:
        print("error: provide at least one --target", file=sys.stderr)
        return 2

    files = find_config_files(repo)
    definitions: list[Definition] = []
    for path in files:
        definitions.extend(extract_definitions(path, repo))

    results = find_hits(repo, files, args.target, definitions)
    if args.json:
        payload = {
            "repo": str(repo),
            "files": [str(path.relative_to(repo)) for path in files],
            "targets": {
                key: {
                    "definitions": [asdict(item) for item in value["definitions"]],
                    "hits": [asdict(item) for item in value["hits"]],
                }
                for key, value in results.items()
            },
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_text_report(repo, files, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
