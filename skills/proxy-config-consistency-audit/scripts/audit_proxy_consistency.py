#!/usr/bin/env python3
"""Read-only consistency audit for ProxyConfig."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


REGIONS = ("HK", "TW", "SG", "JP", "US")
PARTIAL_REGION_BASES = {"Residential", "Relay-Res", "Dialer-Res"}
CLIENT_FILES = {
    "Egern": ("Egern/AutoEgern.yaml",),
    "Mihomo": ("Mihomo/AutoMihomo.yaml",),
    "Surge": ("Surge/AutoSurge.conf", "Surge/Split Conf/AutoSurge/ProxyGroup.dconf", "Surge/Split Conf/AutoSurge/Rule.dconf"),
}
BUILT_INS = {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "FINAL"}


@dataclass
class Definition:
    client: str
    file: str
    line: int
    kind: str
    name: str
    text: str


@dataclass
class Issue:
    severity: str
    kind: str
    subject: str
    detail: str


def configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig", errors="replace").splitlines()


def rel(path: Path, repo: Path) -> str:
    return str(path.relative_to(repo))


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_yaml_name(line: str) -> str | None:
    flow = re.search(r"\bname\s*:\s*([^,}#]+)", line)
    if flow:
        return strip_quotes(flow.group(1))
    block = re.match(r"^\s*name\s*:\s*(.+?)\s*(?:#.*)?$", line)
    if block:
        return strip_quotes(block.group(1))
    return None


def visible_name(name: str) -> str:
    return re.sub(r"^[^\wA-Za-z]+", "", name).strip()


def normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def target_match(name: str, targets: set[str]) -> bool:
    if not targets:
        return True
    name_norm = normalized(name)
    return any(target in name_norm or name_norm in target for target in targets)


def region_base(name: str) -> tuple[str, str] | None:
    clean = visible_name(name)
    match = re.match(r"^(.+)-(" + "|".join(REGIONS) + r")$", clean)
    if not match:
        return None
    return match.group(1), match.group(2)


def is_mihomo_provider_key(lines: list[str], index: int) -> bool:
    for back in range(index, -1, -1):
        line = lines[back]
        if line.startswith("proxy-providers:"):
            return True
        if line.startswith("proxy-groups:"):
            return False
    return False


def extract_yaml_defs(repo: Path, client: str, path: Path) -> list[Definition]:
    defs: list[Definition] = []
    lines = read_lines(path)
    for idx, line in enumerate(lines, start=1):
        if client == "Mihomo":
            provider = re.match(r"^\s{2}([A-Za-z][\w-]*)\s*:\s*$", line)
            if provider and is_mihomo_provider_key(lines, idx - 1):
                defs.append(Definition(client, rel(path, repo), idx, "provider", provider.group(1), line.strip()))
                continue
        name = parse_yaml_name(line)
        if not name:
            continue
        kind = "provider" if re.search(r"[-_]Provider$", name) else "group"
        defs.append(Definition(client, rel(path, repo), idx, kind, name, line.strip()))
    return defs


def extract_surge_defs(repo: Path, path: Path) -> list[Definition]:
    defs: list[Definition] = []
    for idx, line in enumerate(read_lines(path), start=1):
        match = re.match(r"^([^=\[\]#][^=]*?)\s*=\s*([^,\s]+)", line)
        if not match:
            continue
        name = match.group(1).strip()
        kind = "provider" if name.endswith("Provider") else "group"
        defs.append(Definition("Surge", rel(path, repo), idx, kind, name, line.strip()))
    return defs


def extract_rule_refs(repo: Path) -> list[tuple[str, str, int, str, str]]:
    refs: list[tuple[str, str, int, str, str]] = []
    egern = repo / "Egern/AutoEgern.yaml"
    if egern.exists():
        in_rules = False
        for idx, line in enumerate(read_lines(egern), start=1):
            if line.startswith("rules:"):
                in_rules = True
                continue
            if in_rules and re.match(r"^[A-Za-z_][\w-]*:", line):
                break
            if not in_rules:
                continue
            match = re.match(r"^\s{6}policy:\s*(.+?)\s*$", line)
            if match:
                refs.append(("Egern", rel(egern, repo), idx, strip_quotes(match.group(1)), line.strip()))
    mihomo = repo / "Mihomo/AutoMihomo.yaml"
    if mihomo.exists():
        in_rules = False
        for idx, line in enumerate(read_lines(mihomo), start=1):
            if line.startswith("rules:"):
                in_rules = True
                continue
            if in_rules and line.startswith("rule-providers:"):
                break
            if not in_rules:
                continue
            parts = [part.strip() for part in line.strip()[2:].split(",")] if line.strip().startswith("- ") else []
            if len(parts) >= 3 and parts[0] in {"RULE-SET", "GEOSITE", "GEOIP"}:
                refs.append(("Mihomo", rel(mihomo, repo), idx, parts[2], line.strip()))
            elif len(parts) >= 2 and parts[0] in {"MATCH", "FINAL"}:
                refs.append(("Mihomo", rel(mihomo, repo), idx, parts[1], line.strip()))
    for surge_name in ("Surge/AutoSurge.conf", "Surge/Split Conf/AutoSurge/Rule.dconf"):
        surge = repo / surge_name
        if not surge.exists():
            continue
        for idx, line in enumerate(read_lines(surge), start=1):
            stripped = line.strip()
            if not re.match(r"^(RULE-SET|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|GEOIP|FINAL),", stripped):
                continue
            parts = [part.strip() for part in stripped.split(",")]
            if parts[0] == "FINAL" and len(parts) >= 2:
                refs.append(("Surge", rel(surge, repo), idx, parts[1], stripped))
            elif len(parts) >= 3:
                refs.append(("Surge", rel(surge, repo), idx, parts[2], stripped))
    return refs


def audit(repo: Path, raw_targets: list[str]) -> dict[str, object]:
    repo = repo.resolve()
    targets = {normalized(item) for item in raw_targets}
    all_defs: list[Definition] = []
    for client, names in CLIENT_FILES.items():
        for name in names:
            path = repo / name
            if not path.exists():
                continue
            if client == "Surge":
                all_defs.extend(extract_surge_defs(repo, path))
            else:
                all_defs.extend(extract_yaml_defs(repo, client, path))

    defs = [item for item in all_defs if target_match(item.name, targets)]
    providers: dict[str, dict[str, list[Definition]]] = {}
    region_groups: dict[str, dict[str, dict[str, list[Definition]]]] = {}

    for item in defs:
        if item.kind == "provider":
            base = re.sub(r"[-_]?Provider$", "", item.name)
            providers.setdefault(base, {}).setdefault(item.client, []).append(item)
        rb = region_base(item.name)
        if rb:
            base, region = rb
            region_groups.setdefault(base, {}).setdefault(item.client, {}).setdefault(region, []).append(item)

    issues: list[Issue] = []
    all_clients = {"Egern", "Mihomo", "Surge"}
    for provider, by_client in sorted(providers.items()):
        present = set(by_client)
        if len(present) < 2:
            continue
        missing = sorted(all_clients - present)
        if missing:
            issues.append(Issue("info", "provider-client-coverage", provider, f"present in {sorted(present)}, missing in {missing}"))

    for base, by_client in sorted(region_groups.items()):
        if base in PARTIAL_REGION_BASES:
            continue
        for client, by_region in sorted(by_client.items()):
            present = set(by_region)
            if present and present != set(REGIONS):
                issues.append(Issue("warning", "region-coverage", f"{client}:{base}", f"has {sorted(present)}, missing {sorted(set(REGIONS) - present)}"))

    if not targets:
        names_by_client: dict[str, set[str]] = {}
        for item in all_defs:
            names_by_client.setdefault(item.client, set()).add(item.name)
        for client, file, line, policy, text in extract_rule_refs(repo):
            if policy in BUILT_INS:
                continue
            if policy not in names_by_client.get(client, set()):
                issues.append(Issue("warning", "undefined-rule-policy", f"{file}:{line}", f"{client} rule targets undefined policy {policy}: {text}"))

    return {
        "repo": str(repo),
        "providers": {
            key: {client: [asdict(item) for item in items] for client, items in value.items()}
            for key, value in providers.items()
        },
        "region_groups": {
            key: {
                client: {region: [asdict(item) for item in items] for region, items in regions.items()}
                for client, regions in value.items()
            }
            for key, value in region_groups.items()
        },
        "issues": [asdict(item) for item in issues],
    }


def print_report(payload: dict[str, object]) -> None:
    print(f"Repo: {payload['repo']}")
    print()
    print("Providers:")
    providers = payload["providers"]
    if not providers:
        print("  (none)")
    for name, by_client in providers.items():
        clients = ", ".join(sorted(by_client))
        print(f"  {name}: {clients}")
    print()
    print("Region group coverage:")
    groups = payload["region_groups"]
    if not groups:
        print("  (none)")
    for name, by_client in groups.items():
        parts = []
        for client, regions in sorted(by_client.items()):
            parts.append(f"{client}={','.join(sorted(regions))}")
        print(f"  {name}: {'; '.join(parts)}")
    print()
    print("Issues:")
    issues = payload["issues"]
    if not issues:
        print("  (none)")
    for item in issues:
        print(f"  [{item['severity']}] {item['kind']} {item['subject']}: {item['detail']}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit ProxyConfig cross-client consistency.")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--target", action="append", default=[], help="Provider/group fragment to filter; repeatable")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    if not args.repo.exists():
        print(f"error: repo does not exist: {args.repo}", file=sys.stderr)
        return 2
    payload = audit(args.repo, args.target)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_report(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
