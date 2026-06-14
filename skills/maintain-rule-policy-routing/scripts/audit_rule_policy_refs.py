#!/usr/bin/env python3
"""Audit rule targets against policy group definitions in ProxyConfig."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


BUILT_INS = {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "FINAL"}
CLIENT_FILES = {
    "Egern": ("Egern/AutoEgern.yaml",),
    "Mihomo": ("Mihomo/AutoMihomo.yaml",),
    "Surge": ("Surge/AutoSurge.conf", "Surge/Split Conf/AutoSurge/ProxyGroup.dconf", "Surge/Split Conf/AutoSurge/Rule.dconf"),
}


@dataclass
class PolicyDef:
    client: str
    file: str
    line: int
    name: str
    text: str


@dataclass
class RuleRef:
    client: str
    file: str
    line: int
    policy: str
    rule: str
    text: str


def configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig", errors="replace").splitlines()


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


def rel(path: Path, repo: Path) -> str:
    return str(path.relative_to(repo))


def extract_yaml_policy_defs(repo: Path, client: str, path: Path) -> list[PolicyDef]:
    lines = read_lines(path)
    defs: list[PolicyDef] = []
    in_groups = False
    group_key = "policy_groups:" if client == "Egern" else "proxy-groups:"
    for idx, line in enumerate(lines, start=1):
        if line.startswith(group_key):
            in_groups = True
            continue
        if in_groups and (line.startswith("rules:") or line.startswith("rule-providers:")):
            break
        if not in_groups:
            continue
        name = parse_yaml_name(line)
        if name:
            defs.append(PolicyDef(client, rel(path, repo), idx, name, line.strip()))
    return defs


def extract_surge_policy_defs(repo: Path, path: Path) -> list[PolicyDef]:
    defs: list[PolicyDef] = []
    for idx, line in enumerate(read_lines(path), start=1):
        match = re.match(r"^([^=\[\]#][^=]*?)\s*=\s*([^,\s]+)", line)
        if not match:
            continue
        name = match.group(1).strip()
        kind = match.group(2).strip()
        if kind in {"select", "url-test", "fallback", "smart", "load-balance"} or name.endswith("Provider"):
            defs.append(PolicyDef("Surge", rel(path, repo), idx, name, line.strip()))
    return defs


def extract_egern_rules(repo: Path, path: Path) -> list[RuleRef]:
    refs: list[RuleRef] = []
    lines = read_lines(path)
    in_rules = False
    current_rule = ""
    for idx, line in enumerate(lines, start=1):
        if line.startswith("rules:"):
            in_rules = True
            continue
        if in_rules and re.match(r"^[A-Za-z_][\w-]*:", line):
            break
        if not in_rules:
            continue
        match = re.match(r"^\s{6}match:\s*(.+?)\s*$", line)
        if match:
            current_rule = strip_quotes(match.group(1))
        policy = re.match(r"^\s{6}policy:\s*(.+?)\s*$", line)
        if policy:
            refs.append(RuleRef("Egern", rel(path, repo), idx, strip_quotes(policy.group(1)), current_rule, line.strip()))
            current_rule = ""
    return refs


def extract_mihomo_rules(repo: Path, path: Path) -> list[RuleRef]:
    refs: list[RuleRef] = []
    lines = read_lines(path)
    in_rules = False
    for idx, line in enumerate(lines, start=1):
        if line.startswith("rules:"):
            in_rules = True
            continue
        if in_rules and line.startswith("rule-providers:"):
            break
        if not in_rules:
            continue
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        body = stripped[2:]
        parts = [part.strip() for part in body.split(",")]
        if len(parts) >= 3 and parts[0] in {"RULE-SET", "GEOSITE", "GEOIP"}:
            refs.append(RuleRef("Mihomo", rel(path, repo), idx, parts[2], parts[1], stripped))
        elif len(parts) >= 2 and parts[0] in {"MATCH", "FINAL"}:
            refs.append(RuleRef("Mihomo", rel(path, repo), idx, parts[1], parts[0], stripped))
    return refs


def extract_surge_rules(repo: Path, path: Path) -> list[RuleRef]:
    refs: list[RuleRef] = []
    for idx, line in enumerate(read_lines(path), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("["):
            continue
        if not re.match(r"^(RULE-SET|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|IP-CIDR|GEOIP|FINAL),", stripped):
            continue
        parts = [part.strip() for part in stripped.split(",")]
        if parts[0] == "FINAL" and len(parts) >= 2:
            policy = parts[1]
            rule = "FINAL"
        elif len(parts) >= 3:
            policy = parts[2]
            rule = parts[1]
        else:
            continue
        refs.append(RuleRef("Surge", rel(path, repo), idx, policy, rule, stripped))
    return refs


def audit(repo: Path, filters: list[str]) -> dict[str, object]:
    repo = repo.resolve()
    filter_set = {item.casefold() for item in filters}
    defs: list[PolicyDef] = []
    refs: list[RuleRef] = []
    for client, names in CLIENT_FILES.items():
        for name in names:
            path = repo / name
            if not path.exists():
                continue
            if client == "Egern":
                defs.extend(extract_yaml_policy_defs(repo, client, path))
                refs.extend(extract_egern_rules(repo, path))
            elif client == "Mihomo":
                defs.extend(extract_yaml_policy_defs(repo, client, path))
                refs.extend(extract_mihomo_rules(repo, path))
            elif client == "Surge":
                if path.name in {"AutoSurge.conf", "ProxyGroup.dconf"}:
                    defs.extend(extract_surge_policy_defs(repo, path))
                if path.name in {"AutoSurge.conf", "Rule.dconf"}:
                    refs.extend(extract_surge_rules(repo, path))

    defs_by_client: dict[str, set[str]] = {}
    for item in defs:
        defs_by_client.setdefault(item.client, set()).add(item.name)

    undefined = [
        item
        for item in refs
        if item.policy not in BUILT_INS and item.policy not in defs_by_client.get(item.client, set())
    ]

    if filter_set:
        defs = [item for item in defs if item.name.casefold() in filter_set]
        refs = [item for item in refs if item.policy.casefold() in filter_set or item.rule.casefold() in filter_set]
        undefined = [item for item in undefined if item.policy.casefold() in filter_set]

    return {
        "repo": str(repo),
        "policy_definitions": [asdict(item) for item in defs],
        "rule_references": [asdict(item) for item in refs],
        "undefined_rule_policies": [asdict(item) for item in undefined],
    }


def print_report(payload: dict[str, object]) -> None:
    print(f"Repo: {payload['repo']}")
    print()
    print("Policy definitions:")
    for item in payload["policy_definitions"]:
        print(f"  {item['file']}:{item['line']} [{item['client']}] {item['name']}")
    if not payload["policy_definitions"]:
        print("  (none)")
    print()
    print("Rule references:")
    for item in payload["rule_references"]:
        print(f"  {item['file']}:{item['line']} [{item['client']}] {item['rule']} -> {item['policy']}")
    if not payload["rule_references"]:
        print("  (none)")
    print()
    print("Undefined rule policies:")
    for item in payload["undefined_rule_policies"]:
        print(f"  {item['file']}:{item['line']} [{item['client']}] {item['rule']} -> {item['policy']}")
    if not payload["undefined_rule_policies"]:
        print("  (none)")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit ProxyConfig rule policy references.")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--policy", action="append", default=[], help="Policy name to filter; repeatable")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    if not args.repo.exists():
        print(f"error: repo does not exist: {args.repo}", file=sys.stderr)
        return 2
    payload = audit(args.repo, args.policy)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_report(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
