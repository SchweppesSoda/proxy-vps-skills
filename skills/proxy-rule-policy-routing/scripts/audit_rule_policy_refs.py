#!/usr/bin/env python3
"""Audit ProxyConfig rule targets and cross-client ordering contracts."""

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
    "Mihomo": (
        "Mihomo/AutoMihomo.Mobile.yaml",
        "Mihomo/AutoMihomo.OpenWrt.yaml",
        "Mihomo/SafeMihomo.yaml",
    ),
    "Stash": ("Stash/AutoStash.yaml",),
    "Surge": (
        "Surge/AutoSurge.conf",
        "Surge/Split Conf/AutoSurge/ProxyGroup.dconf",
        "Surge/Split Conf/AutoSurge/Rule.dconf",
    ),
    "Loon": ("Loon/AutoLoon.conf", "Loon/AutoLoonLite.conf"),
}
FINANCE_ORDER_FILES = {
    "Egern/AutoEgern.yaml": "Egern",
    "Mihomo/AutoMihomo.Mobile.yaml": "Mihomo",
    "Mihomo/AutoMihomo.OpenWrt.yaml": "Mihomo",
    "Stash/AutoStash.yaml": "Stash",
    "Surge/AutoSurge.conf": "Surge",
    "Loon/AutoLoon.conf": "Loon",
    "Loon/AutoLoonLite.conf": "Loon",
}
FINANCE_SEQUENCE = ("PayPal", "Banking", "Crypto")
MIHOMO_RULE_TYPES = {
    "RULE-SET",
    "GEOSITE",
    "GEOIP",
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
}
SURGE_RULE_PATTERN = re.compile(
    r"^(RULE-SET|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|"
    r"IP-CIDR|IP-CIDR6|GEOIP|PROCESS-NAME|USER-AGENT|URL-REGEX|FINAL),"
)


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


@dataclass
class OrderViolation:
    client: str
    file: str
    line: int
    expected: list[str]
    actual: list[str]
    reason: str


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


def normalized_rel(path: str) -> str:
    return path.replace("\\", "/")


def policy_scope(client: str, file: str) -> tuple[str, str]:
    normalized = normalized_rel(file)
    if client == "Surge" and normalized.endswith("/Rule.dconf"):
        normalized = normalized.rsplit("/", 1)[0] + "/ProxyGroup.dconf"
    return client, normalized


def extract_yaml_policy_defs(
    repo: Path, client: str, path: Path
) -> list[PolicyDef]:
    lines = read_lines(path)
    defs: list[PolicyDef] = []
    in_groups = False
    group_key = "policy_groups:" if client == "Egern" else "proxy-groups:"
    for idx, line in enumerate(lines, start=1):
        if line.startswith(group_key):
            in_groups = True
            continue
        if in_groups and (
            line.startswith("rules:") or line.startswith("rule-providers:")
        ):
            break
        if not in_groups:
            continue
        name = parse_yaml_name(line)
        if name:
            defs.append(PolicyDef(client, rel(path, repo), idx, name, line.strip()))
    return defs


def extract_conf_policy_defs(
    repo: Path, client: str, path: Path
) -> list[PolicyDef]:
    defs: list[PolicyDef] = []
    for idx, line in enumerate(read_lines(path), start=1):
        match = re.match(r"^([^=\[\]#][^=]*?)\s*=\s*([^,\s]+)", line)
        if not match:
            continue
        name = match.group(1).strip()
        kind = match.group(2).strip()
        if kind in {
            "select",
            "url-test",
            "fallback",
            "smart",
            "load-balance",
        } or name.endswith("Provider"):
            defs.append(PolicyDef(client, rel(path, repo), idx, name, line.strip()))
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
            refs.append(
                RuleRef(
                    "Egern",
                    rel(path, repo),
                    idx,
                    strip_quotes(policy.group(1)),
                    current_rule,
                    line.strip(),
                )
            )
            current_rule = ""
    return refs


def extract_mihomo_rules(
    repo: Path, client: str, path: Path
) -> list[RuleRef]:
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
        parts = [part.strip() for part in stripped[2:].split(",")]
        if len(parts) >= 3 and parts[0] in MIHOMO_RULE_TYPES:
            refs.append(
                RuleRef(client, rel(path, repo), idx, parts[2], parts[1], stripped)
            )
        elif len(parts) >= 2 and parts[0] in {"MATCH", "FINAL"}:
            refs.append(
                RuleRef(client, rel(path, repo), idx, parts[1], parts[0], stripped)
            )
    return refs


def extract_conf_rules(repo: Path, client: str, path: Path) -> list[RuleRef]:
    refs: list[RuleRef] = []
    for idx, line in enumerate(read_lines(path), start=1):
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("[")
            or not SURGE_RULE_PATTERN.match(stripped)
        ):
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
        refs.append(RuleRef(client, rel(path, repo), idx, policy, rule, stripped))
    return refs


def extract_loon_rules(repo: Path, path: Path) -> list[RuleRef]:
    refs = extract_conf_rules(repo, "Loon", path)
    for idx, line in enumerate(read_lines(path), start=1):
        stripped = line.strip()
        match = re.match(
            r"^(https?://[^,]+),\s*policy\s*=\s*([^,]+)",
            stripped,
            flags=re.IGNORECASE,
        )
        if match:
            refs.append(
                RuleRef(
                    "Loon",
                    rel(path, repo),
                    idx,
                    match.group(2).strip(),
                    match.group(1),
                    stripped,
                )
            )
    return sorted(refs, key=lambda item: item.line)


def logical_service(item: RuleRef) -> str:
    if item.policy == "AI Suite":
        return "AI Suite"
    if item.policy in FINANCE_SEQUENCE:
        return item.policy
    rule = item.rule.casefold()
    if "paypal" in rule:
        return "PayPal"
    if "/banking.list" in rule or rule.endswith("banking-custom"):
        return "Banking"
    if "/crypto.list" in rule or rule.endswith("crypto-custom"):
        return "Crypto"
    return item.policy


def audit_finance_order(repo: Path, refs: list[RuleRef]) -> list[OrderViolation]:
    by_file: dict[str, list[RuleRef]] = {}
    for item in refs:
        by_file.setdefault(normalized_rel(item.file), []).append(item)

    violations: list[OrderViolation] = []
    required = ("AI Suite", *FINANCE_SEQUENCE)
    for file, client in FINANCE_ORDER_FILES.items():
        if not (repo / file).exists():
            continue
        file_refs = by_file.get(file, [])
        services = [logical_service(item) for item in file_refs]
        missing = [service for service in required if service not in services]
        if missing:
            violations.append(
                OrderViolation(
                    client,
                    file,
                    0,
                    list(FINANCE_SEQUENCE),
                    [],
                    f"missing required service rules: {', '.join(missing)}",
                )
            )
            continue

        ai_positions = [
            idx for idx, service in enumerate(services) if service == "AI Suite"
        ]
        start = max(ai_positions) + 1
        actual = services[start : start + len(FINANCE_SEQUENCE)]
        positions_ok = all(
            [
                idx
                for idx, service in enumerate(services)
                if service == expected
            ]
            == [start + offset]
            for offset, expected in enumerate(FINANCE_SEQUENCE)
        )
        if actual != list(FINANCE_SEQUENCE) or not positions_ok:
            violations.append(
                OrderViolation(
                    client,
                    file,
                    file_refs[max(ai_positions)].line,
                    list(FINANCE_SEQUENCE),
                    actual,
                    (
                        "finance rules must be unique, contiguous, and "
                        "immediately follow the last AI rule"
                    ),
                )
            )
    return violations


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
            elif client in {"Mihomo", "Stash"}:
                defs.extend(extract_yaml_policy_defs(repo, client, path))
                refs.extend(extract_mihomo_rules(repo, client, path))
            elif client == "Surge":
                if path.name in {"AutoSurge.conf", "ProxyGroup.dconf"}:
                    defs.extend(extract_conf_policy_defs(repo, client, path))
                if path.name in {"AutoSurge.conf", "Rule.dconf"}:
                    refs.extend(extract_conf_rules(repo, client, path))
            elif client == "Loon":
                defs.extend(extract_conf_policy_defs(repo, client, path))
                refs.extend(extract_loon_rules(repo, path))

    order_violations = audit_finance_order(repo, refs)

    defs_by_scope: dict[tuple[str, str], set[str]] = {}
    for item in defs:
        defs_by_scope.setdefault(policy_scope(item.client, item.file), set()).add(
            item.name
        )

    undefined = [
        item
        for item in refs
        if item.policy not in BUILT_INS
        and item.policy
        not in defs_by_scope.get(policy_scope(item.client, item.file), set())
    ]

    if filter_set:
        defs = [item for item in defs if item.name.casefold() in filter_set]
        refs = [
            item
            for item in refs
            if item.policy.casefold() in filter_set
            or logical_service(item).casefold() in filter_set
            or item.rule.casefold() in filter_set
        ]
        undefined = [
            item for item in undefined if item.policy.casefold() in filter_set
        ]

    return {
        "repo": str(repo),
        "policy_definitions": [asdict(item) for item in defs],
        "rule_references": [asdict(item) for item in refs],
        "undefined_rule_policies": [asdict(item) for item in undefined],
        "finance_order_violations": [
            asdict(item) for item in order_violations
        ],
    }


def print_report(payload: dict[str, object]) -> None:
    print(f"Repo: {payload['repo']}")
    print()
    print("Policy definitions:")
    for item in payload["policy_definitions"]:
        print(
            f"  {item['file']}:{item['line']} "
            f"[{item['client']}] {item['name']}"
        )
    if not payload["policy_definitions"]:
        print("  (none)")
    print()
    print("Rule references:")
    for item in payload["rule_references"]:
        print(
            f"  {item['file']}:{item['line']} "
            f"[{item['client']}] {item['rule']} -> {item['policy']}"
        )
    if not payload["rule_references"]:
        print("  (none)")
    print()
    print("Undefined rule policies:")
    for item in payload["undefined_rule_policies"]:
        print(
            f"  {item['file']}:{item['line']} "
            f"[{item['client']}] {item['rule']} -> {item['policy']}"
        )
    if not payload["undefined_rule_policies"]:
        print("  (none)")
    print()
    print("Finance order violations:")
    for item in payload["finance_order_violations"]:
        actual = " -> ".join(item["actual"]) if item["actual"] else "(missing)"
        print(
            f"  {item['file']}:{item['line']} [{item['client']}] "
            f"{item['reason']}; actual: {actual}"
        )
    if not payload["finance_order_violations"]:
        print("  (none)")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit ProxyConfig rule policy references and ordering."
    )
    parser.add_argument("repo", type=Path)
    parser.add_argument(
        "--policy", action="append", default=[], help="Policy filter; repeatable"
    )
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
    return (
        1
        if payload["undefined_rule_policies"]
        or payload["finance_order_violations"]
        else 0
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
