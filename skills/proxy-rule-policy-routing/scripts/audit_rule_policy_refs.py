#!/usr/bin/env python3
"""Audit ProxyConfig rule targets, providers, types, and ordering contracts."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit


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
FULL_ORDER_FILES = {
    "Egern/AutoEgern.yaml": "Egern",
    "Mihomo/AutoMihomo.Mobile.yaml": "Mihomo",
    "Mihomo/AutoMihomo.OpenWrt.yaml": "Mihomo",
    "Stash/AutoStash.yaml": "Stash",
    "Surge/AutoSurge.conf": "Surge",
    "Loon/AutoLoon.conf": "Loon",
}
ORDER_FILES = {
    **FULL_ORDER_FILES,
    "Mihomo/SafeMihomo.yaml": "Mihomo",
    "Loon/AutoLoonLite.conf": "Loon",
}
FINANCE_ORDER_FILES = {
    **FULL_ORDER_FILES,
    "Loon/AutoLoonLite.conf": "Loon",
}
FINANCE_SEQUENCE = ("PayPal", "Banking", "Crypto")
APPLE_SEQUENCE = ("ApplePushDomain", "AppleMedia", "AppleCN", "Apple")
TV_SEQUENCE = ("AsianTV", "GlobalTV", "CNMainlandTV")
CN_GUARDS = {
    "AICN": ("aicn", "meta-ai-cn"),
    "MicrosoftCN": ("microsoftcn", "meta-microsoft-cn"),
    "ScholarCN": ("scholarcn", "meta-scholar-cn"),
    "SteamCN": ("steamcn", "meta-steam-cn"),
    "GameDownloadCN": ("gamedownloadcn", "meta-gamedownload-cn"),
}
LEGACY_PROVIDER_NAMES = {"metagooglecn", "metapaypalcn", "googlecn", "paypalcn"}
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
    kind: str
    text: str


@dataclass
class ProviderDef:
    client: str
    file: str
    line: int
    name: str
    behavior: str
    format: str
    url: str
    text: str


@dataclass
class OrderViolation:
    client: str
    file: str
    line: int
    expected: list[str]
    actual: list[str]
    reason: str


@dataclass
class CheckViolation:
    client: str
    file: str
    line: int
    subject: str
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
    return path.relative_to(repo).as_posix()


def normalized_rel(path: str) -> str:
    return path.replace("\\", "/")


def policy_scope(client: str, file: str) -> tuple[str, str]:
    normalized = normalized_rel(file)
    if client == "Surge" and normalized.endswith("/Rule.dconf"):
        normalized = normalized.rsplit("/", 1)[0] + "/ProxyGroup.dconf"
    return client, normalized


def conf_sections(lines: list[str]) -> dict[str, list[tuple[int, str]]]:
    sections: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    for index, line in enumerate(lines, start=1):
        match = re.match(r"^\[([^]]+)\]\s*$", line.strip())
        if match:
            current = match.group(1).strip().casefold()
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append((index, line))
    return sections


def extract_yaml_policy_defs(
    repo: Path, client: str, path: Path
) -> list[PolicyDef]:
    lines = read_lines(path)
    defs: list[PolicyDef] = []
    in_groups = False
    group_key = "policy_groups:" if client == "Egern" else "proxy-groups:"
    for index, line in enumerate(lines, start=1):
        if line.startswith(group_key):
            in_groups = True
            continue
        if in_groups and line and not line.startswith((" ", "#")):
            break
        if not in_groups:
            continue
        name = parse_yaml_name(line)
        if name:
            defs.append(PolicyDef(client, rel(path, repo), index, name, line.strip()))
    return defs


def extract_conf_policy_defs(
    repo: Path, client: str, path: Path
) -> list[PolicyDef]:
    lines = read_lines(path)
    if path.name == "ProxyGroup.dconf":
        candidates = list(enumerate(lines, start=1))
    else:
        candidates = conf_sections(lines).get("proxy group", [])
    defs: list[PolicyDef] = []
    for index, line in candidates:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = re.match(r"^([^=\[\]#][^=]*?)\s*=\s*([^,\s]+)", stripped)
        if not match:
            continue
        name = match.group(1).strip()
        kind = match.group(2).strip()
        if kind in {"select", "url-test", "fallback", "smart", "load-balance"}:
            defs.append(PolicyDef(client, rel(path, repo), index, name, stripped))
    return defs


def extract_yaml_provider_defs(
    repo: Path, client: str, path: Path
) -> list[ProviderDef]:
    lines = read_lines(path)
    providers: list[ProviderDef] = []
    templates: dict[str, dict[str, str]] = {}
    for index, line in enumerate(lines):
        anchor = re.match(r"^(\s*)[^:#]+:\s*&([A-Za-z0-9_-]+)\s*$", line)
        if not anchor:
            continue
        indent = len(anchor.group(1))
        values: dict[str, str] = {}
        for child in lines[index + 1 :]:
            if child.strip() and len(child) - len(child.lstrip()) <= indent:
                break
            prop = re.match(r"^\s+([A-Za-z_-]+):\s*(.*?)\s*(?:#.*)?$", child)
            if prop:
                values[prop.group(1).replace("-", "_")] = strip_quotes(prop.group(2))
        templates[anchor.group(2)] = values
    in_providers = False
    current: dict[str, str | int] | None = None

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        providers.append(
            ProviderDef(
                client=client,
                file=rel(path, repo),
                line=int(current["line"]),
                name=str(current["name"]),
                behavior=str(current.get("behavior", "")),
                format=str(current.get("format", "")),
                url=str(current.get("url", "")),
                text=str(current.get("text", "")),
            )
        )
        current = None

    for index, line in enumerate(lines, start=1):
        if line.startswith("rule-providers:"):
            in_providers = True
            continue
        if in_providers and line and not line.startswith((" ", "#")):
            flush()
            break
        if not in_providers:
            continue
        flow = re.match(r"^  ([^#][^:]+):\s*\{(.*)\}\s*(?:#.*)?$", line)
        if flow:
            flush()
            values: dict[str, str | int] = {
                "name": strip_quotes(flow.group(1)),
                "line": index,
                "text": line.strip(),
            }
            anchor = re.search(r"<<\s*:\s*\*([A-Za-z0-9_-]+)", flow.group(2))
            if anchor:
                values.update(templates.get(anchor.group(1), {}))
            for prop in re.finditer(
                r"(?:^|,)\s*([A-Za-z_-]+)\s*:\s*(\"[^\"]*\"|'[^']*'|[^,}]+)",
                flow.group(2),
            ):
                values[prop.group(1).replace("-", "_")] = strip_quotes(prop.group(2))
            current = values
            flush()
            continue
        header = re.match(r"^  ([^#][^:]+):\s*(?:#.*)?$", line)
        if header:
            flush()
            current = {
                "name": strip_quotes(header.group(1)),
                "line": index,
                "text": line.strip(),
            }
            continue
        merge = re.match(r"^    <<:\s*\*([A-Za-z0-9_-]+)\s*$", line)
        if current is not None and merge:
            current.update(templates.get(merge.group(1), {}))
            continue
        prop = re.match(r"^    ([A-Za-z_-]+):\s*(.*?)\s*(?:#.*)?$", line)
        if current is not None and prop:
            current[prop.group(1).replace("-", "_")] = strip_quotes(prop.group(2))
    flush()
    return providers


def extract_egern_rules(repo: Path, path: Path) -> list[RuleRef]:
    lines = read_lines(path)
    refs: list[RuleRef] = []
    in_rules = False
    entry: list[tuple[int, str]] = []

    def flush() -> None:
        nonlocal entry
        if not entry:
            return
        text = "\n".join(line for _, line in entry)
        if re.search(r"^\s+disabled:\s*true\s*$", text, flags=re.MULTILINE | re.I):
            entry = []
            return
        first_index, first_line = entry[0]
        kind_match = re.match(r"^\s*-\s*([A-Za-z_-]+):", first_line)
        match_value = ""
        policy_value = ""
        policy_line = first_index
        for index, line in entry:
            match = re.match(r"^\s+match:\s*(.+?)\s*$", line)
            if match:
                match_value = strip_quotes(match.group(1))
            policy = re.match(r"^\s+policy:\s*(.+?)\s*$", line)
            if policy:
                policy_value = strip_quotes(policy.group(1))
                policy_line = index
        if policy_value:
            refs.append(
                RuleRef(
                    "Egern",
                    rel(path, repo),
                    policy_line,
                    policy_value,
                    match_value,
                    kind_match.group(1).upper() if kind_match else "RULE",
                    text.strip(),
                )
            )
        entry = []

    for index, line in enumerate(lines, start=1):
        if line.startswith("rules:"):
            in_rules = True
            continue
        if in_rules and line and not line.startswith((" ", "#")):
            flush()
            break
        if not in_rules:
            continue
        if re.match(r"^  -\s+", line):
            flush()
            entry = [(index, line)]
        elif entry and line.strip() and not line.lstrip().startswith("#"):
            entry.append((index, line))
    flush()
    return refs


def extract_mihomo_rules(
    repo: Path, client: str, path: Path
) -> list[RuleRef]:
    refs: list[RuleRef] = []
    in_rules = False
    for index, line in enumerate(read_lines(path), start=1):
        if line.startswith("rules:"):
            in_rules = True
            continue
        if in_rules and line and not line.startswith((" ", "#")):
            break
        if not in_rules:
            continue
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        parts = [part.strip() for part in stripped[2:].split(",")]
        if len(parts) >= 3 and parts[0] in MIHOMO_RULE_TYPES:
            refs.append(
                RuleRef(
                    client,
                    rel(path, repo),
                    index,
                    parts[2],
                    parts[1],
                    parts[0],
                    stripped,
                )
            )
        elif len(parts) >= 2 and parts[0] in {"MATCH", "FINAL"}:
            refs.append(
                RuleRef(
                    client,
                    rel(path, repo),
                    index,
                    parts[1],
                    parts[0],
                    parts[0],
                    stripped,
                )
            )
    return refs


def parse_conf_rule(
    repo: Path, client: str, path: Path, index: int, line: str
) -> RuleRef | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or not SURGE_RULE_PATTERN.match(stripped):
        return None
    parts = [part.strip() for part in stripped.split(",")]
    if parts[0] == "FINAL" and len(parts) >= 2:
        policy = parts[1]
        rule = "FINAL"
    elif len(parts) >= 3:
        policy = parts[2]
        rule = parts[1]
    else:
        return None
    return RuleRef(client, rel(path, repo), index, policy, rule, parts[0], stripped)


def extract_conf_rules(repo: Path, client: str, path: Path) -> list[RuleRef]:
    lines = read_lines(path)
    if path.name == "Rule.dconf":
        candidates = list(enumerate(lines, start=1))
    else:
        candidates = conf_sections(lines).get("rule", [])
    refs: list[RuleRef] = []
    for index, line in candidates:
        parsed = parse_conf_rule(repo, client, path, index, line)
        if parsed:
            refs.append(parsed)
    return refs


def extract_loon_rules(repo: Path, path: Path) -> list[RuleRef]:
    lines = read_lines(path)
    sections = conf_sections(lines)
    local: list[RuleRef] = []
    for index, line in sections.get("rule", []):
        parsed = parse_conf_rule(repo, "Loon", path, index, line)
        if parsed:
            local.append(parsed)
    remote: list[RuleRef] = []
    for index, line in sections.get("remote rule", []):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.search(r"\benabled\s*=\s*false\b", stripped, flags=re.I):
            continue
        match = re.match(
            r"^(https?://[^,]+),\s*policy\s*=\s*([^,]+)",
            stripped,
            flags=re.I,
        )
        if match:
            remote.append(
                RuleRef(
                    "Loon",
                    rel(path, repo),
                    index,
                    match.group(2).strip(),
                    match.group(1),
                    "REMOTE-RULE",
                    stripped,
                )
            )
    # Loon stores FINAL in [Rule] before [Remote Rule], but remote rules are
    # logically evaluated before the local final catch-all.
    return [item for item in local if item.kind != "FINAL"] + remote + [
        item for item in local if item.kind == "FINAL"
    ]


def flat_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", unquote(value).casefold())


def rule_blob(item: RuleRef) -> tuple[str, str]:
    rule = unquote(item.rule)
    if rule.startswith(("http://", "https://")):
        rule = urlsplit(rule).path
    text_without_urls = re.sub(r"https?://[^,\s]+", "", unquote(item.text))
    readable = f"{rule} {item.policy} {text_without_urls}".casefold()
    return readable, flat_text(readable)


def logical_service(item: RuleRef) -> str:
    _, flat = rule_blob(item)
    if item.policy == "AI Suite":
        return "AI Suite"
    if "paypal" in flat:
        return "PayPal"
    if "banking" in flat:
        return "Banking"
    if "crypto" in flat:
        return "Crypto"
    return item.policy


def is_ip_rule(item: RuleRef) -> bool:
    readable, flat = rule_blob(item)
    if item.kind in {"IP-CIDR", "IP-CIDR6", "GEOIP"}:
        return True
    if "/surge/ip/" in readable or "/mihomo/ip/" in readable:
        return True
    return any(
        token in flat
        for token in (
            "applepuship",
            "telegramip",
            "twitterip",
            "googlefcmip",
            "youtubeip",
            "netflixip",
            "googleip",
            "proxyip",
            "chinaip",
            "cnip",
            "domesticips",
            "chinaasn",
            "asnchina",
        )
    )


def classify_rule(item: RuleRef) -> tuple[int, str] | None:
    readable, flat = rule_blob(item)
    policy_flat = flat_text(item.policy)

    if item.kind in {"FINAL", "DEFAULT"} or item.rule == "MATCH":
        return 170, "Final"
    if (
        item.kind == "SSID"
        or "private" in flat
        or "lanlist" in flat
        or "zmmc" in flat
        or (item.policy == "DIRECT" and item.kind in {"IP-CIDR", "IP-CIDR6"})
    ):
        return 10, "HardLocal"
    if "mydirect" in flat:
        return 20, "MyDirect"
    if "myproxy" in flat and "twitter" not in flat:
        return 21, "MyProxy"
    if policy_flat == "adblock" or "advertising" in flat:
        return 30, "AdBlock"
    if "httpdns" in flat:
        return 31, "HTTPDNS"
    if item.policy == "DIRECT" and "special" in flat:
        return 32, "SpecialDirect"
    if "appleintelligence" in flat:
        return 41, "AppleIntelligence"
    if item.policy == "AI Suite" or any(
        token in flat for token in ("opena", "claude", "anthropic", "copilot", "gemini")
    ):
        return 40, "AIGlobal"
    service = logical_service(item)
    if service == "PayPal":
        return 50, "PayPal"
    if service == "Banking":
        return 51, "Banking"
    if service == "Crypto":
        return 52, "Crypto"

    if is_ip_rule(item):
        if "applepush" in flat:
            return 150, "ApplePushIP"
        if "telegram" in flat:
            return 151, "TelegramIP"
        if "twitter" in flat:
            return 152, "TwitterIP"
        if "googlefcm" in flat:
            return 153, "GoogleFCMIP"
        if "youtube" in flat:
            return 154, "YouTubeIP"
        if "netflix" in flat:
            return 155, "NetflixIP"
        if "google" in flat:
            return 156, "GoogleIP"
        if "proxy" in flat:
            return 157, "ProxyIP"
        if item.kind == "GEOIP" or any(
            token in flat
            for token in (
                "china",
                "cnip",
                "domesticips",
                "geoipcn",
                "chinaasn",
                "asnchina",
            )
        ):
            return 160, "ChinaIP"
        return 159, "OtherIP"

    for token, rank, label in (
        ("telegram", 60, "Telegram"),
        ("discord", 61, "Discord"),
        ("twitter", 62, "Twitter"),
        ("tiktok", 63, "TikTok"),
        ("emby", 70, "Emby"),
        ("youtube", 71, "YouTube"),
        ("spotify", 72, "Spotify"),
        ("netflix", 73, "Netflix"),
        ("disney", 74, "Disney"),
    ):
        if token in flat:
            return rank, label
    if "applepush" in flat:
        return 80, "ApplePushDomain"
    if policy_flat == "appletv" or any(
        token in flat for token in ("appletv", "applemusic", "applenews")
    ):
        return 81, "AppleMedia"
    if policy_flat == "applecn" or "applecn" in flat:
        return 82, "AppleCN"
    if policy_flat == "apple" or "applelist" in flat:
        return 83, "Apple"
    if policy_flat == "asiantv":
        return 90, "AsianTV"
    if policy_flat == "globaltv":
        return 91, "GlobalTV"
    if policy_flat == "cnmainlandtv":
        return 92, "CNMainlandTV"
    if "microsoftcn" in flat or "metamicrosoftcn" in flat:
        return 100, "MicrosoftCN"
    if "microsoft" in flat:
        return 101, "Microsoft"
    if "scholarglobal" in flat or policy_flat == "scholar":
        return 102, "ScholarGlobal"
    if "googlefcm" in flat:
        return 103, "GoogleFCM"
    if "github" in flat:
        return 104, "GitHub"
    if "googleglobal" in flat:
        return 105, "GoogleGlobal"
    if "steamcn" in flat or "metasteamcn" in flat:
        return 106, "SteamCN"
    if "gamedownloadcn" in flat or "metagamedownloadcn" in flat:
        return 107, "GameDownloadCN"
    if "gamedownload" in flat:
        return 108, "GameDownload"
    if "steam" in flat:
        return 109, "Steam"
    if "speedtest" in flat:
        return 110, "Speedtest"
    if any(
        token in flat
        for token in ("proxyglobal", "geolocationnotcn", "globallist", "proxydomain")
    ):
        return 120, "BroadGlobal"
    if "aicn" in flat or "meta-ai-cn" in readable:
        return 130, "AICN"
    if "scholarcn" in flat or "meta-scholar-cn" in readable:
        return 131, "ScholarCN"
    if item.policy == "Domestic" and any(
        token in flat for token in ("wechat", "netease", "tencent", "wetv", "youku")
    ):
        return 132, "NarrowDomestic"
    if item.policy == "Domestic" and any(
        token in flat
        for token in ("geolocationcn", "metacn", "domesticlist", "chinalist")
    ):
        return 140, "BroadCN"
    return None


def refs_by_file(refs: list[RuleRef]) -> dict[str, list[RuleRef]]:
    grouped: dict[str, list[RuleRef]] = {}
    for item in refs:
        grouped.setdefault(normalized_rel(item.file), []).append(item)
    return grouped


def audit_finance_order(repo: Path, refs: list[RuleRef]) -> list[OrderViolation]:
    grouped = refs_by_file(refs)
    violations: list[OrderViolation] = []
    required = ("AI Suite", *FINANCE_SEQUENCE)
    for file, client in FINANCE_ORDER_FILES.items():
        if not (repo / file).exists():
            continue
        file_refs = grouped.get(file, [])
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
            index for index, service in enumerate(services) if service == "AI Suite"
        ]
        start = max(ai_positions) + 1
        actual = services[start : start + len(FINANCE_SEQUENCE)]
        positions_ok = all(
            [
                index
                for index, service in enumerate(services)
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
                    "finance rules must be unique, contiguous, and immediately follow the last AI rule",
                )
            )
    return violations


def audit_canonical_order(repo: Path, refs: list[RuleRef]) -> list[OrderViolation]:
    grouped = refs_by_file(refs)
    violations: list[OrderViolation] = []
    for file, client in ORDER_FILES.items():
        if not (repo / file).exists():
            continue
        previous: tuple[int, str, RuleRef] | None = None
        for item in grouped.get(file, []):
            classified = classify_rule(item)
            if classified is None:
                continue
            rank, label = classified
            if previous and rank < previous[0]:
                violations.append(
                    OrderViolation(
                        client,
                        file,
                        item.line,
                        [previous[1], label],
                        [label, previous[1]],
                        f"canonical order inversion after line {previous[2].line}",
                    )
                )
            previous = (rank, label, item)
    return violations


def audit_contiguous_block(
    repo: Path,
    refs: list[RuleRef],
    sequence: tuple[str, ...],
    block_name: str,
) -> list[OrderViolation]:
    grouped = refs_by_file(refs)
    violations: list[OrderViolation] = []
    allowed = set(sequence)
    for file, client in FULL_ORDER_FILES.items():
        if not (repo / file).exists():
            continue
        file_refs = grouped.get(file, [])
        labels = [
            classify_rule(item)[1] if classify_rule(item) else ""
            for item in file_refs
        ]
        positions = [index for index, label in enumerate(labels) if label in allowed]
        present = []
        for label in labels:
            if label in allowed and (not present or present[-1] != label):
                present.append(label)
        if set(present) != allowed or tuple(present) != sequence:
            violations.append(
                OrderViolation(
                    client,
                    file,
                    file_refs[positions[0]].line if positions else 0,
                    list(sequence),
                    present,
                    f"{block_name} block is missing or out of order",
                )
            )
            continue
        start, end = min(positions), max(positions)
        intruders = [
            file_refs[index]
            for index in range(start, end + 1)
            if labels[index] not in allowed
        ]
        if intruders:
            violations.append(
                OrderViolation(
                    client,
                    file,
                    intruders[0].line,
                    list(sequence),
                    present,
                    f"{block_name} block is split by {intruders[0].rule}",
                )
            )
    return violations


def audit_orphan_providers(
    providers: list[ProviderDef], refs: list[RuleRef]
) -> list[ProviderDef]:
    used: dict[tuple[str, str], set[str]] = {}
    for item in refs:
        if item.kind == "RULE-SET" and not item.rule.startswith(("http://", "https://")):
            used.setdefault((item.client, normalized_rel(item.file)), set()).add(item.rule)
    return [
        item
        for item in providers
        if item.name not in used.get((item.client, normalized_rel(item.file)), set())
    ]


def audit_provider_types(
    providers: list[ProviderDef], refs: list[RuleRef]
) -> list[CheckViolation]:
    violations: list[CheckViolation] = []
    by_key = {
        (item.client, normalized_rel(item.file), item.name): item for item in providers
    }
    for item in providers:
        url = unquote(item.url).casefold().replace("\\", "/")
        is_custom_mrs = "schweppessoda/customrules" in url and "/mihomo/" in url and url.endswith(".mrs")
        is_custom_ip = is_custom_mrs and "/mihomo/ip/" in url
        if is_custom_ip and item.behavior != "ipcidr":
            violations.append(
                CheckViolation(item.client, item.file, item.line, item.name, "CustomRules IP MRS must use behavior: ipcidr")
            )
        if is_custom_mrs and not is_custom_ip and item.behavior != "domain":
            violations.append(
                CheckViolation(item.client, item.file, item.line, item.name, "CustomRules domain MRS must use behavior: domain")
            )
        if is_custom_mrs and item.format != "mrs":
            violations.append(
                CheckViolation(item.client, item.file, item.line, item.name, "CustomRules MRS provider must declare format: mrs")
            )
        if "schweppessoda/customrules" in url and "/refs/heads/master/" in url:
            violations.append(
                CheckViolation(item.client, item.file, item.line, item.name, "generated CustomRules artifacts must use auto-build, not master")
            )
        if flat_text(item.name) in LEGACY_PROVIDER_NAMES:
            violations.append(
                CheckViolation(item.client, item.file, item.line, item.name, "legacy GoogleCN/PayPalCN provider is forbidden")
            )
    for ref in refs:
        provider = by_key.get((ref.client, normalized_rel(ref.file), ref.rule))
        if provider and provider.behavior == "ipcidr" and "no-resolve" not in ref.text:
            violations.append(
                CheckViolation(ref.client, ref.file, ref.line, ref.rule, "ipcidr RULE-SET reference must include no-resolve")
            )
        readable = unquote(ref.rule).casefold().replace("\\", "/")
        if "schweppessoda/customrules" in readable and "/refs/heads/master/" in readable:
            violations.append(
                CheckViolation(ref.client, ref.file, ref.line, ref.rule, "generated CustomRules LIST must use auto-build, not master")
            )
    return violations


def audit_cn_guards(refs: list[RuleRef]) -> list[CheckViolation]:
    violations: list[CheckViolation] = []
    for item in refs:
        readable, flat = rule_blob(item)
        for service, tokens in CN_GUARDS.items():
            if any(token in flat or token in readable for token in tokens):
                if item.policy != "Domestic":
                    violations.append(
                        CheckViolation(
                            item.client,
                            item.file,
                            item.line,
                            service,
                            f"CN service guard must route to Domestic, not {item.policy}",
                        )
                    )
                break
        if flat_text(item.rule) in LEGACY_PROVIDER_NAMES:
            violations.append(
                CheckViolation(item.client, item.file, item.line, item.rule, "legacy GoogleCN/PayPalCN rule is forbidden")
            )
    return violations


def audit_loon_tags(refs: list[RuleRef]) -> list[OrderViolation]:
    violations: list[OrderViolation] = []
    grouped = refs_by_file(refs)
    file = "Loon/AutoLoon.conf"
    numbered: list[tuple[int, RuleRef]] = []
    for item in grouped.get(file, []):
        match = re.search(r"\btag\s*=\s*(\d+)-", item.text, flags=re.I)
        if match:
            numbered.append((int(match.group(1)), item))
    expected = list(range(1, len(numbered) + 1))
    actual = [number for number, _ in numbered]
    if actual != expected:
        violations.append(
            OrderViolation(
                "Loon",
                file,
                numbered[0][1].line if numbered else 0,
                [str(value) for value in expected],
                [str(value) for value in actual],
                "Loon numeric remote-rule tags must be sequential",
            )
        )
    return violations


def audit_generated_sync(refs: list[RuleRef]) -> list[CheckViolation]:
    grouped = refs_by_file(refs)
    full = grouped.get("Surge/AutoSurge.conf", [])
    split = grouped.get("Surge/Split Conf/AutoSurge/Rule.dconf", [])
    if not full or not split:
        return []
    signature = lambda item: (item.kind, item.rule, item.policy)
    full_signatures = [signature(item) for item in full]
    split_signatures = [signature(item) for item in split]
    if full_signatures == split_signatures:
        return []
    mismatch = next(
        (
            index
            for index, pair in enumerate(zip(full_signatures, split_signatures))
            if pair[0] != pair[1]
        ),
        min(len(full_signatures), len(split_signatures)),
    )
    return [
        CheckViolation(
            "Surge",
            "Surge/Split Conf/AutoSurge/Rule.dconf",
            split[mismatch].line if mismatch < len(split) else 0,
            "Surge Full/Split",
            f"generated Rule.dconf differs at rule {mismatch + 1} (full={len(full)}, split={len(split)})",
        )
    ]


def audit(repo: Path, filters: list[str]) -> dict[str, object]:
    repo = repo.resolve()
    filter_set = {item.casefold() for item in filters}
    defs: list[PolicyDef] = []
    refs: list[RuleRef] = []
    providers: list[ProviderDef] = []
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
                providers.extend(extract_yaml_provider_defs(repo, client, path))
            elif client == "Surge":
                if path.name in {"AutoSurge.conf", "ProxyGroup.dconf"}:
                    defs.extend(extract_conf_policy_defs(repo, client, path))
                if path.name in {"AutoSurge.conf", "Rule.dconf"}:
                    refs.extend(extract_conf_rules(repo, client, path))
            elif client == "Loon":
                defs.extend(extract_conf_policy_defs(repo, client, path))
                refs.extend(extract_loon_rules(repo, path))

    defs_by_scope: dict[tuple[str, str], set[str]] = {}
    for item in defs:
        defs_by_scope.setdefault(policy_scope(item.client, item.file), set()).add(item.name)
    undefined = [
        item
        for item in refs
        if item.policy not in BUILT_INS
        and item.policy not in defs_by_scope.get(policy_scope(item.client, item.file), set())
    ]
    finance_violations = audit_finance_order(repo, refs)
    order_violations = [
        *audit_canonical_order(repo, refs),
        *audit_contiguous_block(repo, refs, APPLE_SEQUENCE, "Apple"),
        *audit_contiguous_block(repo, refs, TV_SEQUENCE, "regional TV"),
        *audit_loon_tags(refs),
    ]
    orphan_providers = audit_orphan_providers(providers, refs)
    type_violations = audit_provider_types(providers, refs)
    cn_violations = audit_cn_guards(refs)
    sync_violations = audit_generated_sync(refs)

    if filter_set:
        defs = [item for item in defs if item.name.casefold() in filter_set]
        providers = [item for item in providers if item.name.casefold() in filter_set]
        refs = [
            item
            for item in refs
            if item.policy.casefold() in filter_set
            or logical_service(item).casefold() in filter_set
            or item.rule.casefold() in filter_set
        ]
        undefined = [item for item in undefined if item.policy.casefold() in filter_set]
        orphan_providers = [
            item for item in orphan_providers if item.name.casefold() in filter_set
        ]

    return {
        "repo": str(repo),
        "policy_definitions": [asdict(item) for item in defs],
        "rule_references": [asdict(item) for item in refs],
        "rule_providers": [asdict(item) for item in providers],
        "undefined_rule_policies": [asdict(item) for item in undefined],
        "finance_order_violations": [asdict(item) for item in finance_violations],
        "canonical_order_violations": [asdict(item) for item in order_violations],
        "orphan_rule_providers": [asdict(item) for item in orphan_providers],
        "provider_type_violations": [asdict(item) for item in type_violations],
        "cn_guard_violations": [asdict(item) for item in cn_violations],
        "generated_sync_violations": [asdict(item) for item in sync_violations],
    }


def print_items(payload: dict[str, object], key: str, title: str) -> None:
    print(f"{title}:")
    items = payload[key]
    for item in items:
        subject = item.get("name") or item.get("subject") or item.get("rule")
        reason = item.get("reason", "")
        suffix = f" — {reason}" if reason else ""
        print(f"  {item['file']}:{item['line']} [{item['client']}] {subject}{suffix}")
    if not items:
        print("  (none)")
    print()


def print_report(payload: dict[str, object]) -> None:
    print(f"Repo: {payload['repo']}")
    print()
    print_items(payload, "undefined_rule_policies", "Undefined rule policies")
    print_items(payload, "finance_order_violations", "Finance order violations")
    print_items(payload, "canonical_order_violations", "Canonical order violations")
    print_items(payload, "orphan_rule_providers", "Orphan rule providers")
    print_items(payload, "provider_type_violations", "Provider type violations")
    print_items(payload, "cn_guard_violations", "CN guard violations")
    print_items(payload, "generated_sync_violations", "Generated Full/Split drift")
    print(
        "Inventory: "
        f"{len(payload['policy_definitions'])} policies, "
        f"{len(payload['rule_providers'])} providers, "
        f"{len(payload['rule_references'])} active rules"
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit ProxyConfig rule policy references and canonical ordering."
    )
    parser.add_argument("repo", type=Path)
    parser.add_argument(
        "--policy", action="append", default=[], help="Policy filter; repeatable"
    )
    parser.add_argument(
        "--require-generated-sync",
        action="store_true",
        help="Fail when Surge Full and generated Split Rule.dconf differ.",
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
    failures = [
        "undefined_rule_policies",
        "finance_order_violations",
        "canonical_order_violations",
        "orphan_rule_providers",
        "provider_type_violations",
        "cn_guard_violations",
    ]
    if args.require_generated_sync:
        failures.append("generated_sync_violations")
    return 1 if any(payload[key] for key in failures) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
