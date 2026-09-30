#!/usr/bin/env python3
"""Audit ProxyConfig rule targets, providers, types, and ordering contracts."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from urllib.parse import unquote, urlsplit


BUILT_INS = {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-TINYGIF", "FINAL"}
CLIENT_FILES = {
    "Egern": ("Egern/AutoEgern.yaml", "Egern/AutoEgernLite.yaml"),
    "Mihomo": (
        "Mihomo/AutoMihomo.Mobile.yaml",
        "Mihomo/AutoMihomo.OpenWrt.yaml",
        "Mihomo/SafeMihomo.yaml",
    ),
    "Stash": ("Stash/AutoStash.yaml",),
}
RETIRED_PROFILES = ("Loon/AutoLoon.conf", "Loon/AutoLoonLite.conf")
FULL_ORDER_FILES = {
    "Egern/AutoEgern.yaml": "Egern",
    "Mihomo/AutoMihomo.Mobile.yaml": "Mihomo",
    "Mihomo/AutoMihomo.OpenWrt.yaml": "Mihomo",
    "Stash/AutoStash.yaml": "Stash",
}
ORDER_FILES = {
    **FULL_ORDER_FILES,
    "Mihomo/SafeMihomo.yaml": "Mihomo",
    "Egern/AutoEgernLite.yaml": "Egern",
}
FINANCE_ORDER_FILES = {
    **FULL_ORDER_FILES,
    "Egern/AutoEgernLite.yaml": "Egern",
}
FINANCE_SEQUENCE = ("PayPal", "Banking", "Crypto")
SERVICE_ADDRESS_SEQUENCE = (
    "ClaudeIP", "ApplePushIP", "TelegramIP", "TwitterIP", "GoogleFCMIP",
    "YouTubeIP", "NetflixIP", "GoogleIP",
)
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
NON_ADDRESS_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "USER-AGENT", "PROCESS-NAME", "URL-REGEX",
}
ADDRESS_TYPES = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
INLINE_TYPES = NON_ADDRESS_TYPES | ADDRESS_TYPES | {"GEOIP", "GEOSITE", "SSID", "FINAL", "MATCH", "DEFAULT"}
LOCAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/3", "::/127", "fc00::/7", "fe80::/10", "ff00::/8",
))
HTTPDNS_SOURCES = {
    "Stash-HTTPDNS-Block": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/BlockHttpDNS/BlockHttpDNS.list",
    "Stash-HTTPDNS-Loon-Extra": "https://raw.githubusercontent.com/SchweppesSoda/CustomRules/master/Stash/Rules/HTTPDNS.Loon-Extra.list",
}
INI_RULE_PATTERN = re.compile(
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
    source: str = ""
    behavior: str = ""
    content_kind: str = ""
    content_value: str = ""
    artifact: str = ""
    artifact_line: int = 0
    format: str = ""


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


@dataclass(frozen=True)
class ArtifactRule:
    kind: str
    value: str
    line: int

    @property
    def canonical(self) -> str:
        return f"{self.kind},{self.value}"


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
    group_keys = {"policy_groups:"} if client == "Egern" else {"proxy-groups:", "proxies:"}
    for index, line in enumerate(lines, start=1):
        if line in group_keys:
            in_groups = True
            continue
        if in_groups and line and not line.startswith((" ", "#")):
            in_groups = False
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
        if re.search(r"^\s+disabled:\s*true\s*(?:#.*)?$", text, flags=re.MULTILINE | re.I):
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
        # An active entry that cannot be parsed is evidence of incomplete
        # coverage, not an absent rule. Keep it for the content gate.
        refs.append(
            RuleRef(
                "Egern", rel(path, repo), policy_line, policy_value, match_value,
                kind_match.group(1).upper() if kind_match else "UNKNOWN", text.strip(),
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
        parts = split_rule_fields(strip_quotes(stripped[2:]))
        # Retain unknown active types so content verification can fail closed.
        if len(parts) >= 3:
            refs.append(
                RuleRef(
                    client,
                    rel(path, repo),
                    index,
                    parts[2],
                    ",".join(parts[1:-1]) if parts[0] in {"AND", "OR", "NOT"} else parts[1],
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
        else:
            refs.append(RuleRef(client, rel(path, repo), index, "",
                parts[1] if len(parts) > 1 else "", parts[0] if parts else "UNKNOWN", stripped))
    return refs


def parse_conf_rule(
    repo: Path, client: str, path: Path, index: int, line: str
) -> RuleRef | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or not INI_RULE_PATTERN.match(stripped):
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


def split_rule_fields(value: str) -> list[str]:
    if not value.startswith(("AND,", "OR,", "NOT,")):
        return [part.strip() for part in value.split(",")]
    parts: list[str] = []
    start = depth = 0
    for index, char in enumerate(value):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    parts.append(value[start:].strip())
    return parts


def rule_kind(item: RuleRef) -> str:
    return (item.content_kind or item.kind).upper().replace("_", "-")


def source_name(item: RuleRef) -> str:
    value = unquote(item.source or item.rule)
    if value.startswith(("http://", "https://")):
        value = urlsplit(value).path
    for client in ("/Surge/", "/Mihomo/"):
        if client.casefold() in value.casefold():
            value = value[value.casefold().index(client.casefold()) + len(client):]
            break
    return re.sub(r"\.(?:list|yaml|yml|mrs)$", "", value, flags=re.I)


def rule_blob(item: RuleRef) -> tuple[str, str]:
    # URL hosts, comments and member values do not identify the owning service.
    rule = source_name(item)
    readable = f"{rule} {item.policy}".casefold()
    return readable, flat_text(readable)


def logical_service(item: RuleRef) -> str:
    _, flat = rule_blob(item)
    if is_ip_rule(item):
        return classify_address(item)[1]
    if item.policy == "AI Suite" or any(token in flat for token in ("appleintelligence", "opena", "claude", "anthropic", "copilot", "gemini", "aiglobal")):
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
    if item.content_kind:
        return rule_kind(item) in ADDRESS_TYPES | {"GEOIP"}
    if rule_kind(item) in ADDRESS_TYPES | {"GEOIP"} or item.behavior == "ipcidr":
        return True
    name = source_name(item).casefold()
    if name.startswith(("ip/", "address/")):
        return True
    return any(
        token in flat
        for token in (
            "applepuship",
            "claudeip",
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


def is_local_network(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value.split(",", 1)[0], strict=False)
    except ValueError:
        return False
    return any(network.version == allowed.version and network.subnet_of(allowed) for allowed in LOCAL_NETWORKS)


def is_local_composite(item: RuleRef) -> bool:
    """Accept supported AND leaves only when every destination is local."""
    if rule_kind(item) != "AND" or not item.rule.startswith("((") or not item.rule.endswith("))"):
        return False
    leaves = split_rule_fields("AND," + item.rule[1:-1])[1:]
    local_target = False
    for leaf in leaves:
        if not leaf.startswith("(") or not leaf.endswith(")") or "(" in leaf[1:-1] or ")" in leaf[1:-1]:
            return False
        parts = leaf[1:-1].split(",")
        kind = parts[0]
        if kind == "NETWORK":
            if len(parts) != 2 or parts[1] not in {"TCP", "UDP"}:
                return False
        elif kind in {"DST-PORT", "SRC-PORT"}:
            if len(parts) != 2 or not parts[1].isdecimal() or not 1 <= int(parts[1]) <= 65535:
                return False
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            value = ",".join(parts[1:])
            try:
                validate_artifact_rule(kind, value)
            except ValueError:
                return False
            if not is_local_network(value):
                return False
            local_target = True
        else:
            return False
    return local_target


def is_company_rule(item: RuleRef) -> bool:
    if item.content_kind:
        return False
    kind = rule_kind(item)
    if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return item.rule == "zmmc.com.cn" or item.rule.endswith(".zmmc.com.cn")
    if kind == "IP-CIDR":
        return normalized_rel(item.file) == "Mihomo/SafeMihomo.yaml" and item.policy == "DIRECT" and item.rule == "9.0.0.0/8"
    return is_local_composite(item)


def is_private_source(item: RuleRef) -> bool:
    name = source_name(item).casefold()
    return item.policy == "DIRECT" and name in {
        "private", "privateip", "meta-private", "meta-private-ip",
        "classical/private", "ip/private",
    }


def is_special_source(item: RuleRef) -> bool:
    return item.policy == "DIRECT" and source_name(item).casefold() == "classical/special"


def is_httpdns_exception(item: RuleRef) -> bool:
    return item.client == "Stash" and item.policy == "HTTPDNS" and HTTPDNS_SOURCES.get(item.rule) == item.source


def classify_address(item: RuleRef) -> tuple[int, str]:
    identity = source_name(item).casefold()
    flat = flat_text(identity)
    name = identity.split("/")[-1]
    if (rule_kind(item) == "GEOIP" and item.rule.casefold() == "cn") or name in {"china", "chinaasn", "asn.china"} or any(
        token in flat for token in ("chinaip", "cnip", "domesticips", "geoipcn", "chinaasn", "asnchina")
    ):
        return 160, "ChinaIP"
    if name in {"proxy", "proxyip", "custom-proxy-ip"} or "proxyip" in flat:
        return 157, "ProxyIP"
    for token, label in (
        ("claude", "ClaudeIP"), ("applepush", "ApplePushIP"),
        ("telegram", "TelegramIP"), ("twitter", "TwitterIP"),
        ("googlefcm", "GoogleFCMIP"), ("youtube", "YouTubeIP"),
        ("netflix", "NetflixIP"), ("google", "GoogleIP"),
    ):
        if token in flat:
            return 150, label
    return 150, "ServiceAddress"


def classify_rule(item: RuleRef) -> tuple[int, str] | None:
    readable, flat = rule_blob(item)
    policy_flat = flat_text(item.policy)

    if rule_kind(item) in {"FINAL", "DEFAULT", "MATCH"}:
        return 170, "Final"
    if (
        rule_kind(item) == "SSID"
        or is_private_source(item)
        or is_company_rule(item)
        or (not item.content_kind and item.policy == "DIRECT" and rule_kind(item) in {"IP-CIDR", "IP-CIDR6"} and is_local_network(item.rule))
    ):
        return 10, "HardLocal"
    if is_special_source(item):
        return 32, "SpecialDirect"
    if is_httpdns_exception(item):
        return 31, "HTTPDNS"
    # Address ownership takes precedence over the target policy and service name.
    if is_ip_rule(item):
        return classify_address(item)
    if "mydirect" in flat:
        return 20, "MyDirect"
    if "myproxy" in flat and "twitter" not in flat:
        return 21, "MyProxy"
    if policy_flat == "adblock" or "advertising" in flat:
        return 30, "AdBlock"
    if "httpdns" in flat:
        return 31, "HTTPDNS"
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
    if "googleglobal" in flat or source_name(item).casefold().endswith("classical/google"):
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
        for token in ("proxyglobal", "geolocationnotcn", "globallist", "proxydomain", "classicalproxy")
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
        for token in ("geolocationcn", "metacn", "domesticlist", "chinalist", "classicalchina")
    ):
        return 140, "BroadCN"
    if item.policy == "Domestic" and source_name(item).casefold() == "china":
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
        address_previous: tuple[int, str, RuleRef] | None = None
        public_address: RuleRef | None = None
        final_seen: RuleRef | None = None
        reported: set[tuple[int, str, str]] = set()
        for item in grouped.get(file, []):
            classified = classify_rule(item)
            if final_seen is not None:
                violations.append(OrderViolation(client, file, item.line, ["Final"],
                    [classified[1] if classified else "ActiveRule"],
                    f"active rule follows final catch-all at line {final_seen.line}"))
            if classified and classified[1] == "Final":
                final_seen = item
            if classified and 150 <= classified[0] <= 160:
                public_address = item
            if classified is None:
                known_non_address = rule_kind(item) in NON_ADDRESS_TYPES | {"GEOSITE"} or item.behavior == "domain" or source_name(item).casefold().startswith("nonip/")
                if public_address is not None and known_non_address:
                    violations.append(OrderViolation(client, file, item.line,
                        ["NonAddress", "ServiceAddress"], ["ServiceAddress", "NonAddress"],
                        f"non-address rule follows address rule at line {public_address.line}"))
                continue
            rank, label = classified
            if previous and rank < previous[0] and (item.line, previous[1], label) not in reported:
                reported.add((item.line, previous[1], label))
                location = f" ({item.artifact}:{item.artifact_line})" if item.artifact else ""
                violations.append(
                    OrderViolation(
                        client,
                        file,
                        item.line,
                        [previous[1], label],
                        [label, previous[1]],
                        f"canonical order inversion after line {previous[2].line}{location}",
                    )
                )
            previous = (rank, label, item)
            if label in SERVICE_ADDRESS_SEQUENCE:
                position = SERVICE_ADDRESS_SEQUENCE.index(label)
                if address_previous and position < address_previous[0] and (item.line, address_previous[1], label) not in reported:
                    reported.add((item.line, address_previous[1], label))
                    violations.append(OrderViolation(client, file, item.line,
                        [address_previous[1], label], [label, address_previous[1]],
                        f"service address subsequence inversion after line {address_previous[2].line}"))
                address_previous = (position, label, item)
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


def audit_final_catchalls(repo: Path, refs: list[RuleRef]) -> list[CheckViolation]:
    grouped = refs_by_file(refs)
    violations: list[CheckViolation] = []
    for file, client in ORDER_FILES.items():
        if not (repo / file).is_file():
            continue
        final = [item for item in grouped.get(file, []) if rule_kind(item) in {"MATCH", "FINAL", "DEFAULT"}]
        if len(final) != 1:
            violations.append(CheckViolation(client, file, final[1].line if len(final) > 1 else 0,
                "Final", "canonical profile must contain exactly one final catch-all"))
    return violations


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
        if is_custom_mrs and "/mihomo/address/" in url:
            violations.append(CheckViolation(item.client, item.file, item.line, item.name, "Address partitions remain classical and may not use MRS"))
        try:
            custom_artifact_path(item.url)
        except ValueError as error:
            violations.append(
                CheckViolation(item.client, item.file, item.line, item.name, str(error))
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
        try:
            custom_artifact_path(ref.rule)
        except ValueError as error:
            violations.append(
                CheckViolation(ref.client, ref.file, ref.line, ref.rule, str(error))
            )
        if rule_kind(ref) in {"MATCH", "FINAL", "DEFAULT"} and ref.policy != "Final":
            violations.append(CheckViolation(ref.client, ref.file, ref.line, ref.rule, "final catch-all must target Final"))
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


def custom_artifact_path(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.hostname != "raw.githubusercontent.com":
        return None
    parts = unquote(parsed.path).strip("/").split("/")
    if len(parts) < 4 or [part.casefold() for part in parts[:2]] != ["schweppessoda", "customrules"]:
        return None
    offset = 5 if parts[2] == "refs" else 3
    if len(parts) <= offset or parts[offset] not in {"Mihomo", "Surge"}:
        return None
    if offset == 5 and parts[3] != "heads":
        raise ValueError("generated CustomRules artifacts require auto-build branch")
    branch = parts[4] if offset == 5 else parts[2]
    if branch != "auto-build":
        raise ValueError("generated CustomRules artifacts require auto-build branch")
    remaining = parts[offset:]
    if any(part in {"", ".", ".."} for part in remaining) or any("\\" in part for part in remaining):
        raise ValueError("unsafe artifact path")
    return "/".join(remaining)


def validate_artifact_rule(kind: str, value: str) -> None:
    if kind not in NON_ADDRESS_TYPES | ADDRESS_TYPES:
        raise ValueError(f"unsupported rule type {kind}")
    if not value:
        raise ValueError(f"empty {kind} value")
    if kind in {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}:
        if any(char.isspace() for char in value) or any(char in value for char in ",/:()"):
            raise ValueError(f"unsupported {kind} syntax")
    if kind in ADDRESS_TYPES:
        if kind == "IP-ASN":
            # The maintained ASN.China LIST keeps descriptive // annotations.
            match = re.fullmatch(r"([0-9]+)(?:,no-resolve)?(?: //.*)?", value)
            if not match or not 0 <= int(match.group(1)) <= 4294967295:
                raise ValueError("invalid IP-ASN")
        else:
            parts = value.split(",")
            if len(parts) > 2 or (len(parts) == 2 and parts[1] != "no-resolve"):
                raise ValueError(f"unsupported {kind} options")
            network = ipaddress.ip_network(parts[0], strict=False)
            if network.version != (6 if kind == "IP-CIDR6" else 4):
                raise ValueError(f"wrong address family for {kind}")


def load_artifact_rules(path: Path, behavior: str = "classical") -> list[ArtifactRule]:
    """Read generated LIST/YAML without ignoring unknown or compound syntax."""
    if behavior not in {"domain", "ipcidr", "classical"}:
        raise ValueError(f"unsupported behavior {behavior}")
    yaml_file = path.suffix.casefold() in {".yaml", ".yml"}
    payload_seen = False
    rules: list[ArtifactRule] = []
    for index, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        token = line.strip()
        if not token or token.startswith("#"):
            continue
        if yaml_file:
            if token in {"payload:", "payload: []"} and not payload_seen:
                payload_seen = True
                continue
            if not payload_seen or not token.startswith("- "):
                raise ValueError(f"line {index}: unsupported YAML payload syntax")
            token = strip_quotes(token[2:].strip())
        if yaml_file and behavior == "domain":
            kind = "DOMAIN-SUFFIX" if token.startswith("+.") else "DOMAIN"
            value = token[2:] if kind == "DOMAIN-SUFFIX" else token
        elif yaml_file and behavior == "ipcidr":
            kind, value = ("IP-CIDR6" if ":" in token else "IP-CIDR"), token
        else:
            kind, separator, value = token.partition(",")
            if not separator:
                raise ValueError(f"line {index}: rule type is missing")
            if behavior == "ipcidr":
                value = value.removesuffix(",no-resolve")
        try:
            validate_artifact_rule(kind, value)
        except ValueError as error:
            raise ValueError(f"line {index}: {error}") from error
        rules.append(ArtifactRule(kind, value, index))
    if yaml_file and not payload_seen:
        raise ValueError("missing YAML payload")
    return rules


def scoped_rule_sources(refs: list[RuleRef], providers: list[ProviderDef]) -> list[RuleRef]:
    by_key = {(item.client, normalized_rel(item.file), item.name): item for item in providers}
    result: list[RuleRef] = []
    for item in refs:
        provider = by_key.get((item.client, normalized_rel(item.file), item.rule)) if item.kind == "RULE-SET" else None
        result.append(replace(item, source=provider.url, behavior=provider.behavior, format=provider.format) if provider else item)
    return result


def audit_artifact_contents(
    refs: list[RuleRef], artifact_root: Path, external_artifacts: Path | None = None,
) -> tuple[list[RuleRef], list[dict[str, object]], list[CheckViolation], list[CheckViolation]]:
    """Expand every active input; retain type runs for order without rule snapshots."""
    incomplete: list[CheckViolation] = []
    violations: list[CheckViolation] = []
    checked: list[dict[str, object]] = []
    expanded: list[RuleRef] = []
    cache: dict[tuple[Path, str], list[ArtifactRule]] = {}
    file_hashes: dict[Path, str] = {}
    manifest: dict[str, object] = {}
    manifest_error = ""
    try:
        manifest = json.loads((artifact_root / "manifest.json").read_text(encoding="utf-8"))
        if manifest.get("schema") != 2 or not isinstance(manifest.get("sets"), dict):
            raise ValueError("manifest must have schema 2 and sets")
    except (OSError, ValueError, AttributeError) as error:
        manifest_error = f"CustomRules manifest unavailable or invalid ({type(error).__name__})"
    external: dict[str, object] = {}
    external_error = "no external snapshot mapping supplied"
    if external_artifacts is not None:
        try:
            document = json.loads(external_artifacts.read_text(encoding="utf-8"))
            if document.get("schema") != 1 or not isinstance(document.get("artifacts"), dict):
                raise ValueError("external mapping must have schema 1 and artifacts")
            external = document["artifacts"]
            external_error = "external URL has no supplied snapshot"
        except (OSError, ValueError, AttributeError) as error:
            external_error = f"external snapshot mapping unavailable or invalid ({type(error).__name__})"

    for item in refs:
        subject = item.rule
        remote = item.source or (item.rule if item.rule.startswith(("https://", "http://")) else "")
        if not item.policy:
            incomplete.append(CheckViolation(item.client, item.file, item.line, subject or item.kind, "active rule has no parsed target policy"))
        if not item.rule and rule_kind(item) not in {"MATCH", "FINAL", "DEFAULT"}:
            incomplete.append(CheckViolation(item.client, item.file, item.line, subject or item.kind, "active rule has no parsed matcher"))
        if item.kind not in {"RULE-SET", "RULE_SET", "REMOTE-RULE"}:
            kind = rule_kind(item)
            if kind not in INLINE_TYPES and not is_company_rule(item):
                incomplete.append(CheckViolation(item.client, item.file, item.line, subject, f"unsupported active inline type {kind}"))
            elif kind in ADDRESS_TYPES:
                try:
                    validate_artifact_rule(kind, item.rule)
                except ValueError as error:
                    incomplete.append(CheckViolation(item.client, item.file, item.line, subject, str(error)))
            expanded.append(item)
            continue
        if not remote:
            incomplete.append(CheckViolation(item.client, item.file, item.line, subject, "rule provider has no resolvable source"))
            continue
        try:
            relative = custom_artifact_path(remote)
            info: dict[str, object]
            if relative is not None:
                subject = item.rule if item.source else relative
                if manifest_error:
                    raise ValueError(manifest_error)
                set_name = relative.split("/", 1)[1].rsplit(".", 1)[0]
                info = manifest["sets"].get(set_name, {})
                if not isinstance(info, dict) or not info:
                    raise ValueError(f"manifest has no set {set_name}")
                path = artifact_root / relative
                if not path.is_file():
                    raise ValueError(f"missing artifact {relative}")
                extension = path.suffix[1:].casefold()
                extension = "yaml" if extension == "yml" else extension
                if extension not in info.get("formats", []):
                    raise ValueError(f"manifest does not declare {extension} for {set_name}")
                behavior = str(info.get("behavior", ""))
                if path.suffix.casefold() == ".mrs":
                    if item.behavior != info.get("mrs_behavior"):
                        violations.append(CheckViolation(item.client, item.file, item.line, subject, "provider behavior differs from manifest MRS behavior"))
                    path = path.with_suffix(".yaml")
                    if not path.is_file() or "yaml" not in info.get("formats", []):
                        raise ValueError(f"missing textual MRS companion for {set_name}")
                artifact = path.relative_to(artifact_root).as_posix()
            else:
                subject = item.rule if item.source else "external rule set"
                if remote not in HTTPDNS_SOURCES.values():
                    raise ValueError("external source is outside the reviewed source inventory")
                info = external.get(remote, {})
                if not isinstance(info, dict) or not info or external_artifacts is None:
                    raise ValueError(external_error)
                base = external_artifacts.parent.resolve()
                path = (base / str(info.get("path", ""))).resolve()
                if not path.is_relative_to(base) or not path.is_file():
                    raise ValueError("external snapshot missing or outside mapping directory")
                expected_hash = info.get("sha256")
                if not isinstance(expected_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_hash):
                    raise ValueError("external snapshot has no valid sha256")
                if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                    violations.append(CheckViolation(item.client, item.file, item.line, subject, "external snapshot sha256 mismatch"))
                behavior = str(info.get("behavior", ""))
                artifact = "external/" + path.relative_to(base).as_posix()
                if info.get("format") not in {"text", "yaml"}:
                    raise ValueError("unsupported external snapshot format")
            if item.source and path.suffix.casefold() != ".mrs":
                # MRS has already switched path to its YAML companion above.
                consuming_mrs = urlsplit(item.source).path.casefold().endswith(".mrs")
                if not consuming_mrs:
                    expected_format = "yaml" if path.suffix.casefold() in {".yaml", ".yml"} else "text"
                    expected_behavior = behavior if expected_format == "yaml" else "classical"
                    if item.behavior != expected_behavior:
                        violations.append(CheckViolation(item.client, item.file, item.line, subject,
                            f"provider behavior must match {expected_format} encoding: {expected_behavior}"))
                    if (item.format or "yaml") != expected_format:
                        violations.append(CheckViolation(item.client, item.file, item.line, subject,
                            f"provider format must match artifact encoding: {expected_format}"))
            key = (path, behavior)
            if key not in cache:
                cache[key] = load_artifact_rules(path, behavior)
            members = cache[key]
            if not members:
                if relative is None:
                    raise ValueError("reviewed HTTPDNS snapshot contains no active rules")
                prefix, separator, original = set_name.partition("/")
                expected_partition = {"source": original, "part": "non_ip" if prefix == "NonIP" else "address", "clients": ["Egern"]}
                if prefix not in {"NonIP", "Address"} or not separator or info.get("partition") != expected_partition or behavior != "classical":
                    raise ValueError("empty artifact is not a manifest-declared NonIP/Address partition")
            if relative is not None:
                if not isinstance(info.get("rule_count"), int) or not isinstance(info.get("rules_sha256"), str):
                    raise ValueError("manifest is missing rule_count or rules_sha256")
                digest = hashlib.sha256("\n".join(member.canonical for member in members).encode()).hexdigest()
                if len(members) != info["rule_count"] or digest != info["rules_sha256"]:
                    violations.append(CheckViolation(item.client, item.file, item.line, subject, f"artifact count or rule hash differs from manifest: {artifact}"))
            types = sorted({member.kind for member in members})
            if path not in file_hashes:
                file_hashes[path] = hashlib.sha256(path.read_bytes()).hexdigest()
            checked.append({"client": item.client, "file": item.file, "line": item.line,
                "subject": subject, "artifact": artifact, "rule_count": len(members), "types": types,
                "text_sha256": file_hashes[path]})
            contract_reasons: set[str] = set()
            parent_class = classify_rule(item)
            previous_address: bool | None = None
            for member in members:
                address = member.kind in ADDRESS_TYPES
                if address != previous_address:
                    expanded.append(replace(item, content_kind=member.kind, content_value=member.value,
                        artifact=artifact, artifact_line=member.line))
                    previous_address = address
                reason = ""
                artifact_lower = artifact.casefold()
                if "/nonip/" in artifact_lower and address:
                    reason = "NonIP artifact contains an address rule"
                elif ("/address/" in artifact_lower or "/ip/" in artifact_lower) and not address:
                    reason = "address artifact contains a non-address rule"
                elif item.behavior == "domain" and member.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
                    reason = "domain provider contains a non-domain rule"
                elif item.behavior == "ipcidr" and member.kind not in {"IP-CIDR", "IP-CIDR6"}:
                    reason = "ipcidr provider contains a non-CIDR rule"
                elif address and is_private_source(item):
                    if member.kind == "IP-ASN" or not is_local_network(member.value):
                        reason = "Private exception contains a public or ASN address rule"
                elif address and is_special_source(item):
                    if normalized_rel(item.file) not in FULL_ORDER_FILES or member.kind != "IP-CIDR" or member.value.split(",")[0] != "100.64.0.0/10":
                        reason = "Special exception is limited to full-profile 100.64.0.0/10"
                elif address and not is_httpdns_exception(item) and (parent_class is None or parent_class[0] < 150):
                    reason = "business address appears in a non-address block; use the address output"
                if reason and reason not in contract_reasons:
                    contract_reasons.add(reason)
                    violations.append(CheckViolation(item.client, item.file, item.line, subject, f"{reason}: {artifact}:{member.line}"))
        except (OSError, ValueError, TypeError, AttributeError) as error:
            incomplete.append(CheckViolation(item.client, item.file, item.line, subject, str(error) if isinstance(error, ValueError) else f"unreadable content ({type(error).__name__})"))
    if manifest_error and not any(manifest_error == item.reason for item in incomplete):
        incomplete.append(CheckViolation("CustomRules", "manifest.json", 0, "manifest", manifest_error))
    return expanded, checked, incomplete, violations


def audit(repo: Path, filters: list[str], artifact_root: Path | None = None, external_artifacts: Path | None = None) -> dict[str, object]:
    repo = repo.resolve()
    filter_set = {item.casefold() for item in filters}
    defs: list[PolicyDef] = []
    refs: list[RuleRef] = []
    providers: list[ProviderDef] = []
    checked: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    skipped = [
        {"client": "Loon", "path": relative, "reason": "retired-profile"}
        for relative in RETIRED_PROFILES
        if (repo / relative).is_file()
    ]
    for client, names in CLIENT_FILES.items():
        root = repo / client
        if root.is_dir():
            for candidate in sorted(root.iterdir()):
                if candidate.is_file() and candidate.suffix.casefold() in {".yaml", ".yml", ".conf"}:
                    relative = candidate.relative_to(repo).as_posix()
                    if relative not in names:
                        skipped.append({"client": client, "path": relative, "reason": "outside-canonical-rule-inventory; verify with owner"})
        for name in names:
            path = repo / name
            if not path.is_file():
                missing.append({"client": client, "path": name, "reason": "required canonical profile absent"})
                continue
            checked.append({"client": client, "path": name, "checks": "rule targets, providers and applicable order"})
            if client == "Egern":
                defs.extend(extract_yaml_policy_defs(repo, client, path))
                refs.extend(extract_egern_rules(repo, path))
            elif client in {"Mihomo", "Stash"}:
                defs.extend(extract_yaml_policy_defs(repo, client, path))
                refs.extend(extract_mihomo_rules(repo, client, path))
                providers.extend(extract_yaml_provider_defs(repo, client, path))
            elif client == "Loon":
                defs.extend(extract_conf_policy_defs(repo, client, path))
                refs.extend(extract_loon_rules(repo, path))

    refs = scoped_rule_sources(refs, providers)
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
    final_violations = audit_final_catchalls(repo, refs)
    content_checked: list[dict[str, object]] = []
    content_incomplete: list[CheckViolation] = []
    content_violations: list[CheckViolation] = []
    expanded_violations: list[OrderViolation] = []
    if artifact_root is not None:
        expanded, content_checked, content_incomplete, content_violations = audit_artifact_contents(refs, artifact_root, external_artifacts)
        expanded_violations = audit_canonical_order(repo, expanded)

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
        "checked": checked,
        "skipped": skipped,
        "missing": missing,
        "validation_scope": {
            "mode": "text-artifact-content" if artifact_root is not None else "references-only",
            "content_status": "incomplete" if content_incomplete else "failed" if content_violations or expanded_violations else "checked" if artifact_root is not None else "not-requested",
            "mrs": "matching YAML + manifest; verify_build must validate compiled MRS separately" if artifact_root is not None else "not-expanded",
        },
        "policy_definitions": [asdict(item) for item in defs],
        "rule_references": [asdict(item) for item in refs],
        "rule_providers": [asdict(item) for item in providers],
        "undefined_rule_policies": [asdict(item) for item in undefined],
        "finance_order_violations": [asdict(item) for item in finance_violations],
        "canonical_order_violations": [asdict(item) for item in order_violations],
        "orphan_rule_providers": [asdict(item) for item in orphan_providers],
        "provider_type_violations": [asdict(item) for item in type_violations],
        "cn_guard_violations": [asdict(item) for item in cn_violations],
        "final_catchall_violations": [asdict(item) for item in final_violations],
        "artifact_content_checked": content_checked,
        "artifact_content_incomplete": [asdict(item) for item in content_incomplete],
        "artifact_content_violations": [asdict(item) for item in content_violations],
        "expanded_order_violations": [asdict(item) for item in expanded_violations],
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
    scope = payload["validation_scope"]
    print(f"Validation scope: {scope['mode']}; content {scope['content_status']}")
    for status in ("checked", "skipped", "missing"):
        print(f"{status}: {len(payload[status])}")
        for item in payload[status]:
            print(f"  {item['path']} ({item.get('reason', item.get('checks', ''))})")
    print()
    print_items(payload, "undefined_rule_policies", "Undefined rule policies")
    print_items(payload, "finance_order_violations", "Finance order violations")
    print_items(payload, "canonical_order_violations", "Canonical order violations")
    print_items(payload, "orphan_rule_providers", "Orphan rule providers")
    print_items(payload, "provider_type_violations", "Provider type violations")
    print_items(payload, "cn_guard_violations", "CN guard violations")
    print_items(payload, "final_catchall_violations", "Final catch-all violations")
    print_items(payload, "artifact_content_incomplete", "Incomplete artifact content checks")
    print_items(payload, "artifact_content_violations", "Artifact content violations")
    print_items(payload, "expanded_order_violations", "Expanded content order violations")
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
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--artifact-root", type=Path, help="Local verified CustomRules output root; enables required text content expansion")
    parser.add_argument("--external-artifacts", type=Path, help="Schema 1 local URL-to-snapshot mapping for external rule sets")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    if not args.repo.exists():
        print(f"error: repo does not exist: {args.repo}", file=sys.stderr)
        return 2
    if args.external_artifacts is not None and args.artifact_root is None:
        print("error: --external-artifacts requires --artifact-root", file=sys.stderr)
        return 2
    payload = audit(args.repo, args.policy, args.artifact_root, args.external_artifacts)
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
        "final_catchall_violations",
        "artifact_content_violations",
        "expanded_order_violations",
    ]
    if payload["missing"] or payload["artifact_content_incomplete"]:
        return 2
    return 1 if any(payload[key] for key in failures) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
