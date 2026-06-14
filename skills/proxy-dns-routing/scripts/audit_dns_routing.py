#!/usr/bin/env python3
"""Audit DNS routing surfaces in ProxyConfig.

The script is dependency-free and read-only. It focuses on AirportServers
references and provider node-domain DNS policies across Egern, Mihomo, and
Surge.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


AIRPORTSERVERS_TOKEN = "AirportServers"
DEFAULT_FILES = (
    "Egern/AutoEgern.yaml",
    "Mihomo/AutoMihomo.yaml",
    "Surge/AutoSurge.conf",
    "Surge/Split Conf/AutoSurge/Host.dconf",
    "Surge/Split Conf/AutoSurge/Main.conf",
)


@dataclass
class Hit:
    file: str
    line: int
    kind: str
    key: str
    value: str
    text: str


def configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig", errors="replace").splitlines()


def norm_domain(value: str) -> str:
    value = value.strip().strip('"').strip("'")
    value = re.sub(r"^(?:\+\.)?\*\.", "", value)
    value = re.sub(r"^\+\.", "", value)
    return value.casefold()


def wanted(domain: str, filters: set[str]) -> bool:
    if not filters:
        return True
    normalized = norm_domain(domain)
    return normalized in filters or any(normalized.endswith("." + item) for item in filters)


def rel(path: Path, repo: Path) -> str:
    return str(path.relative_to(repo))


def find_existing_files(repo: Path) -> list[Path]:
    return [repo / item for item in DEFAULT_FILES if (repo / item).exists()]


def extract_egern_upstreams(path: Path) -> dict[str, list[str]]:
    lines = read_lines(path)
    upstreams: dict[str, list[str]] = {}
    in_upstreams = False
    current: str | None = None
    for line in lines:
        if re.match(r"^\s{2}upstreams:\s*$", line):
            in_upstreams = True
            continue
        if in_upstreams and re.match(r"^\s{2}[A-Za-z_][\w-]*:\s*$", line):
            break
        if not in_upstreams:
            continue
        name = re.match(r"^\s{4}([A-Za-z_][\w-]*):\s*$", line)
        if name:
            current = name.group(1)
            upstreams.setdefault(current, [])
            continue
        server = re.match(r"^\s{6}-\s*(.+?)\s*$", line)
        if current and server:
            upstreams[current].append(server.group(1).strip())
    return upstreams


def extract_egern_forward(path: Path, repo: Path, filters: set[str]) -> list[Hit]:
    lines = read_lines(path)
    upstreams = extract_egern_upstreams(path)
    hits: list[Hit] = []
    for idx, line in enumerate(lines):
        item = re.match(r"^\s{4}-\s+(domain_suffix|proxy_rule_set):\s*$", line)
        if not item:
            continue
        kind = item.group(1)
        block_end = idx + 1
        while block_end < len(lines) and not re.match(r"^\s{4}-\s+", lines[block_end]):
            block_end += 1
        block = lines[idx:block_end]
        match_value = ""
        resolver = ""
        for entry in block:
            match = re.match(r"^\s{8}match:\s*(.+?)\s*$", entry)
            value = re.match(r"^\s{8}value:\s*(.+?)\s*$", entry)
            if match:
                match_value = match.group(1).strip().strip('"')
            if value:
                resolver = value.group(1).strip().strip('"')
        if not match_value:
            continue
        if kind == "domain_suffix" and not wanted(match_value, filters):
            continue
        if kind == "proxy_rule_set" and filters:
            continue
        target = resolver
        if resolver in upstreams:
            target = f"{resolver} -> {', '.join(upstreams[resolver])}"
        hits.append(Hit(rel(path, repo), idx + 1, f"egern-{kind}", match_value, target, line.strip()))
    return hits


def extract_mihomo_policy(path: Path, repo: Path, filters: set[str]) -> list[Hit]:
    lines = read_lines(path)
    hits: list[Hit] = []
    in_policy = False
    for idx, line in enumerate(lines):
        if re.match(r"^\s{2}proxy-server-nameserver-policy:\s*$", line):
            in_policy = True
            continue
        if in_policy and re.match(r"^\s{2}[A-Za-z0-9_-]+:", line):
            break
        if not in_policy:
            continue
        match = re.match(r'^\s{4}["\']?([^"\':]+)["\']?\s*:\s*["\']?(.+?)["\']?\s*$', line)
        if not match:
            continue
        domain, resolver = match.group(1).strip(), match.group(2).strip()
        if wanted(domain, filters):
            hits.append(Hit(rel(path, repo), idx + 1, "mihomo-proxy-server-policy", domain, resolver, line.strip()))
    return hits


def extract_surge_host(path: Path, repo: Path, filters: set[str]) -> list[Hit]:
    lines = read_lines(path)
    hits: list[Hit] = []
    for idx, line in enumerate(lines):
        match = re.match(r"^\s*([^#=\s][^=]*?)\s*=\s*server:(.+?)\s*$", line)
        if not match:
            continue
        domain, resolver = match.group(1).strip(), match.group(2).strip()
        if wanted(domain, filters):
            hits.append(Hit(rel(path, repo), idx + 1, "surge-host", domain, resolver, line.strip()))
    return hits


def find_airportservers(repo: Path, files: list[Path]) -> list[Hit]:
    hits: list[Hit] = []
    local = repo / "Surge" / "AirportServers.list"
    if local.exists():
        hits.append(Hit(rel(local, repo), 1, "local-airportservers-list", "exists", str(local), "local file exists"))
    for path in files:
        for idx, line in enumerate(read_lines(path), start=1):
            if AIRPORTSERVERS_TOKEN in line:
                hits.append(Hit(rel(path, repo), idx, "airportservers-reference", AIRPORTSERVERS_TOKEN, line.strip(), line.strip()))
    return hits


def audit(repo: Path, domains: list[str], include_airportservers: bool) -> dict[str, object]:
    repo = repo.resolve()
    filters = {norm_domain(item) for item in domains}
    files = find_existing_files(repo)
    hits: list[Hit] = []
    for path in files:
        if "Egern" in path.parts:
            hits.extend(extract_egern_forward(path, repo, filters))
        elif "Mihomo" in path.parts:
            hits.extend(extract_mihomo_policy(path, repo, filters))
        elif path.name == "Host.dconf" or path.name == "AutoSurge.conf":
            hits.extend(extract_surge_host(path, repo, filters))
    airport_hits = find_airportservers(repo, files) if include_airportservers else []
    return {
        "repo": str(repo),
        "domains": domains,
        "files": [rel(path, repo) for path in files],
        "dns_hits": [asdict(item) for item in hits],
        "airportservers": [asdict(item) for item in airport_hits],
    }


def print_report(payload: dict[str, object]) -> None:
    print(f"Repo: {payload['repo']}")
    print("Scanned files:")
    for item in payload["files"]:
        print(f"  - {item}")
    print()
    print("DNS routing entries:")
    hits = payload["dns_hits"]
    if not hits:
        print("  (none)")
    for item in hits:
        print(f"  {item['file']}:{item['line']} [{item['kind']}] {item['key']} -> {item['value']}")
    if payload["airportservers"]:
        print()
        print("AirportServers:")
        for item in payload["airportservers"]:
            print(f"  {item['file']}:{item['line']} [{item['kind']}] {item['value']}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit ProxyConfig DNS routing entries.")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--domain", action="append", default=[], help="Domain or wildcard domain to filter; repeatable")
    parser.add_argument("--airportservers", action="store_true", help="Include AirportServers list/reference audit")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    if not args.repo.exists():
        print(f"error: repo does not exist: {args.repo}", file=sys.stderr)
        return 2
    payload = audit(args.repo, args.domain, args.airportservers)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_report(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
