#!/usr/bin/env python3
"""Dependency-free, read-only DNS audit for the four ProxyConfig client families.

Profiles are discovered dynamically.  Derived Mihomo WAN2
files remain visible in generated/skipped ranges but are not treated as a
second source of truth when their canonical source is present.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

AIRPORTSERVERS_TOKEN = "AirportServers"
WRITER_CONTRACT_RELATIVE = Path("Sub-Store/config/generated-writers.json")
CONFIG_SUFFIXES = {".yaml", ".yml", ".conf", ".dconf"}
EXCLUDED_DIRS = {".git", ".github", ".codex", ".agents", ".vscode"}


@dataclass
class Hit:
    # Keep the original constructor shape; metadata is optional.
    file: str
    line: int
    kind: str
    key: str
    value: str
    text: str
    client: str = ""
    scope: str = ""
    generated: bool = False


@dataclass
class Profile:
    client: str
    path: Path
    role: str
    scope: str
    generated_from: str | None
    markers: list[dict[str, Any]]


@dataclass
class ContractIssue:
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
    return path.relative_to(repo).as_posix()


def norm_domain(value: str) -> str:
    value = str(value).strip().strip('"').strip("'")
    value = re.sub(r"^(?:\+\.)?\*\.", "", value)
    value = re.sub(r"^\+\.", "", value)
    return value.rstrip(".").casefold()


def wanted(domain: str, filters: set[str]) -> bool:
    if not filters:
        return True
    value = norm_domain(domain)
    return bool(value) and (value in filters or any(value.endswith("." + item) for item in filters if item))


# Redaction is applied both at collection time and once more to the whole
# payload.  It intentionally removes the full URL, not merely its query.
URL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>\[\](){}\\`,;]+"
)
SECRET_RE = re.compile(
    r"""(?ix)
    (["']?\b(?:authorization|proxy[-_ ]?authorization|password|passwd|
    passphrase|client[-_ ]?(?:secret|password)|secret|credential|
    private[-_ ]?key|x[-_ ]?api[-_ ]?key|api[-_ ]?(?:key|secret|token)|
    access[-_ ]?key|
    access[-_ ]?token|refresh[-_ ]?token|auth[-_ ]?token|
    capability[-_ ]?token|bearer|token)\b["']?\s*[:=]\s*)
    (?:"[^"]*"|'[^']*'|[^\r\n,;}\]]+)
    """
)
BLOB_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{48,}(?![A-Za-z0-9])")
UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")
SENSITIVE_KEY_RE = re.compile(
    r"(?ix)^(?:authorization|proxy[-_ ]?authorization|password|passwd|"
    r"passphrase|client[-_ ]?(?:secret|password)|secret|credential|"
    r"private[-_ ]?key|x[-_ ]?api[-_ ]?key|api[-_ ]?(?:key|secret|token)|"
    r"access[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|auth[-_ ]?token|"
    r"capability[-_ ]?token|bearer|token)$"
)


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            visible_key = str(redact(key))
            key_name = str(key).strip().strip('"').strip("'")
            result[visible_key] = "<redacted>" if SENSITIVE_KEY_RE.fullmatch(key_name) else redact(item)
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if not isinstance(value, str):
        return value
    value = URL_RE.sub("<redacted-url>", value)
    value = SECRET_RE.sub(r"\1<redacted>", value)
    value = UUID_RE.sub("<redacted-uuid>", value)
    return BLOB_RE.sub("<redacted>", value)


def _safe_line(line: str) -> str:
    return str(redact(line.strip()))


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _comment(line: str) -> bool:
    return not line.strip() or line.lstrip().startswith(("#", ";"))


def marker_ranges(lines: Sequence[str]) -> list[dict[str, Any]]:
    starts: dict[str, list[int]] = {}
    ends: dict[str, list[int]] = {}
    for number, line in enumerate(lines, 1):
        for kind, store in (("BEGIN", starts), ("END", ends)):
            match = re.search(rf"\b{kind}\s+AUTO(?:-GENERATED)?\s+(.+?)\s*$", line, re.I)
            if match:
                label = re.sub(r"\s+", " ", match.group(1).strip()).casefold()
                store.setdefault(label, []).append(number)
    result: list[dict[str, Any]] = []
    for label in sorted(set(starts) | set(ends)):
        begin, end = starts.get(label, []), ends.get(label, [])
        if len(begin) == 1 and len(end) == 1:
            result.append({"label": label, "begin_line": begin[0], "end_line": end[0], "status": "paired", "begin_count": 1, "end_count": 1})
        else:
            result.append({"label": label, "begin_line": begin[0] if begin else None, "end_line": end[0] if end else None, "status": "partial-or-duplicate", "begin_count": len(begin), "end_count": len(end)})
    return result


def _candidate_files(repo: Path, directory: str, recursive: bool) -> list[Path]:
    root = repo / directory
    if not root.is_dir():
        return []
    paths = root.rglob("*") if recursive else root.iterdir()
    result: list[Path] = []
    for path in paths:
        if not path.is_file() or path.suffix.casefold() not in CONFIG_SUFFIXES:
            continue
        parts = path.relative_to(repo).parts
        if any(part in EXCLUDED_DIRS or part.casefold() in {"tests", "test", "docs", "overrides"} for part in parts[:-1]):
            continue
        result.append(path)
    return sorted(result, key=lambda item: rel(item, repo).casefold())


def classify_profile(repo: Path, path: Path, client: str) -> Profile:
    relative = rel(path, repo).casefold()
    markers = marker_ranges(read_lines(path))
    if client == "Mihomo" and "wan2" in path.name.casefold():
        return Profile(client, path, "generated", "whole-file", "Mihomo/AutoMihomo.OpenWrt.yaml", markers)
    if markers:
        return Profile(client, path, "mixed-marker", "mixed-marker", None, markers)
    return Profile(client, path, "canonical", "manual/canonical", None, markers)


def discover_profiles(repo: Path) -> list[Profile]:
    roots = (("Egern", "Egern", True), ("Mihomo", "Mihomo", True), ("Loon", "Loon", True), ("Stash", "Stash", True))
    profiles = [classify_profile(repo, path, client) for client, directory, recursive in roots for path in _candidate_files(repo, directory, recursive)]
    return sorted(profiles, key=lambda item: rel(item.path, repo).casefold())


def find_existing_files(repo: Path) -> list[Path]:
    """Compatibility view of the dynamic discovery plan."""
    return [profile.path for profile in discover_profiles(repo)]


def profile_dict(profile: Profile, repo: Path) -> dict[str, Any]:
    return {"client": profile.client, "path": rel(profile.path, repo), "role": profile.role, "scope": profile.scope, "generated_from": profile.generated_from, "markers": profile.markers}


def _block_end(lines: Sequence[str], start: int, parent_indent: int) -> int:
    index = start + 1
    while index < len(lines):
        if not _comment(lines[index]) and _indent(lines[index]) <= parent_indent:
            break
        index += 1
    return index


def _yaml_mapping_entries(path: Path, sections: set[str]) -> list[tuple[str, int, str, str]]:
    lines = read_lines(path)
    result: list[tuple[str, int, str, str]] = []
    index = 0
    while index < len(lines):
        header = re.match(r"^(\s*)([A-Za-z0-9_-]+):\s*$", lines[index])
        if not header or header.group(2) not in sections:
            index += 1
            continue
        parent = len(header.group(1))
        end = _block_end(lines, index, parent)
        for number in range(index + 1, end):
            line = lines[number]
            if _comment(line) or _indent(line) <= parent:
                continue
            match = re.match(r"^\s+(?:[\"']([^\"']+)[\"']|([^:#][^:]*?))\s*:\s*(.*?)\s*$", line)
            if match:
                key = (match.group(1) or match.group(2) or "").strip()
                if key:
                    result.append((key, number + 1, match.group(3).strip(), line))
        index = end
    return result


def extract_egern_upstreams(path: Path) -> dict[str, list[str]]:
    lines = read_lines(path)
    result: dict[str, list[str]] = {}
    active = False
    current: str | None = None
    for line in lines:
        if re.match(r"^\s{2}upstreams:\s*$", line):
            active = True
            continue
        if active and re.match(r"^\s{2}[A-Za-z_][\w-]*:\s*$", line):
            break
        if not active:
            continue
        name = re.match(r"^\s{4}([A-Za-z_][\w-]*):\s*$", line)
        if name:
            current = name.group(1)
            result.setdefault(current, [])
        else:
            server = re.match(r"^\s{6}-\s*(.+?)\s*$", line)
            if current and server:
                result[current].append(server.group(1).strip())
    return result


def extract_egern_forward(path: Path, repo: Path, filters: set[str]) -> list[Hit]:
    lines, upstreams, result = read_lines(path), extract_egern_upstreams(path), []
    active, index = False, 0
    while index < len(lines):
        line = lines[index]
        if re.match(r"^\s{2}forward:\s*$", line):
            active = True
            index += 1
            continue
        if active and not _comment(line) and _indent(line) <= 2:
            break
        if not active:
            index += 1
            continue
        item = re.match(r"^(\s{4})-\s+([A-Za-z_][\w-]*):\s*$", line)
        if not item:
            index += 1
            continue
        end, kind, matched, resolver = _block_end(lines, index, 4), item.group(2), "", ""
        for entry in lines[index:end]:
            m = re.match(r"^\s{8}match:\s*(.+?)\s*$", entry)
            v = re.match(r"^\s{8}value:\s*(.+?)\s*$", entry)
            if m:
                matched = m.group(1).strip().strip('"').strip("'")
            if v:
                resolver = v.group(1).strip().strip('"').strip("'")
        if matched and (not filters or kind in {"domain", "domain_suffix", "domain_wildcard"} and wanted(matched, filters)):
            target = f"{resolver} -> {', '.join(upstreams[resolver])}" if resolver in upstreams else resolver
            result.append(Hit(rel(path, repo), index + 1, f"egern-{kind}", matched, target, _safe_line(line), "Egern"))
        index = end
    return result


def _policy_hits(path: Path, repo: Path, filters: set[str], client: str) -> list[Hit]:
    result: list[Hit] = []
    for section in ("proxy-server-nameserver-policy", "nameserver-policy"):
        for key, line, value, text in _yaml_mapping_entries(path, {section}):
            if wanted(key, filters):
                result.append(Hit(rel(path, repo), line, f"{client.casefold()}-{section}", key, value, _safe_line(text), client))
    return result


def extract_mihomo_policy(path: Path, repo: Path, filters: set[str]) -> list[Hit]:
    return _policy_hits(path, repo, filters, "Mihomo")


def extract_stash_policy(path: Path, repo: Path, filters: set[str]) -> list[Hit]:
    return _policy_hits(path, repo, filters, "Stash")


def extract_yaml_hosts(path: Path, repo: Path, filters: set[str], client: str) -> list[Hit]:
    return [Hit(rel(path, repo), line, f"{client.casefold()}-hosts", key, value, _safe_line(text), client) for key, line, value, text in _yaml_mapping_entries(path, {"hosts", "proxy-hosts"}) if wanted(key, filters)]


def _ini_host(path: Path, repo: Path, filters: set[str], client: str) -> list[Hit]:
    lines, result, active = read_lines(path), [], False
    for index, line in enumerate(lines, 1):
        if re.match(r"^\s*\[Host\]\s*$", line, re.I):
            active = True
            continue
        if active and re.match(r"^\s*\[[^]]+\]\s*$", line):
            break
        if not active or not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        match = re.match(r"^\s*([^#=\s][^=]*?)\s*=\s*(?:server:)?(.+?)\s*$", line)
        if match:
            key, value = match.group(1).strip(), match.group(2).strip()
            if wanted(key, filters):
                result.append(Hit(rel(path, repo), index, f"{client.casefold()}-host", key, value, _safe_line(line), client))
    return result


def extract_loon_host(path: Path, repo: Path, filters: set[str]) -> list[Hit]:
    return _ini_host(path, repo, filters, "Loon")


def extract_ini_dns_settings(path: Path, repo: Path, client: str, filters: set[str] | None = None) -> list[Hit]:
    result: list[Hit] = []
    for index, line in enumerate(read_lines(path), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        match = re.match(r"(?i)^(dns-server|doh-server|encrypted-dns-server)\s*=\s*(.*)$", stripped)
        if match and not filters:
            result.append(Hit(rel(path, repo), index, f"{client.casefold()}-dns-setting", match.group(1), match.group(2), _safe_line(line), client))
            continue
        if re.match(r"(?i)^SSID:[^ ]+\s+dns-server=", stripped) and not filters:
            result.append(Hit(rel(path, repo), index, f"{client.casefold()}-ssid-dns", "SSID", stripped, _safe_line(line), client))
    return result


def find_airportservers(repo: Path, profiles: Iterable[Profile]) -> list[Hit]:
    result, seen = [], set()
    paths: list[Path] = []
    for item in profiles:
        # The first script version accepted a list of Paths; retain that
        # calling convention while the audit itself passes Profile objects.
        path = item.path if isinstance(item, Profile) else Path(item)
        if path not in paths:
            paths.append(path)
    explicit = set()
    for candidate in (repo / "Surge/AirportServers.list", repo / "Sub-Store/config/airport-domain-sources.json"):
        if candidate.exists():
            explicit.add(candidate)
            if candidate not in paths:
                paths.append(candidate)
    for path in paths:
        try:
            lines = read_lines(path)
        except (OSError, UnicodeError):
            continue
        found = False
        for index, line in enumerate(lines, 1):
            if AIRPORTSERVERS_TOKEN.casefold() not in line.casefold():
                continue
            found = True
            key = (rel(path, repo), index)
            if key in seen:
                continue
            seen.add(key)
            kind = "local-airportservers-list" if path.name.casefold() == "airportservers.list" else "airportservers-reference"
            result.append(Hit(key[0], index, kind, AIRPORTSERVERS_TOKEN, _safe_line(line), _safe_line(line)))
        if path in explicit and path.name.casefold() == "airportservers.list" and not found:
            # Preserve the old, useful signal that the local inventory exists
            # even when its contents do not repeat the token in its filename.
            key = (rel(path, repo), 0)
            if key not in seen:
                seen.add(key)
                result.append(Hit(key[0], 0, "local-airportservers-list", "exists", "present", "local file exists"))
    return result


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _writer_list(document: Any) -> list[tuple[str, Mapping[str, Any]]]:
    if not isinstance(document, Mapping):
        raise ValueError("writer contract root must be an object")
    raw = next((document[key] for key in ("writers", "generated_writers", "generated-writers", "writer") if key in document), None)
    if raw is None:
        return []
    result: list[tuple[str, Mapping[str, Any]]] = []
    if isinstance(raw, Mapping):
        for key, value in raw.items():
            if isinstance(value, Mapping):
                result.append((str(value.get("id") or value.get("name") or key), value))
    elif isinstance(raw, list):
        for index, value in enumerate(raw):
            if isinstance(value, Mapping):
                result.append((str(value.get("id") or value.get("name") or f"writer-{index + 1}"), value))
    else:
        raise ValueError("writers must be an object or array")
    return result


def _target_list(writer: Mapping[str, Any]) -> list[Mapping[str, Any] | str]:
    raw = next((writer[key] for key in ("targets", "target", "outputs", "files", "paths") if key in writer), None)
    if raw is None:
        return []
    if isinstance(raw, (str, Mapping)):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, (str, Mapping))]
    raise ValueError("writer targets must be an object, string, or array")


def _target_path(target: Mapping[str, Any] | str) -> str:
    if isinstance(target, str):
        return target
    return _text(next((target[key] for key in ("path", "file", "target", "output", "target_path", "targetPath", "output_path", "outputPath") if key in target), ""))


def _scope(target: Mapping[str, Any] | str) -> str:
    if isinstance(target, str):
        return "whole-file"
    raw = str(target.get("scope") or target.get("kind") or target.get("type") or "whole-file").casefold().replace("_", "-")
    if raw in {"whole", "whole-file", "file", "generated-file"}:
        return "whole-file"
    if raw in {"marker", "marker-pair", "markers", "block"}:
        return "marker-pair"
    if raw in {"field", "field-selector", "selector", "key"}:
        return "field-selector"
    return raw


def _marker_pair(target: Mapping[str, Any] | str) -> tuple[str, str] | None:
    if isinstance(target, str):
        return None
    begin = next((target[key] for key in ("begin_marker", "beginMarker", "begin", "start_marker", "startMarker") if target.get(key)), None)
    end = next((target[key] for key in ("end_marker", "endMarker", "end", "finish_marker", "finishMarker") if target.get(key)), None)
    marker = next((target[key] for key in ("marker", "markers", "selector", "marker_selector", "markerSelector") if target.get(key)), None)
    if isinstance(marker, Mapping):
        begin = begin or next((marker[key] for key in ("begin", "beginMarker", "start", "startMarker") if marker.get(key)), None)
        end = end or next((marker[key] for key in ("end", "endMarker", "finish", "finishMarker") if marker.get(key)), None)
    elif isinstance(marker, (list, tuple)) and len(marker) >= 2:
        begin, end = begin or marker[0], end or marker[1]
    elif isinstance(marker, str) and not begin:
        label = marker.strip()
        if label.casefold().startswith("auto-generated "):
            begin, end = f"BEGIN {label}", f"END {label}"
        else:
            begin, end = f"BEGIN AUTO-GENERATED {label}", f"END AUTO-GENERATED {label}"
    return (str(begin), str(end)) if begin and end else None


def _concurrency(writer: Mapping[str, Any]) -> str:
    for key in ("concurrency_group", "concurrencyGroup", "concurrency-group", "concurrency", "lock", "lock_group", "lockGroup", "group"):
        value = writer.get(key)
        if isinstance(value, Mapping):
            value = value.get("group") or value.get("name") or value.get("key")
        if value:
            return str(value)
    return ""


def load_writer_contract(repo: Path) -> dict[str, Any]:
    path = repo / WRITER_CONTRACT_RELATIVE
    if not path.exists():
        return {"status": "absent", "path": WRITER_CONTRACT_RELATIVE.as_posix(), "writers": [], "errors": ["generated-writers contract absent"]}
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
        writers = _writer_list(document)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return {"status": "invalid", "path": WRITER_CONTRACT_RELATIVE.as_posix(), "writers": [], "errors": [f"invalid generated-writers contract: {exc}"]}
    return {"status": "valid", "path": WRITER_CONTRACT_RELATIVE.as_posix(), "writers": [{"id": identifier, "target_count": len(_target_list(writer))} for identifier, writer in writers], "errors": [] if writers else ["generated-writers contract contains no writers"], "document": document}


def _matching_profiles(pattern: str, profiles: Sequence[Profile], repo: Path) -> list[Profile]:
    pattern = pattern.replace("\\", "/")
    while pattern.startswith("./"):
        pattern = pattern[2:]
    return [profile for profile in profiles if fnmatch.fnmatch(rel(profile.path, repo), pattern)]


def audit_writer_contract(repo: Path, profiles: Sequence[Profile], contract: Mapping[str, Any]) -> tuple[list[ContractIssue], list[dict[str, Any]], list[str]]:
    """Validate marker ownership, scope overlap, and shared-file locks."""
    issues: list[ContractIssue] = []
    ownership: list[dict[str, Any]] = []
    environment_errors = list(contract.get("errors", []))
    if contract.get("status") != "valid":
        return issues, ownership, environment_errors
    try:
        writers = _writer_list(contract.get("document", {}))
    except ValueError as exc:
        return issues, ownership, [str(exc)]
    for writer_id, writer in writers:
        try:
            targets = _target_list(writer)
        except ValueError as exc:
            environment_errors.append(f"writer {writer_id}: {exc}")
            continue
        concurrency = _concurrency(writer)
        if not targets:
            environment_errors.append(f"writer {writer_id}: no targets")
        for target_index, target in enumerate(targets, 1):
            repository = str(target.get("repository") or target.get("repo") or "").strip() if isinstance(target, Mapping) else ""
            repository_name = repository.replace("\\", "/").rstrip("/").split("/")[-1].casefold().replace("_", "-")
            if repository and repository_name not in {"proxyconfig", "proxy-config"}:
                # A single contract can describe CustomRules outputs too;
                # this auditor owns only the local ProxyConfig worktree.
                continue
            pattern = _target_path(target).replace("\\", "/").lstrip("./")
            if not pattern:
                environment_errors.append(f"writer {writer_id} target {target_index}: missing path")
                continue
            matches = _matching_profiles(pattern, profiles, repo)
            if not matches:
                if not re.match(r"^(?:https?|git|ssh)://", pattern, re.I) and not pattern.startswith("../"):
                    environment_errors.append(f"writer {writer_id} target missing: {pattern}")
                continue
            scope = _scope(target)
            marker = _marker_pair(target)
            selector = _text(next((target[key] for key in ("field", "field_selector", "fieldSelector", "selector", "key_selector", "keySelector") if target.get(key)), "")) if isinstance(target, Mapping) else ""
            for profile in matches:
                path = rel(profile.path, repo)
                entry = {"writer": writer_id, "path": path, "scope": scope, "concurrency_group": concurrency or None, "begin_marker": marker[0] if marker else None, "end_marker": marker[1] if marker else None, "field_selector": selector or None}
                ownership.append(entry)
                if scope == "marker-pair":
                    if not marker:
                        issues.append(ContractIssue("error", "marker-contract-invalid", f"{writer_id}:{path}", "marker-pair target has no begin/end marker"))
                        continue
                    text = profile.path.read_text(encoding="utf-8-sig", errors="replace")
                    begin_count, end_count = text.count(marker[0]), text.count(marker[1])
                    if begin_count == 0 or end_count == 0 or begin_count != end_count:
                        issues.append(ContractIssue("error", "marker-missing", f"{writer_id}:{path}", f"marker pair counts begin={begin_count}, end={end_count}"))
                    elif begin_count > 1 or end_count > 1:
                        issues.append(ContractIssue("error", "marker-duplicate", f"{writer_id}:{path}", f"marker pair counts begin={begin_count}, end={end_count}"))
                elif scope not in {"whole-file", "field-selector"}:
                    issues.append(ContractIssue("error", "scope-invalid", f"{writer_id}:{path}", f"unsupported scope {scope}"))
    by_path: dict[str, list[dict[str, Any]]] = {}
    for entry in ownership:
        by_path.setdefault(entry["path"], []).append(entry)
    for path, entries in sorted(by_path.items()):
        groups = {entry["concurrency_group"] for entry in entries}
        if len(entries) > 1 and (len(groups) != 1 or None in groups):
            issues.append(ContractIssue("error", "concurrency-mismatch", path, f"shared physical file has groups {sorted(str(item) for item in groups)}"))
        lines = read_lines(repo / path)
        spans: list[tuple[int, int, dict[str, Any]]] = []
        for entry in entries:
            if entry["scope"] == "whole-file":
                spans.append((1, 10**9, entry))
            elif entry["scope"] == "field-selector":
                selector = entry.get("field_selector")
                if selector and any(previous.get("scope") == "field-selector" and previous.get("field_selector") == selector for previous in entries[:entries.index(entry)]):
                    issues.append(ContractIssue("error", "scope-overlap", path, f"field selector {selector} is owned more than once"))
            else:
                begin, end = entry.get("begin_marker"), entry.get("end_marker")
                if not begin or not end:
                    continue
                starts = [index + 1 for index, line in enumerate(lines) if begin in line]
                ends = [index + 1 for index, line in enumerate(lines) if end in line]
                if starts and ends and len(starts) == len(ends):
                    spans.extend((start, finish, entry) for start, finish in zip(starts, ends))
        for index, left in enumerate(spans):
            for right in spans[index + 1 :]:
                if left[0] <= right[1] and right[0] <= left[1] and left[2] is not right[2]:
                    if left[2]["writer"] != right[2]["writer"] or left[2].get("begin_marker") != right[2].get("begin_marker"):
                        issues.append(ContractIssue("error", "scope-overlap", path, f"writer scopes overlap: {left[2]['writer']} and {right[2]['writer']}"))
    unique: dict[tuple[str, str, str], ContractIssue] = {}
    for issue in issues:
        unique[(issue.kind, issue.subject, issue.detail)] = issue
    return list(unique.values()), ownership, environment_errors


def _scan_profile(profile: Profile, repo: Path, filters: set[str]) -> list[Hit]:
    if profile.client == "Egern":
        return extract_egern_forward(profile.path, repo, filters) + extract_yaml_hosts(profile.path, repo, filters, "Egern")
    if profile.client == "Mihomo":
        return extract_mihomo_policy(profile.path, repo, filters) + extract_yaml_hosts(profile.path, repo, filters, "Mihomo")
    if profile.client == "Stash":
        return extract_stash_policy(profile.path, repo, filters) + extract_yaml_hosts(profile.path, repo, filters, "Stash")
    if profile.client == "Loon":
        return extract_loon_host(profile.path, repo, filters) + extract_ini_dns_settings(profile.path, repo, "Loon", filters)
    return []


def _scan_plan(profiles: Sequence[Profile], repo: Path) -> tuple[list[Profile], list[dict[str, Any]]]:
    available = {rel(profile.path, repo) for profile in profiles}
    scanned, skipped = [], []
    for profile in profiles:
        if profile.role == "generated" and profile.generated_from and profile.generated_from in available:
            skipped.append({"path": rel(profile.path, repo), "reason": "derived artifact; canonical source scanned", "generated_from": profile.generated_from, "scope": profile.scope})
        else:
            scanned.append(profile)
    return scanned, skipped


def audit(repo: Path, domains: list[str], include_airportservers: bool) -> dict[str, Any]:
    repo = repo.resolve()
    if not repo.exists() or not repo.is_dir():
        return redact({"repo": str(repo), "domains": domains, "scanned": [], "skipped": [], "generated": [], "files": [], "dns_hits": [], "airportservers": [], "issues": [], "environment_errors": ["repo does not exist"], "contract": {"status": "unknown"}, "exit_code": 2})
    filters = {norm_domain(item) for item in domains}
    profiles = discover_profiles(repo)
    scanned, skipped = _scan_plan(profiles, repo)
    hits = [hit for profile in scanned for hit in _scan_profile(profile, repo, filters)]
    generated: list[dict[str, Any]] = []
    for profile in profiles:
        if profile.role == "generated":
            generated.append({"path": rel(profile.path, repo), "client": profile.client, "scope": profile.scope, "generated_from": profile.generated_from, "ranges": profile.markers})
        else:
            generated.extend({"path": rel(profile.path, repo), "client": profile.client, "scope": "marker", "marker": marker} for marker in profile.markers)
    contract = load_writer_contract(repo)
    contract_issues, ownership, contract_errors = audit_writer_contract(repo, profiles, contract)
    environment_errors = list(contract_errors)
    if not profiles:
        environment_errors.append("no supported profile files discovered")
    payload: dict[str, Any] = {
        "repo": str(repo),
        "domains": domains,
        "scanned": [profile_dict(profile, repo) for profile in scanned],
        "skipped": skipped + ([{"path": WRITER_CONTRACT_RELATIVE.as_posix(), "reason": "contract absent", "kind": "contract"}] if contract.get("status") != "valid" else []),
        "generated": generated,
        # Backward-compatible alias retained for callers of the first version.
        "files": [rel(profile.path, repo) for profile in scanned],
        "dns_hits": [asdict(hit) for hit in hits],
        "airportservers": [asdict(hit) for hit in (find_airportservers(repo, profiles) if include_airportservers else [])],
        "issues": [asdict(issue) for issue in contract_issues],
        "writer_ownership": ownership,
        "contract": {key: value for key, value in contract.items() if key != "document"},
        "environment_errors": environment_errors,
    }
    payload["exit_code"] = 2 if environment_errors else (1 if contract_issues else 0)
    return redact(payload)


def print_report(payload: Mapping[str, Any]) -> None:
    print(f"Repo: {payload['repo']}")
    print(f"Exit code: {payload.get('exit_code', 0)}")
    print("Scanned profiles:")
    for item in payload.get("scanned", []):
        print(f"  - {item['client']} {item['path']} [{item['role']}; {item['scope']}]")
    if payload.get("skipped"):
        print("Skipped:")
        for item in payload["skipped"]:
            print(f"  - {item.get('path', '<unknown>')} ({item.get('reason', 'not scanned')})")
    print("Generated scopes:")
    if not payload.get("generated"):
        print("  (none)")
    for item in payload.get("generated", []):
        marker = item.get("marker") or item.get("scope")
        print(f"  - {item.get('path')} [{marker}]")
    print("DNS routing entries:")
    hits = payload.get("dns_hits", [])
    if not hits:
        print("  (none)")
    for item in hits:
        print(f"  {item['file']}:{item['line']} [{item['kind']}] {item['key']} -> {item['value']}")
    if payload.get("airportservers"):
        print("AirportServers:")
        for item in payload["airportservers"]:
            print(f"  {item['file']}:{item['line']} [{item['kind']}] {item['value']}")
    if payload.get("issues"):
        print("Writer issues:")
        for item in payload["issues"]:
            print(f"  [{item['severity']}] {item['kind']} {item['subject']}: {item['detail']}")
    if payload.get("environment_errors"):
        print("Environment/contract errors:")
        for item in payload["environment_errors"]:
            print(f"  - {item}")


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit ProxyConfig DNS routing entries.")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--domain", action="append", default=[], help="Domain or wildcard domain to filter; repeatable")
    parser.add_argument("--airportservers", action="store_true", help="Include AirportServers list/reference audit")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    configure_output()
    args = parse_args(list(argv or sys.argv[1:]))
    payload = audit(args.repo, args.domain, args.airportservers)
    if args.json:
        print(json.dumps(redact(payload), ensure_ascii=False, indent=2))
    else:
        print_report(payload)
    return int(payload.get("exit_code", 2))


if __name__ == "__main__":
    raise SystemExit(main())
