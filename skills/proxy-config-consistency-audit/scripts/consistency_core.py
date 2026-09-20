#!/usr/bin/env python3
"""Contract-aware, read-only consistency audit for ProxyConfig."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any


REGIONS = ("HK", "TW", "SG", "JP", "US")
PARTIAL_REGION_BASES = {"Residential", "Relay-Res", "Dialer-Res"}
BUILT_INS = {
    "DIRECT",
    "FINAL",
    "GLOBAL",
    "PASS",
    "PROXY",
    "REJECT",
    "REJECT-DROP",
    "REJECT-TINYGIF",
}
CLIENT_EXTENSIONS = {
    "Egern": {".yaml", ".yml"},
    "Mihomo": {".yaml", ".yml"},
    "Loon": {".conf"},
    "Stash": {".yaml", ".yml"},
}
YAML_GROUP_SECTIONS = {"proxy-groups", "policy-groups", "policy_groups"}
YAML_PROVIDER_SECTIONS = {"proxy-providers", "policy-providers", "policy_providers"}
RULE_TYPES_WITH_POLICY = {
    "DOMAIN",
    "DOMAIN-KEYWORD",
    "DOMAIN-SET",
    "DOMAIN-SUFFIX",
    "GEOIP",
    "GEOSITE",
    "IP-ASN",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "RULE-SET",
    "SCRIPT",
    "URL-REGEX",
}
ALLOWED_SCOPES = {"whole-file", "marker-pair", "field-selector"}
URL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>\[\](){}\\`,;]+"
)
UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")
SECRET_ASSIGNMENT_RE = re.compile(
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
SENSITIVE_KEY_RE = re.compile(
    r"(?ix)^(?:authorization|proxy[-_ ]?authorization|password|passwd|"
    r"passphrase|client[-_ ]?(?:secret|password)|secret|credential|"
    r"private[-_ ]?key|x[-_ ]?api[-_ ]?key|api[-_ ]?(?:key|secret|token)|"
    r"access[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|auth[-_ ]?token|"
    r"capability[-_ ]?token|bearer|token)$"
)


@dataclass(frozen=True)
class Definition:
    client: str
    file: str
    line: int
    kind: str
    name: str


@dataclass(frozen=True)
class Finding:
    severity: str
    kind: str
    subject: str
    detail: str


def configure_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def redact_text(value: str) -> str:
    value = URL_RE.sub("<redacted-url>", value)
    value = UUID_RE.sub("<redacted-uuid>", value)
    return SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}<redacted>", value)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            visible_key = redact_text(str(key))
            key_name = str(key).strip().strip('"').strip("'")
            result[visible_key] = "<redacted>" if SENSITIVE_KEY_RE.fullmatch(key_name) else redact_value(item)
        return result
    return value


def read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8-sig", errors="replace").splitlines()


def relative_path(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except (OSError, ValueError):
        return redact_text(path.name)


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def visible_name(name: str) -> str:
    return re.sub(r"^[^\wA-Za-z]+", "", name).strip()


def target_match(name: str, targets: set[str]) -> bool:
    if not targets:
        return True
    candidate = normalized(name)
    return any(target in candidate or candidate in target for target in targets)


def region_base(name: str) -> tuple[str, str] | None:
    match = re.match(r"^(.+)-(" + "|".join(REGIONS) + r")$", visible_name(name))
    if not match:
        return None
    return match.group(1), match.group(2)


def is_local_repository(name: object) -> bool:
    if not isinstance(name, str) or not name.strip():
        return True
    return name.replace("\\", "/").rstrip("/").casefold().split("/")[-1] == "proxyconfig"


def clean_repo_path(raw: object) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    candidate = raw.replace("\\", "/")
    while candidate.startswith("./"):
        candidate = candidate[2:]
    pure = PurePosixPath(candidate)
    if pure.is_absolute() or ".." in pure.parts:
        return None
    return pure.as_posix()


def has_magic(path: str) -> bool:
    return any(character in path for character in "*?[")


def pattern_matches(path: str, pattern: str) -> bool:
    clean = pattern.replace("\\", "/")
    while clean.startswith("./"):
        clean = clean[2:]
    return path == clean or (has_magic(clean) and PurePosixPath(path).match(clean))


def expand_local_target(repo: Path, pattern: str) -> list[Path]:
    if has_magic(pattern):
        return sorted(path for path in repo.glob(pattern) if path.is_file())
    path = repo / Path(pattern)
    return [path] if path.is_file() else []


def selector_markers(selector: object) -> tuple[str | None, str | None]:
    if isinstance(selector, str) and selector.strip():
        label = selector.strip()
        return f"BEGIN {label}", f"END {label}"
    if isinstance(selector, dict):
        begin = selector.get("begin")
        end = selector.get("end")
        if isinstance(begin, str) and isinstance(end, str) and begin and end:
            return begin, end
    return None, None


def validator_locator_path(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    locator = value.strip()
    if locator.casefold() == "git diff --check":
        return ""
    if re.match(r"^[^:]+/[^:]+:", locator):
        return ""
    return clean_repo_path(locator.split()[0])


def workflow_concurrency(path: Path) -> str | None:
    lines = read_lines(path)
    in_concurrency = False
    base_indent = 0
    for line in lines:
        if re.match(r"^concurrency\s*:\s*$", line):
            in_concurrency = True
            base_indent = len(line) - len(line.lstrip())
            continue
        if not in_concurrency:
            continue
        indent = len(line) - len(line.lstrip())
        if line.strip() and indent <= base_indent:
            break
        match = re.match(r"^\s*group\s*:\s*(.+?)\s*(?:#.*)?$", line)
        if match:
            return strip_quotes(match.group(1))
    inline = next((re.match(r"^concurrency\s*:\s*(.+?)\s*$", line) for line in lines if line.startswith("concurrency:")), None)
    return strip_quotes(inline.group(1)) if inline else None


def load_contract(repo: Path, contract_path: Path) -> tuple[dict[str, Any] | None, list[Finding]]:
    errors: list[Finding] = []
    if not contract_path.is_file():
        errors.append(Finding("error", "missing-contract", relative_path(contract_path, repo), "generated-writer contract is unavailable"))
        return None, errors
    try:
        payload = json.loads(contract_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(Finding("error", "invalid-contract", relative_path(contract_path, repo), f"cannot parse generated-writer contract: {exc}"))
        return None, errors
    if not isinstance(payload, dict) or payload.get("schema") != 1 or not isinstance(payload.get("writers"), list):
        errors.append(Finding("error", "invalid-contract-schema", relative_path(contract_path, repo), "expected schema 1 with a writers array"))
        return None, errors
    return payload, errors


def validate_contract(repo: Path, contract: dict[str, Any]) -> tuple[list[Finding], list[dict[str, Any]], list[str]]:
    issues: list[Finding] = []
    generated: list[dict[str, Any]] = []
    whole_file_patterns: list[str] = []
    writers = contract.get("writers", [])
    ids: list[str] = []
    by_id: dict[str, dict[str, Any]] = {}
    owners: dict[tuple[str, str, str], list[tuple[str, str, object, str]]] = {}
    marker_ranges: dict[tuple[str, str, str], list[tuple[str, int, int]]] = {}

    for index, raw_writer in enumerate(writers):
        if not isinstance(raw_writer, dict):
            issues.append(Finding("error", "invalid-writer", f"writers[{index}]", "writer must be an object"))
            continue
        writer_id = raw_writer.get("id")
        if not isinstance(writer_id, str) or not writer_id.strip():
            issues.append(Finding("error", "invalid-writer-id", f"writers[{index}]", "writer id is required"))
            continue
        if writer_id in by_id:
            issues.append(Finding("error", "duplicate-writer-id", writer_id, "writer id is declared more than once"))
        ids.append(writer_id)
        by_id[writer_id] = raw_writer
        related_repositories = [
            item.get("repository")
            for field in ("inputs", "targets")
            for item in (raw_writer.get(field) if isinstance(raw_writer.get(field), list) else [])
            if isinstance(item, dict)
        ]
        writer_is_local = any(is_local_repository(name) for name in related_repositories)

        inputs = raw_writer.get("inputs")
        if not isinstance(inputs, list) or not inputs:
            issues.append(Finding("error", "missing-inputs", writer_id, "writer must declare at least one input"))
        else:
            for input_index, source in enumerate(inputs):
                subject = f"{writer_id}.inputs[{input_index}]"
                if not isinstance(source, dict):
                    issues.append(Finding("error", "invalid-input", subject, "input must be an object"))
                    continue
                source_path = clean_repo_path(source.get("path"))
                if source_path is None:
                    issues.append(Finding("error", "invalid-input-path", subject, "input path must be repository-relative"))
                    continue
                source_branch = source.get("branch")
                if source_branch is not None and (not isinstance(source_branch, str) or not source_branch.strip()):
                    issues.append(Finding("error", "invalid-input-branch", subject, "branch must be a non-empty string"))
                if not is_local_repository(source.get("repository")):
                    if source_branch is None:
                        issues.append(Finding("error", "missing-external-input-branch", subject, "external input must declare its branch"))
                    continue
                if not expand_local_target(repo, source_path):
                    issues.append(Finding("error", "missing-input", subject, f"declared input does not exist: {source_path}"))

        concurrency = raw_writer.get("concurrency_group")
        if not isinstance(concurrency, str) or not concurrency.strip():
            issues.append(Finding("error", "missing-concurrency-group", writer_id, "writer must declare a concurrency group"))
            concurrency = ""

        for field in ("entrypoint", "workflow"):
            declared = clean_repo_path(raw_writer.get(field))
            if declared is None:
                issues.append(Finding("error", f"invalid-{field}", writer_id, f"{field} must be a repository-relative path"))
                continue
            if not writer_is_local:
                continue
            actual = repo / Path(declared)
            if not actual.is_file():
                issues.append(Finding("error", f"missing-{field}", writer_id, f"declared {field} does not exist: {declared}"))
            elif field == "workflow" and concurrency:
                actual_group = workflow_concurrency(actual)
                if actual_group != concurrency:
                    issues.append(Finding("error", "workflow-concurrency-mismatch", writer_id, f"contract={concurrency}; workflow={actual_group or '<missing>'}"))

        targets = raw_writer.get("targets")
        if not isinstance(targets, list) or not targets:
            issues.append(Finding("error", "missing-targets", writer_id, "writer must declare at least one target"))
            continue
        for target_index, target in enumerate(targets):
            if not isinstance(target, dict):
                issues.append(Finding("error", "invalid-target", f"{writer_id}[{target_index}]", "target must be an object"))
                continue
            repository = target.get("repository", "ProxyConfig")
            branch = target.get("branch", "")
            path = clean_repo_path(target.get("path"))
            scope = target.get("scope")
            selector = target.get("selector")
            subject = f"{writer_id}[{target_index}]"
            if path is None:
                issues.append(Finding("error", "invalid-target-path", subject, "target path must be repository-relative"))
                continue
            if scope not in ALLOWED_SCOPES:
                issues.append(Finding("error", "invalid-target-scope", subject, f"unsupported scope: {scope!r}"))
                continue
            repository_key = repository if isinstance(repository, str) else ""
            branch_key = branch if isinstance(branch, str) else ""
            if branch is not None and branch != "" and (not isinstance(branch, str) or not branch.strip()):
                issues.append(Finding("error", "invalid-target-branch", subject, "branch must be a non-empty string"))
            if not is_local_repository(repository) and not branch_key:
                issues.append(Finding("error", "missing-external-target-branch", subject, "external target must declare its branch"))
            owners.setdefault((repository_key, branch_key, path), []).append((writer_id, scope, selector, concurrency))
            generated.append({"writer": writer_id, "repository": repository_key, "branch": branch_key, "path": path, "scope": scope})

            if not is_local_repository(repository):
                continue
            matches = expand_local_target(repo, path)
            if not matches:
                issues.append(Finding("error", "missing-generated-target", subject, f"declared target does not exist: {path}"))
                continue
            if scope == "whole-file":
                whole_file_patterns.append(path)
            elif scope == "marker-pair":
                begin, end = selector_markers(selector)
                if not begin or not end:
                    issues.append(Finding("error", "invalid-marker-selector", subject, "marker-pair requires a selector string or begin/end object"))
                    continue
                for match_path in matches:
                    lines = read_lines(match_path)
                    begin_lines = [number for number, line in enumerate(lines, 1) if begin in line]
                    end_lines = [number for number, line in enumerate(lines, 1) if end in line]
                    if len(begin_lines) != 1 or len(end_lines) != 1:
                        issues.append(Finding("error", "marker-cardinality", relative_path(match_path, repo), f"{writer_id} expects one begin/end marker; found {len(begin_lines)}/{len(end_lines)}"))
                    elif begin_lines[0] >= end_lines[0]:
                        issues.append(Finding("error", "marker-order", relative_path(match_path, repo), f"{writer_id} begin marker must precede end marker"))
                    else:
                        marker_key = (repository_key, branch_key, relative_path(match_path, repo))
                        marker_ranges.setdefault(marker_key, []).append((writer_id, begin_lines[0], end_lines[0]))
            elif scope == "field-selector" and not isinstance(selector, (str, dict)):
                issues.append(Finding("error", "invalid-field-selector", subject, "field-selector requires a stable selector"))

        validators = raw_writer.get("validators")
        if not isinstance(validators, list) or not validators:
            issues.append(Finding("error", "missing-validators", writer_id, "writer must declare validator locators"))
        else:
            for validator_index, validator in enumerate(validators):
                subject = f"{writer_id}.validators[{validator_index}]"
                locator = validator_locator_path(validator)
                if locator is None:
                    issues.append(Finding("error", "invalid-validator", subject, "validator must be a non-empty locator string"))
                elif locator and writer_is_local and not expand_local_target(repo, locator):
                    issues.append(Finding("error", "missing-validator", subject, f"validator locator does not exist: {locator}"))

        exclusions = raw_writer.get("intentional_exclusions")
        if not isinstance(exclusions, list):
            issues.append(Finding("error", "invalid-intentional-exclusions", writer_id, "intentional_exclusions must be an array"))

    declared_ids = set(ids)
    for writer_id, writer in by_id.items():
        delegates = writer.get("delegates_to", [])
        if not isinstance(delegates, list):
            issues.append(Finding("error", "invalid-delegates", writer_id, "delegates_to must be an array"))
            continue
        for delegate in delegates:
            if not isinstance(delegate, str) or delegate not in declared_ids:
                issues.append(Finding("error", "undefined-delegate", writer_id, f"unknown delegated writer: {delegate!r}"))
            elif delegate == writer_id:
                issues.append(Finding("error", "self-delegation", writer_id, "writer cannot delegate to itself"))

    for (repository, branch, path), declarations in owners.items():
        if len(declarations) < 2:
            continue
        writer_names = [item[0] for item in declarations]
        locks = {item[3] for item in declarations}
        scopes = [item[1] for item in declarations]
        selectors = [json.dumps(item[2], ensure_ascii=False, sort_keys=True) for item in declarations]
        subject = f"{repository}@{branch}:{path}"
        if len(locks) != 1 or "" in locks:
            issues.append(Finding("error", "shared-target-lock-mismatch", subject, f"writers {writer_names} must share one concurrency group"))
        if "whole-file" in scopes:
            issues.append(Finding("error", "whole-file-owner-overlap", subject, f"whole-file target has multiple writers: {writer_names}"))
        if len(selectors) != len(set(selectors)):
            issues.append(Finding("error", "selector-owner-overlap", subject, f"multiple writers claim the same selector: {writer_names}"))

    for (repository, branch, path), ranges in marker_ranges.items():
        for index, (left_writer, left_begin, left_end) in enumerate(ranges):
            for right_writer, right_begin, right_end in ranges[index + 1 :]:
                if max(left_begin, right_begin) <= min(left_end, right_end):
                    subject = f"{repository}@{branch}:{path}"
                    issues.append(Finding("error", "marker-range-overlap", subject, f"{left_writer} and {right_writer} claim overlapping marker ranges"))

    return issues, sorted(generated, key=lambda item: (item["repository"], item["path"], item["writer"])), sorted(set(whole_file_patterns))


def discover_client_files(repo: Path, whole_file_patterns: list[str]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    scanned: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for client, extensions in CLIENT_EXTENSIONS.items():
        root = repo / client
        if not root.is_dir():
            continue
        for path in sorted(item for item in root.rglob("*") if item.is_file() and item.suffix.casefold() in extensions):
            relative = relative_path(path, repo)
            matching = next((pattern for pattern in whole_file_patterns if pattern_matches(relative, pattern)), None)
            if matching:
                skipped.append({"client": client, "path": relative, "reason": "whole-file-generated"})
            else:
                scanned.append({"client": client, "path": relative, "role": "canonical-or-mixed"})
    return scanned, skipped


def parse_yaml_name(line: str) -> str | None:
    flow = re.search(r"\bname\s*:\s*([^,}#]+)", line)
    if flow:
        return strip_quotes(flow.group(1))
    block = re.match(r"^\s*(?:-\s*)?name\s*:\s*(.+?)\s*(?:#.*)?$", line)
    if block:
        return strip_quotes(block.group(1))
    return None


def extract_yaml_definitions(repo: Path, client: str, path: Path) -> list[Definition]:
    definitions: list[Definition] = []
    section: str | None = None
    for line_number, line in enumerate(read_lines(path), 1):
        top = re.match(r"^([A-Za-z][\w-]*)\s*:\s*(?:#.*)?$", line)
        if top:
            section = top.group(1)
            continue
        if section in YAML_PROVIDER_SECTIONS:
            provider = re.match(r"^\s{2,}([^\s#][^:#]*?)\s*:\s*(?:\{|$)", line)
            if provider:
                definitions.append(Definition(client, relative_path(path, repo), line_number, "provider", strip_quotes(provider.group(1))))
                continue
        name = parse_yaml_name(line)
        if not name:
            continue
        if section in YAML_GROUP_SECTIONS:
            kind = "provider" if re.search(r"[-_]Provider$", name) else "group"
            definitions.append(Definition(client, relative_path(path, repo), line_number, kind, name))
        elif re.search(r"[-_]Provider$", name):
            definitions.append(Definition(client, relative_path(path, repo), line_number, "provider", name))
    return definitions


def extract_ini_definitions(repo: Path, client: str, path: Path) -> list[Definition]:
    definitions: list[Definition] = []
    section = ""
    for line_number, line in enumerate(read_lines(path), 1):
        header = re.match(r"^\s*\[([^]]+)]\s*$", line)
        if header:
            section = header.group(1).strip().casefold()
            continue
        if section not in {"proxy group", "remote proxy", "remote filter"}:
            continue
        match = re.match(r"^\s*([^#;=][^=]*?)\s*=", line)
        if not match:
            continue
        name = match.group(1).strip()
        kind = "provider" if section in {"remote proxy", "remote filter"} or re.search(r"[-_]Provider$", name) else "group"
        definitions.append(Definition(client, relative_path(path, repo), line_number, kind, name))
    return definitions


def yaml_rule_refs(repo: Path, client: str, path: Path) -> list[tuple[str, str, int, str]]:
    references: list[tuple[str, str, int, str]] = []
    in_rules = False
    for line_number, line in enumerate(read_lines(path), 1):
        if re.match(r"^rules\s*:\s*(?:#.*)?$", line):
            in_rules = True
            continue
        if in_rules and line and not line[0].isspace() and re.match(r"^[A-Za-z][\w-]*\s*:", line):
            break
        if not in_rules:
            continue
        policy = re.match(r"^\s+policy\s*:\s*(.+?)\s*(?:#.*)?$", line)
        if policy:
            references.append((client, relative_path(path, repo), line_number, strip_quotes(policy.group(1))))
            continue
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        parts = [part.strip() for part in stripped[2:].split(",")]
        if not parts:
            continue
        rule_type = parts[0].upper()
        if rule_type in {"MATCH", "FINAL"} and len(parts) >= 2:
            references.append((client, relative_path(path, repo), line_number, parts[1]))
        elif rule_type in RULE_TYPES_WITH_POLICY and len(parts) >= 3:
            references.append((client, relative_path(path, repo), line_number, parts[2]))
    return references


def ini_rule_refs(repo: Path, client: str, path: Path) -> list[tuple[str, str, int, str]]:
    references: list[tuple[str, str, int, str]] = []
    section = ""
    for line_number, line in enumerate(read_lines(path), 1):
        header = re.match(r"^\s*\[([^]]+)]\s*$", line)
        if header:
            section = header.group(1).strip().casefold()
            continue
        if section != "rule":
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        parts = [part.strip() for part in stripped.split(",")]
        rule_type = parts[0].upper() if parts else ""
        if rule_type in {"FINAL", "MATCH"} and len(parts) >= 2:
            references.append((client, relative_path(path, repo), line_number, parts[1]))
        elif rule_type in RULE_TYPES_WITH_POLICY and len(parts) >= 3:
            references.append((client, relative_path(path, repo), line_number, parts[2]))
    return references


def inspect_clients(repo: Path, scanned: list[dict[str, str]], raw_targets: list[str]) -> tuple[dict[str, Any], dict[str, Any], list[Finding]]:
    targets = {normalized(item) for item in raw_targets}
    all_definitions: list[Definition] = []
    all_references: list[tuple[str, str, int, str]] = []
    for item in scanned:
        path = repo / Path(item["path"])
        client = item["client"]
        if path.suffix.casefold() in {".yaml", ".yml"}:
            all_definitions.extend(extract_yaml_definitions(repo, client, path))
            all_references.extend(yaml_rule_refs(repo, client, path))
        else:
            all_definitions.extend(extract_ini_definitions(repo, client, path))
            all_references.extend(ini_rule_refs(repo, client, path))

    definitions = [item for item in all_definitions if target_match(item.name, targets)]
    providers: dict[str, dict[str, list[Definition]]] = {}
    region_groups: dict[str, dict[str, dict[str, list[Definition]]]] = {}
    for item in definitions:
        if item.kind == "provider":
            base = re.sub(r"[-_]?Provider$", "", visible_name(item.name), flags=re.IGNORECASE)
            providers.setdefault(base, {}).setdefault(item.client, []).append(item)
        if item.kind == "group":
            parsed = region_base(item.name)
            if parsed:
                base, region = parsed
                region_groups.setdefault(base, {}).setdefault(item.client, {}).setdefault(region, []).append(item)

    issues: list[Finding] = []
    active_clients = {item["client"] for item in scanned}
    for provider, by_client in sorted(providers.items()):
        present = set(by_client)
        if len(present) < 2:
            continue
        missing = sorted(active_clients - present)
        if missing:
            issues.append(Finding("warning", "provider-client-coverage", provider, f"present in {sorted(present)}, missing in {missing}"))

    for base, by_client in sorted(region_groups.items()):
        if base in PARTIAL_REGION_BASES:
            continue
        for client, by_region in sorted(by_client.items()):
            present = set(by_region)
            if present and present != set(REGIONS):
                issues.append(Finding("warning", "region-coverage", f"{client}:{base}", f"has {sorted(present)}, missing {sorted(set(REGIONS) - present)}"))

    if not targets:
        names_by_client: dict[str, set[str]] = {}
        for definition in all_definitions:
            names_by_client.setdefault(definition.client, set()).add(definition.name)
        seen: set[tuple[str, str, int, str]] = set()
        for client, file, line, policy in all_references:
            key = (client, file, line, policy)
            if key in seen:
                continue
            seen.add(key)
            if policy.upper() in BUILT_INS or policy in names_by_client.get(client, set()):
                continue
            issues.append(Finding("warning", "undefined-rule-policy", f"{file}:{line}", f"{client} rule targets undefined policy {policy}"))

    provider_payload = {
        name: {client: [asdict(item) for item in items] for client, items in by_client.items()}
        for name, by_client in providers.items()
    }
    region_payload = {
        name: {
            client: {region: [asdict(item) for item in items] for region, items in regions.items()}
            for client, regions in by_client.items()
        }
        for name, by_client in region_groups.items()
    }
    return provider_payload, region_payload, issues


def audit(repo: Path, raw_targets: list[str], contract_path: Path | None = None) -> dict[str, Any]:
    repo = repo.resolve()
    contract_file = contract_path or repo / "Sub-Store/config/generated-writers.json"
    if not contract_file.is_absolute():
        contract_file = repo / contract_file
    contract, environment_errors = load_contract(repo, contract_file)
    contract_issues: list[Finding] = []
    generated: list[dict[str, Any]] = []
    whole_file_patterns: list[str] = []
    if contract is not None:
        contract_issues, generated, whole_file_patterns = validate_contract(repo, contract)
    scanned, skipped = discover_client_files(repo, whole_file_patterns)
    providers, region_groups, client_issues = inspect_clients(repo, scanned, raw_targets)
    issues = contract_issues + client_issues
    payload: dict[str, Any] = {
        "schema": 1,
        "repo": str(repo),
        "contract": {
            "path": relative_path(contract_file, repo),
            "writers": len(contract.get("writers", [])) if contract else 0,
        },
        "scanned": scanned,
        "skipped": skipped,
        "generated": generated,
        "providers": providers,
        "region_groups": region_groups,
        "issues": [asdict(item) for item in issues],
        "environment_errors": [asdict(item) for item in environment_errors],
        "summary": {
            "scanned": len(scanned),
            "skipped": len(skipped),
            "generated": len(generated),
            "issues": len(issues),
            "environment_errors": len(environment_errors),
        },
    }
    return redact_value(payload)


def print_report(payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    print(f"Repo: {payload['repo']}")
    print(f"Contract: {payload['contract']['path']} ({payload['contract']['writers']} writers)")
    print(
        "Files: "
        f"scanned={summary['scanned']} skipped={summary['skipped']} generated={summary['generated']}"
    )
    print(f"Findings: issues={summary['issues']} environment_errors={summary['environment_errors']}")
    for item in payload["environment_errors"]:
        print(f"  [environment] {item['kind']} {item['subject']}: {item['detail']}")
    for item in payload["issues"]:
        print(f"  [{item['severity']}] {item['kind']} {item['subject']}: {item['detail']}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit ProxyConfig cross-client and generated-writer consistency.")
    parser.add_argument("repo", type=Path)
    parser.add_argument("--target", action="append", default=[], help="Provider/group fragment to filter; repeatable")
    parser.add_argument("--contract", type=Path, help="Generated-writer contract path; defaults under the repository")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    if not args.repo.is_dir():
        print("error: repository directory does not exist", file=sys.stderr)
        return 2
    payload = audit(args.repo, args.target, args.contract)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_report(payload)
    if payload["environment_errors"]:
        return 2
    if payload["issues"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
