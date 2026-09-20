#!/usr/bin/env python3
"""Audit proxy group definitions and references in ProxyConfig.

The script is intentionally dependency-free. It does not validate full YAML or
Loon INI syntax; it finds definitions and occurrences so an agent can reason about
the edit surface before touching Mihomo, Egern, Stash, or Loon files.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


CONFIG_SUFFIXES = {".yaml", ".yml", ".conf", ".dconf", ".json"}
DEFAULT_DIRS = ("Mihomo", "Egern", "Stash", "Loon")
DEFINITION_WINDOW = 12

# Audit reports are frequently copied into issue trackers and agent logs.
# Strip credentials and provider capability material before anything reaches
# either the text or JSON renderer.
_URL_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])"
    r"[A-Za-z][A-Za-z0-9+.-]*:"
    r"(?://|(?:\\?/){2})[^\s<>{}\[\]()\\\"'`,;]+",
    re.IGNORECASE,
)
_HEX_CAPABILITY_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
_UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b")
_SENSITIVE_KEY_RE = re.compile(
    r"(?<![\w-])['\"]?(?:"
    r"authorization|proxy[-_ ]?authorization|password|passwd|passphrase|"
    r"client[-_ ]?secret|client[-_ ]?password|secret|credential|"
    r"private[-_ ]?key|x[-_ ]?api[-_ ]?key|api[-_ ]?(?:key|secret|token)|"
    r"access[-_ ]?key|"
    r"access[-_ ]?token|"
    r"refresh[-_ ]?token|auth[-_ ]?token|capability[-_ ]?token|token"
    r")[ '\"]*\s*[:=：＝]\s*",
    re.IGNORECASE,
)


def _redact_urls(value: str) -> str:
    """Replace complete scheme-based URIs with a safe scheme/host summary."""

    def replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        trailing = ""
        while raw and raw[-1] in ".;:!?)]}":
            trailing = raw[-1] + trailing
            raw = raw[:-1]

        try:
            parsed = urlsplit(raw.replace("\\/", "/"))
            scheme = parsed.scheme.casefold()
            hostname = parsed.hostname
        except ValueError:
            scheme = ""
            hostname = None

        if hostname and scheme in {"http", "https", "ftp"}:
            safe_host = _HEX_CAPABILITY_RE.sub("[REDACTED_TOKEN]", hostname)
            return f"[REDACTED_URL scheme={scheme} host={safe_host}]{trailing}"
        if scheme:
            return f"[REDACTED_URL scheme={scheme}]{trailing}"
        return f"[REDACTED_URL]{trailing}"

    return _URL_RE.sub(replace, value)


def _redact_sensitive_assignments(value: str) -> str:
    """Redact values assigned to secret-like keys in YAML/JSON/INI text.

    This is deliberately line-oriented: the script is an inventory scanner,
    not a YAML parser.  Delimiters and comments are preserved while an
    unquoted scalar consumes the whole value, including ``Bearer`` headers.
    """

    result: list[str] = []
    cursor = 0
    for match in _SENSITIVE_KEY_RE.finditer(value):
        if match.start() < cursor:
            continue

        result.append(value[cursor : match.end()])
        start = match.end()
        while start < len(value) and value[start].isspace() and value[start] not in "\r\n":
            result.append(value[start])
            start += 1

        if start >= len(value) or value[start] in "\r\n":
            cursor = start
            continue

        quote = value[start] if value[start] in {"'", '"'} else None
        if quote:
            end = start + 1
            escaped = False
            while end < len(value):
                char = value[end]
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    end += 1
                    break
                end += 1
            result.append(f"{quote}[REDACTED]{quote}")
            cursor = end
            continue

        end = start
        while end < len(value) and value[end] not in ",}]\r\n#":
            end += 1
        scalar = value[start:end]
        if scalar.strip():
            result.append(scalar[: len(scalar) - len(scalar.lstrip())])
            result.append("[REDACTED]")
            result.append(scalar[len(scalar.rstrip()) :])
        cursor = end

    result.append(value[cursor:])
    return "".join(result)


def redact_text(value: str) -> str:
    """Return an audit-safe representation of arbitrary config text."""

    redacted = _redact_urls(value)
    redacted = _redact_sensitive_assignments(redacted)
    redacted = _UUID_RE.sub("[REDACTED_UUID]", redacted)
    return _HEX_CAPABILITY_RE.sub("[REDACTED_TOKEN]", redacted)


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
    """Normalize names without discarding non-ASCII letters or digits."""

    value = unicodedata.normalize("NFKC", value).casefold()
    return "".join(char for char in value if char.isalnum())


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_name_from_yaml(line: str) -> str | None:
    # The optional quotes also cover JSON objects encountered under a client
    # directory; a full JSON parser is unnecessary for line-level inventory.
    flow = re.search(r"['\"]?name['\"]?\s*:\s*([^,}\]#]+)", line)
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
    for back in range(index, -1, -1):
        line = lines[back]
        if re.match(r"^proxy-providers\s*:\s*$", line):
            return True
        if re.match(r"^(?:proxy-groups|policy_groups|policy-groups)\s*:\s*$", line):
            return False
        if back != index and re.match(r"^[A-Za-z0-9_-]+:\s*$", line):
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

        ini = re.match(r"^([^=\[\]#][^=]*?)\s*=\s*([^,\s]+)", line)
        if ini and path.suffix.lower() in {".conf", ".dconf"}:
            name = ini.group(1).strip()
            kind = ini.group(2).strip()
            defs.append(Definition(name=name, file=rel, line=idx + 1, kind=kind, text=stripped))
            continue

        provider_key = re.match(r"^\s{2}([A-Za-z][\w-]*)\s*:\s*$", line)
        if provider_key and is_mihomo_provider_key(lines, idx):
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
    print(f"Repo: {redact_text(str(repo))}")
    print("Scanned files:")
    for path in files:
        print(f"  - {redact_text(str(path.relative_to(repo)))}")

    for target, data in results.items():
        print()
        print(f"=== Target: {redact_text(target)} ===")
        definitions: list[Definition] = data["definitions"]
        hits: list[Hit] = data["hits"]

        print(f"Definitions: {len(definitions)}")
        for item in definitions:
            print(
                f"  {redact_text(item.file)}:{item.line} "
                f"[{redact_text(item.kind)}] {redact_text(item.name)} :: "
                f"{redact_text(item.text)}"
            )

        print(f"Occurrences: {len(hits)}")
        for item in hits:
            print(
                f"  {redact_text(item.file)}:{item.line} "
                f"[{redact_text(item.kind)}] {redact_text(item.text)}"
            )

        if not hits:
            print("  (none)")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Audit ProxyConfig group definitions and references.")
    parser.add_argument("repo", type=Path, help="Path to ProxyConfig repository")
    parser.add_argument("--target", action="append", default=[], help="Group/provider/name fragment to audit; repeatable")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return parser.parse_args(argv)


def safe_definition(item: Definition) -> dict[str, str | int]:
    return {
        "name": redact_text(item.name),
        "file": redact_text(item.file),
        "line": item.line,
        "kind": redact_text(item.kind),
        "text": redact_text(item.text),
    }


def safe_hit(item: Hit) -> dict[str, str | int]:
    return {
        "file": redact_text(item.file),
        "line": item.line,
        "kind": redact_text(item.kind),
        "text": redact_text(item.text),
    }


def main(argv: list[str]) -> int:
    configure_output()
    args = parse_args(argv)
    try:
        repo = args.repo.resolve()
    except OSError as exc:
        print(f"error: unable to resolve repo: {redact_text(str(exc))}", file=sys.stderr)
        return 2
    if not repo.exists() or not repo.is_dir():
        print(f"error: repo directory does not exist: {redact_text(str(repo))}", file=sys.stderr)
        return 2
    if not args.target:
        print("error: provide at least one --target", file=sys.stderr)
        return 2
    if any(not target.strip() or not normalize(target) for target in args.target):
        print("error: each --target must contain a letter or digit", file=sys.stderr)
        return 2

    try:
        files = find_config_files(repo)
        definitions: list[Definition] = []
        for path in files:
            definitions.extend(extract_definitions(path, repo))
    except OSError as exc:
        print(f"error: unable to read repo: {redact_text(str(exc))}", file=sys.stderr)
        return 2

    try:
        results = find_hits(repo, files, args.target, definitions)
    except OSError as exc:
        print(f"error: unable to read repo: {redact_text(str(exc))}", file=sys.stderr)
        return 2
    if args.json:
        payload = {
            "repo": redact_text(str(repo)),
            # Keep the historical ``files`` key and expose an explicit name
            # for consumers that want to assert exactly what was scanned.
            "files": [redact_text(str(path.relative_to(repo))) for path in files],
            "scanned_files": [redact_text(str(path.relative_to(repo))) for path in files],
            "targets": {
                key: {
                    "definitions": [safe_definition(item) for item in value["definitions"]],
                    "hits": [safe_hit(item) for item in value["hits"]],
                }
                for key, value in results.items()
            },
        }
        payload["targets"] = {
            redact_text(key): value for key, value in payload["targets"].items()
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print_text_report(repo, files, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
