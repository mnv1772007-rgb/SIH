#!/usr/bin/env python3
"""Offline-only URL feed normalization for Email Threat Forensics.

This module parses strings from already-collected files. It never follows,
resolves, downloads, previews, or otherwise visits a candidate URL.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=None)  # Never retrieve a suffix list at runtime.
except ImportError:  # pragma: no cover - minimal installations retain a safe fallback.
    _TLD_EXTRACT = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS_DIR = PROJECT_ROOT / "datasets" / "downloads"
PROCESSED_DIR = PROJECT_ROOT / "datasets" / "processed"
METADATA_DIR = PROJECT_ROOT / "datasets" / "metadata"
VALID_LABELS = {"benign", "malicious", "phishing", "suspicious"}
MAX_URL_LENGTH = 8192
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass
class URLRecord:
    id: str
    url: str
    normalized_url: str
    label: str
    source_dataset: str
    domain: str
    tld: str
    scheme: str
    port: str | None
    path: str
    query: str
    fragment: str
    metadata: dict[str, Any]


def _source_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def validate_and_normalize_url(value: Any) -> tuple[str | None, str | None]:
    """Return canonical HTTP(S) URL or a non-sensitive validation reason."""
    if not isinstance(value, str):
        return None, "non_string_url"
    raw = value.strip()
    if not raw:
        return None, "empty_url"
    if len(raw) > MAX_URL_LENGTH:
        return None, "url_too_large"
    if CONTROL_CHARACTERS.search(raw):
        return None, "control_character_url"
    try:
        parsed = urlsplit(raw)
    except (TypeError, ValueError):
        return None, "malformed_url"
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None, "invalid_scheme"
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return None, "invalid_port"
    if not hostname:
        return None, "missing_host"
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None, "invalid_host_encoding"
    if any(character.isspace() for character in hostname) or hostname.startswith("."):
        return None, "invalid_host"
    if parsed.username is not None or parsed.password is not None:
        return None, "credentialed_url"
    netloc = hostname if port is None or (scheme == "http" and port == 80) or (scheme == "https" and port == 443) else f"{hostname}:{port}"
    path = parsed.path or ""
    # Fragments are client-side only and should not create distinct train/test samples.
    return urlunsplit((scheme, netloc, path, parsed.query, "")), None


def normalize_url(url: str) -> str:
    """Compatibility helper returning an empty string for an invalid URL."""
    normalized, _ = validate_and_normalize_url(url)
    return normalized or ""


def extract_domain_tld(normalized_url: str) -> tuple[str, str]:
    hostname = urlsplit(normalized_url).hostname or ""
    if _TLD_EXTRACT is None:
        pieces = hostname.rsplit(".", 2)
        return (".".join(pieces[-2:]) if len(pieces) >= 2 else hostname, pieces[-1] if len(pieces) >= 2 else "")
    result = _TLD_EXTRACT(hostname)
    domain = ".".join(part for part in (result.domain, result.suffix) if part)
    return domain.lower(), result.suffix.lower()


def build_record(raw_url: Any, label: str, source: str) -> tuple[URLRecord | None, str | None]:
    normalized, error = validate_and_normalize_url(raw_url)
    if error or not normalized:
        return None, error or "normalization_failed"
    parsed = urlsplit(normalized)
    domain, tld = extract_domain_tld(normalized)
    return URLRecord(
        id=_source_hash(normalized), url=str(raw_url).strip(), normalized_url=normalized, label=label,
        source_dataset=source, domain=domain, tld=tld, scheme=parsed.scheme,
        port=str(parsed.port) if parsed.port else None, path=parsed.path, query=parsed.query,
        fragment="", metadata={"offline_only": True, "fragment_removed_for_deduplication": bool(urlsplit(str(raw_url).strip()).fragment)},
    ), None


def _read_text(path: Path) -> tuple[str | None, str | None]:
    try:
        return path.read_text(encoding="utf-8", errors="replace"), None
    except (OSError, UnicodeError, ValueError) as exc:
        return None, f"read_error:{type(exc).__name__}"


def iter_urls_from_file(path: Path) -> tuple[Iterable[tuple[int, Any]], str | None]:
    """Extract potential values from a known feed format without network use."""
    text, error = _read_text(path)
    if error or text is None:
        return (), error
    name = path.name.lower()
    try:
        if "phishtank" in name and path.suffix.lower() == ".json":
            data = json.loads(text)
            if not isinstance(data, list):
                return (), "invalid_json_feed_shape"
            return ((index + 1, item.get("url", "") if isinstance(item, dict) else "") for index, item in enumerate(data)), None
        if "urlhaus" in name and path.suffix.lower() == ".csv":
            rows = csv.DictReader(line for line in text.splitlines() if not line.lstrip().startswith("#"))
            return ((index + 2, row.get("url", "") or row.get("urlhaus_url", "")) for index, row in enumerate(rows)), None
        if path.suffix.lower() == ".csv":
            rows = list(csv.DictReader(text.splitlines()))
            if rows and any("url" in key.lower() for key in rows[0]):
                url_column = next(key for key in rows[0] if "url" in key.lower())
                return ((index + 2, row.get(url_column, "")) for index, row in enumerate(rows)), None
            # Public top-domain files use rank,domain and remain offline strings.
            if rows and any("domain" in key.lower() for key in rows[0]):
                domain_column = next(key for key in rows[0] if "domain" in key.lower())
                return ((index + 2, f"https://{row.get(domain_column, '').strip()}/") for index, row in enumerate(rows)), None
            return (), "unrecognised_csv_columns"
        return ((index + 1, line.strip()) for index, line in enumerate(text.splitlines())), None
    except (csv.Error, json.JSONDecodeError, UnicodeError, ValueError, TypeError) as exc:
        return (), f"parse_error:{type(exc).__name__}"


def _infer_label(path: Path, root: Path) -> tuple[str | None, str]:
    relative = path.relative_to(root)
    parts = [part.lower() for part in relative.parts]
    name = path.name.lower()
    source = parts[0] if parts else "unknown"
    for label in VALID_LABELS:
        if label in parts or label in name:
            return label, source
    if "phishtank" in name or "openphish" in name:
        return "phishing", source
    if "urlhaus" in name:
        return "malicious", source
    if "umbrella" in name or "majestic" in name or "top-1m" in name:
        return "benign", source
    return None, source


def find_url_files(root: Path) -> list[tuple[Path, str, str]]:
    if not root.exists():
        return []
    results: list[tuple[Path, str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in {".txt", ".csv", ".json"}:
            continue
        label, source = _infer_label(path, root)
        if label:
            results.append((path, label, source))
    return sorted(results, key=lambda item: str(item[0]).lower())


def _validate_jsonl(path: Path) -> tuple[int, int]:
    valid = invalid = 0
    required = {"id", "url", "normalized_url", "label", "source_dataset", "metadata"}
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
            valid += int(required.issubset(record) and record.get("normalized_url") == normalize_url(record.get("url", "")))
            invalid += int(not (required.issubset(record) and record.get("normalized_url") == normalize_url(record.get("url", ""))))
        except json.JSONDecodeError:
            invalid += 1
    return valid, invalid


def main() -> int:
    parser = argparse.ArgumentParser(description="Process offline URL feeds into normalized JSONL")
    parser.add_argument("--input", type=Path, default=DOWNLOADS_DIR / "urls", help="Directory containing collected feeds")
    parser.add_argument("--output", type=Path, default=PROCESSED_DIR / "urls.jsonl", help="Output JSONL path")
    parser.add_argument("--limit", type=int, help="Limit accepted rows for a smoke run")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    feeds = find_url_files(args.input)
    print(f"Scanning {args.input} for URL data files...")
    print(f"Found {len(feeds)} URL data files")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    issues_path = METADATA_DIR / f"url_processing_issues_{timestamp}.jsonl"
    stats: dict[str, Any] = {"feed_files": len(feeds), "candidate_rows": 0, "processed": 0, "duplicates": 0, "malformed": 0, "by_label": {}, "by_source": {}, "issues_by_reason": {}}
    records: list[URLRecord] = []
    seen: set[str] = set()
    with issues_path.open("w", encoding="utf-8") as issue_handle:
        for path, label, source in feeds:
            values, file_error = iter_urls_from_file(path)
            if file_error:
                stats["malformed"] += 1
                stats["issues_by_reason"][file_error] = stats["issues_by_reason"].get(file_error, 0) + 1
                issue_handle.write(json.dumps({"source_file": str(path.relative_to(PROJECT_ROOT)), "reason": file_error}) + "\n")
                continue
            for line_number, value in values:
                stats["candidate_rows"] += 1
                record, error = build_record(value, label, source)
                issue = {"source_file": str(path.relative_to(PROJECT_ROOT)), "line": line_number, "url_hash": _source_hash(str(value))}
                if error or not record:
                    reason = error or "unknown_url_error"
                    stats["malformed"] += 1
                    stats["issues_by_reason"][reason] = stats["issues_by_reason"].get(reason, 0) + 1
                    issue_handle.write(json.dumps({**issue, "reason": reason}) + "\n")
                    continue
                if record.normalized_url in seen:
                    stats["duplicates"] += 1
                    issue_handle.write(json.dumps({**issue, "reason": "normalized_url_duplicate"}) + "\n")
                    continue
                seen.add(record.normalized_url)
                records.append(record)
                stats["processed"] += 1
                stats["by_label"][label] = stats["by_label"].get(label, 0) + 1
                stats["by_source"][source] = stats["by_source"].get(source, 0) + 1
                if args.limit and stats["processed"] >= args.limit:
                    break
            if args.limit and stats["processed"] >= args.limit:
                break
    temporary_output = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary_output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
    temporary_output.replace(args.output)
    valid, invalid = _validate_jsonl(args.output)
    stats["jsonl_valid_lines"], stats["jsonl_invalid_lines"] = valid, invalid
    report_path = METADATA_DIR / f"url_processing_report_{timestamp}.json"
    report_path.write_text(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "input_dir": str(args.input), "output_file": str(args.output), "issues_file": str(issues_path), "stats": stats, "offline_only": True}, indent=2), encoding="utf-8")
    print("\nProcessing complete:")
    print(f"  Candidate rows:      {stats['candidate_rows']}")
    print(f"  Unique processed:    {stats['processed']}")
    print(f"  Duplicates:          {stats['duplicates']}")
    print(f"  Malformed/skipped:   {stats['malformed']}")
    for label, count in sorted(stats["by_label"].items()):
        print(f"  {label}: {count}")
    print(f"  JSONL validation:    {valid} valid, {invalid} invalid")
    print(f"  Report: {report_path}")
    return 0 if invalid == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
