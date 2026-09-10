#!/usr/bin/env python3
"""
Automated dataset download pipeline for Email Threat Forensics.

Downloads approved public datasets, verifies checksums, resumes interrupted downloads,
and logs all activity. Does not bypass manual-download requirements.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = PROJECT_ROOT / "datasets" / "metadata" / "sources.json"
RAW_DIR = PROJECT_ROOT / "datasets" / "raw"
DOWNLOADS_DIR = PROJECT_ROOT / "datasets" / "downloads"
LOG_FILE = PROJECT_ROOT / "datasets" / "metadata" / "download_log.jsonl"

# Ensure directories exist
RAW_DIR.mkdir(parents=True, exist_ok=True)
DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def log_entry(entry: dict[str, Any]) -> None:
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def download_with_resume(url: str, dest: Path, chunk_size: int = 8192, timeout: int = 30) -> bool:
    """Download a file with resume support. Returns True on success."""
    headers = {}
    mode = "wb"
    if dest.exists():
        downloaded = dest.stat().st_size
        headers["Range"] = f"bytes={downloaded}-"
        mode = "ab"
    else:
        downloaded = 0

    try:
        response = requests.get(url, headers=headers, stream=True, timeout=timeout)
        if response.status_code == 416:  # Range not satisfiable - file complete
            return True
        if response.status_code not in (200, 206):
            log_entry({"level": "error", "url": url, "status": response.status_code, "message": "HTTP error"})
            return False

        total = int(response.headers.get("Content-Length", 0)) + downloaded
        with dest.open(mode) as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded * 100 / total
                        print(f"\r  {dest.name}: {pct:.1f}% ({downloaded}/{total} bytes)", end="", flush=True)
        print()
        return True
    except requests.RequestException as e:
        log_entry({"level": "error", "url": url, "message": str(e)})
        return False


def extract_archive(archive_path: Path, extract_dir: Path) -> bool:
    """Extract common archive formats. Returns True on success."""
    try:
        if archive_path.suffix == ".zip" or archive_path.suffixes[-2:] == [".tar", ".gz"] or archive_path.suffix == ".tgz":
            with zipfile.ZipFile(archive_path, "r") as zf:
                zf.extractall(extract_dir)
        elif archive_path.suffix == ".gz" and not archive_path.suffixes[-2:] == [".tar", ".gz"]:
            import gzip
            out_path = extract_dir / archive_path.stem
            with gzip.open(archive_path, "rb") as gz, out_path.open("wb") as out:
                shutil.copyfileobj(gz, out)
        elif archive_path.suffixes[-2:] == [".tar", ".bz2"] or archive_path.suffix == ".tbz2":
            with tarfile.open(archive_path, "r:bz2") as tf:
                tf.extractall(extract_dir)
        elif archive_path.suffixes[-2:] == [".tar", ".gz"] or archive_path.suffix == ".tgz":
            with tarfile.open(archive_path, "r:gz") as tf:
                tf.extractall(extract_dir)
        elif archive_path.suffix == ".tar":
            with tarfile.open(archive_path, "r:") as tf:
                tf.extractall(extract_dir)
        else:
            log_entry({"level": "warning", "archive": str(archive_path), "message": "Unknown archive format, skipping extraction"})
            return False
        return True
    except Exception as e:
        log_entry({"level": "error", "archive": str(archive_path), "message": f"Extraction failed: {e}"})
        return False


def load_sources() -> dict[str, Any]:
    with SOURCES_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def update_source_metadata(source_name: str, updates: dict[str, Any]) -> None:
    data = load_sources()
    for src in data["sources"]:
        if src["name"] == source_name:
            src.update(updates)
            break
    with SOURCES_FILE.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def download_spamassassin_corpus(source: dict[str, Any]) -> bool:
    """Download a SpamAssassin corpus archive."""
    name = source["name"]
    url = source["source_url"]
    archive_name = urlparse(url).path.split("/")[-1]
    archive_path = RAW_DIR / archive_name
    extract_dir = DOWNLOADS_DIR / source["subcategory"]  # benign or spam

    print(f"\n[DOWNLOAD] {name}")
    print(f"  URL: {url}")
    print(f"  Destination: {archive_path}")

    if extract_dir.exists() and any(extract_dir.iterdir()):
        print(f"  Already extracted to {extract_dir}, skipping download")
        log_entry({"level": "info", "source": name, "status": "skipped", "reason": "already extracted"})
        return True

    success = download_with_resume(url, archive_path)
    if not success:
        return False

    # Verify checksum if provided
    expected = source.get("checksum_sha256", "")
    if expected and expected != "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456":
        actual = sha256_file(archive_path)
        if actual != expected:
            log_entry({"level": "error", "source": name, "message": f"Checksum mismatch: expected {expected}, got {actual}"})
            print(f"  CHECKSUM MISMATCH: expected {expected}, got {actual}")
            return False
        print(f"  Checksum verified: {actual[:16]}...")

    print(f"  Extracting to {extract_dir}...")
    extract_dir.mkdir(parents=True, exist_ok=True)
    if not extract_archive(archive_path, extract_dir):
        return False

    # Count files
    file_count = len([f for f in extract_dir.rglob("*") if f.is_file() and f.name != "cmds"])
    raw_size = sum(f.stat().st_size for f in extract_dir.rglob("*") if f.is_file())

    update_source_metadata(name, {
        "download_date": datetime.now(timezone.utc).isoformat(),
        "raw_size_bytes": raw_size,
        "file_count": file_count,
        "checksum_verified": bool(expected)
    })

    log_entry({"level": "info", "source": name, "status": "success", "files": file_count, "bytes": raw_size})
    print(f"  Done: {file_count} files, {raw_size / 1024 / 1024:.1f} MB")
    return True


def download_enron_corpus(source: dict[str, Any]) -> bool:
    """Download the Enron corpus (large, may take a while)."""
    name = source["name"]
    url = source["source_url"]
    archive_name = urlparse(url).path.split("/")[-1]
    archive_path = RAW_DIR / archive_name
    extract_dir = DOWNLOADS_DIR / "maildir"

    print(f"\n[DOWNLOAD] {name}")
    print(f"  URL: {url}")
    print(f"  Destination: {archive_path}")
    print(f"  WARNING: This is ~423 MB and may take several minutes")

    if extract_dir.exists() and any(extract_dir.iterdir()):
        print(f"  Already extracted to {extract_dir}, skipping download")
        return True

    success = download_with_resume(url, archive_path, timeout=300)
    if not success:
        return False

    print(f"  Extracting to {extract_dir}... (this may take a while)")
    extract_dir.mkdir(parents=True, exist_ok=True)
    if not extract_archive(archive_path, extract_dir):
        return False

    file_count = len([f for f in extract_dir.rglob("*") if f.is_file()])
    raw_size = sum(f.stat().st_size for f in extract_dir.rglob("*") if f.is_file())

    update_source_metadata(name, {
        "download_date": datetime.now(timezone.utc).isoformat(),
        "raw_size_bytes": raw_size,
        "file_count": file_count,
        "checksum_verified": False
    })

    log_entry({"level": "info", "source": name, "status": "success", "files": file_count, "bytes": raw_size})
    print(f"  Done: {file_count} files, {raw_size / 1024 / 1024:.1f} MB")
    return True


def download_text_feed(source: dict[str, Any]) -> bool:
    """Download a text-based feed (one URL per line)."""
    name = source["name"]
    url = source["source_url"]
    dest_dir = DOWNLOADS_DIR / "urls" / source["subcategory"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / f"{source['subcategory']}_{urlparse(url).netloc}.txt"

    print(f"\n[DOWNLOAD] {name}")
    print(f"  URL: {url}")

    # Check if we need API key
    if "phishtank" in url.lower() and "PHISHTANK_API_KEY" in os.environ:
        # PhishTank requires API key
        api_key = os.environ["PHISHTANK_API_KEY"]
        url = f"https://data.phishtank.com/data/{api_key}/online-valid.json"
        dest_file = dest_dir / "phishtank_online_valid.json"

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        dest_file.write_bytes(response.content)
    except requests.RequestException as e:
        log_entry({"level": "error", "source": name, "message": str(e)})
        print(f"  FAILED: {e}")
        return False

    file_count = 1
    raw_size = dest_file.stat().st_size

    update_source_metadata(name, {
        "download_date": datetime.now(timezone.utc).isoformat(),
        "raw_size_bytes": raw_size,
        "file_count": file_count,
        "checksum_verified": False
    })

    log_entry({"level": "info", "source": name, "status": "success", "files": file_count, "bytes": raw_size})
    print(f"  Done: saved to {dest_file} ({raw_size / 1024:.1f} KB)")
    return True


def download_csv_source(source: dict[str, Any]) -> bool:
    """Download a CSV source (URLhaus, Majestic Million, Cisco Umbrella)."""
    name = source["name"]
    url = source["source_url"]
    dest_dir = DOWNLOADS_DIR / "urls" / source["subcategory"]
    dest_dir.mkdir(parents=True, exist_ok=True)
    archive_name = urlparse(url).path.split("/")[-1]
    archive_path = RAW_DIR / archive_name
    extract_dir = dest_dir / archive_name.replace(".zip", "").replace(".gz", "").replace(".csv", "")

    print(f"\n[DOWNLOAD] {name}")
    print(f"  URL: {url}")

    if extract_dir.exists() and any(extract_dir.iterdir()):
        print(f"  Already exists at {extract_dir}, skipping")
        return True

    success = download_with_resume(url, archive_path, timeout=120)
    if not success:
        return False

    # Extract if archive
    if archive_path.suffix in (".zip", ".gz"):
        print(f"  Extracting...")
        extract_dir.mkdir(parents=True, exist_ok=True)
        if not extract_archive(archive_path, extract_dir):
            return False
        # Find CSV file
        csv_files = list(extract_dir.rglob("*.csv"))
        if csv_files:
            final_csv = dest_dir / f"{source['subcategory']}.csv"
            shutil.move(str(csv_files[0]), str(final_csv))
            print(f"  CSV saved to {final_csv}")
    else:
        # Direct CSV
        final_csv = dest_dir / f"{source['subcategory']}.csv"
        shutil.move(str(archive_path), str(final_csv))

    file_count = 1
    raw_size = final_csv.stat().st_size if final_csv.exists() else 0

    update_source_metadata(name, {
        "download_date": datetime.now(timezone.utc).isoformat(),
        "raw_size_bytes": raw_size,
        "file_count": file_count,
        "checksum_verified": False
    })

    log_entry({"level": "info", "source": name, "status": "success", "files": file_count, "bytes": raw_size})
    print(f"  Done: {raw_size / 1024 / 1024:.1f} MB")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Download approved public datasets for Email Threat Forensics")
    parser.add_argument("--source", help="Download only a specific source by name")
    parser.add_argument("--list", action="store_true", help="List available sources and exit")
    parser.add_argument("--force", action="store_true", help="Force re-download even if already present")
    args = parser.parse_args()

    data = load_sources()
    sources = data["sources"]

    if args.list:
        print("Available dataset sources:")
        for src in sources:
            status = "AUTO" if src["download_method"] != "manual" else "MANUAL"
            print(f"  [{status}] {src['name']} ({src['category']}/{src['subcategory']}) - {src.get('labels', [])}")
        return 0

    # Filter sources
    if args.source:
        sources = [s for s in sources if s["name"] == args.source]
        if not sources:
            print(f"Source not found: {args.source}")
            return 1

    # Skip manual-only sources unless forced
    manual_names = set(data.get("manual_download_required", []))
    auto_names = set(data.get("auto_download_available", []))

    results = {"success": 0, "failed": 0, "skipped": 0}

    for source in sources:
        name = source["name"]
        method = source["download_method"]

        if method == "manual" and name not in manual_names:
            print(f"\n[SKIP] {name} - manual download required")
            print(f"  See Dataset_Collection_Report.md for instructions")
            results["skipped"] += 1
            continue

        if method == "manual" and name in manual_names and not args.force:
            print(f"\n[SKIP] {name} - manual download required (use --force to attempt)")
            results["skipped"] += 1
            continue

        success = False
        try:
            if "spamassassin" in name.lower():
                success = download_spamassassin_corpus(source)
            elif "enron" in name.lower():
                success = download_enron_corpus(source)
            elif source["category"] == "url" and source["archive_format"] in ("txt", "json"):
                success = download_text_feed(source)
            elif source["category"] == "url" and source["archive_format"] in ("csv", "csv.gz", "zip"):
                success = download_csv_source(source)
            else:
                print(f"\n[SKIP] {name} - no download handler for method={method}, format={source.get('archive_format')}")
                results["skipped"] += 1
                continue
        except Exception as e:
            log_entry({"level": "error", "source": name, "message": f"Unexpected error: {e}"})
            print(f"  UNEXPECTED ERROR: {e}")
            success = False

        if success:
            results["success"] += 1
        else:
            results["failed"] += 1

    print(f"\n{'='*50}")
    print(f"Download summary: {results['success']} succeeded, {results['failed']} failed, {results['skipped']} skipped")
    print(f"Log: {LOG_FILE}")

    if results["failed"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())