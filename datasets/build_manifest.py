"""Inventory approved local corpora without downloading or relabelling data."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
DOWNLOADS = ROOT / "downloads"
SOURCES: dict[str, dict[str, Any]] = {
    "easy_ham": {
        "name": "Apache SpamAssassin Public Corpus: easy_ham",
        "source_url": "https://spamassassin.apache.org/old/publiccorpus/",
        "label_scheme": "benign (non-spam)",
        "category": "email",
        "license_or_usage": "Corpus readme states message copyright remains with original senders; use for spam-filter research/testing and do not inject samples into live mail systems.",
    },
    "hard_ham": {
        "name": "Apache SpamAssassin Public Corpus: hard_ham",
        "source_url": "https://spamassassin.apache.org/old/publiccorpus/",
        "label_scheme": "benign (non-spam, spam-like formatting)",
        "category": "email",
        "license_or_usage": "Corpus readme states message copyright remains with original senders; use for spam-filter research/testing and do not inject samples into live mail systems.",
    },
    "spam": {
        "name": "Apache SpamAssassin Public Corpus: spam",
        "source_url": "https://spamassassin.apache.org/old/publiccorpus/",
        "label_scheme": "spam",
        "category": "email",
        "license_or_usage": "Corpus readme states message copyright remains with original senders; use for spam-filter research/testing and do not inject samples into live mail systems.",
    },
    "spam_2": {
        "name": "Apache SpamAssassin Public Corpus: spam_2",
        "source_url": "https://spamassassin.apache.org/old/publiccorpus/",
        "label_scheme": "spam",
        "category": "email",
        "license_or_usage": "Corpus readme states message copyright remains with original senders; use for spam-filter research/testing and do not inject samples into live mail systems.",
    },
    "maildir": {
        "name": "CMU CALO Enron Email Dataset subset",
        "source_url": "https://www.cs.cmu.edu/~enron/",
        "label_scheme": "unlabelled reference corpus; excluded from supervised spam baseline",
        "category": "email",
        "license_or_usage": "Research-use corpus; source cautions users to be sensitive to privacy and notes redactions/integrity limitations.",
    },
}


def _inventory(directory: Path) -> dict[str, Any]:
    # Win32 normally strips a trailing period before ``stat``. The Enron subset
    # contains mail files such as ``1.``, so use the extended-length path form
    # while walking and statting. This is an inventory-only compatibility fix;
    # it neither rewrites nor relabels the corpus.
    root = str(directory.resolve())
    walk_root = f"\\\\?\\{root}" if os.name == "nt" and not root.startswith("\\\\?\\") else root
    digest = hashlib.sha256()
    total = 0
    file_count = 0
    entries: list[tuple[str, int]] = []
    for current_directory, _, names in os.walk(walk_root):
        for name in names:
            if name == "cmds":
                continue
            filename = os.path.join(current_directory, name)
            try:
                relative = os.path.relpath(filename, walk_root).replace("\\", "/")
                entries.append((relative, os.path.getsize(filename)))
            except OSError:
                # An inventory should remain useful if one local filesystem
                # entry is unreadable; the processing issue log is the right
                # place for detailed sample-level handling.
                continue
    for relative, size in sorted(entries):
        file_count += 1
        total += size
        digest.update(relative.encode())
        digest.update(str(size).encode())
    return {"files": file_count, "bytes": total, "inventory_sha256": digest.hexdigest()}


def build_manifest() -> dict[str, Any]:
    entries = []
    for name, metadata in SOURCES.items():
        directory = DOWNLOADS / name
        if not directory.is_dir():
            continue
        entry = {"directory": str(directory.relative_to(ROOT)).replace("\\", "/"), **metadata, **_inventory(directory)}
        entry["download_date"] = "unknown; archive was already present locally when this manifest was generated"
        entries.append(entry)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "Inventory of local public email corpora; no private collection or network download was performed.",
        "deduplication": "Training additionally performs exact SHA-256 deduplication on normalized message text before splitting.",
        "sources": entries,
        "total_files": sum(entry["files"] for entry in entries),
        "total_bytes": sum(entry["bytes"] for entry in entries),
        "url_data": "No labelled URL corpus is currently staged. URL reference directories are deliberately empty rather than populated with assumed-safe domains.",
    }


if __name__ == "__main__":
    output = ROOT / "manifest.json"
    output.write_text(json.dumps(build_manifest(), indent=2), encoding="utf-8")
    print(output)
