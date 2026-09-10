"""Compatibility entry point for file-based forensic analysis.

The active application accepts bytes through ``AnalysisService``.  This module
keeps the historical ``parse_email(path)`` API working for scripts without
maintaining a second, divergent analysis pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from Backend.services.analysis_service import AnalysisService
from Backend.services.case_store import CaseStore


PROJECT_ROOT = Path(__file__).resolve().parent


def parse_email(file_path: str | Path) -> dict[str, Any]:
    """Analyze an RFC822 file with the unified forensic engine."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Email file not found: {path}")
    store = CaseStore(PROJECT_ROOT / "Backend" / "data" / "cases.sqlite3")
    return AnalysisService(PROJECT_ROOT, store).analyze(path.read_bytes(), path.name)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyze an RFC822 .eml file.")
    parser.add_argument("email", type=Path)
    args = parser.parse_args()
    print(json.dumps(parse_email(args.email), indent=2, ensure_ascii=False))
