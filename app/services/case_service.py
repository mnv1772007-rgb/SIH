"""
app/services/case_service.py
Forensic Case Dossier persistence and management.
SIH 26106 - IronPulse | Role 1
"""
import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CaseService:
    """Manages persistence and retrieval of analyzed forensic cases."""

    def __init__(self, cases_dir: Optional[Path] = None):
        if cases_dir is None:
            base_dir = Path(__file__).resolve().parent.parent.parent
            self.cases_dir = base_dir / "data" / "cases"
        else:
            self.cases_dir = Path(cases_dir)
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    def generate_case_id(self) -> str:
        """Generate a deterministic, investigator-friendly case identifier."""
        now_str = datetime.now(timezone.utc).strftime("%Y%m%d")
        rand_suffix = os.urandom(3).hex().upper()
        return f"CASE-{now_str}-{rand_suffix}"

    def save_case(
        self,
        case_id: str,
        filename: str,
        sha256: str,
        verdict: str,
        risk_score: int,
        risk_level: str,
        full_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Save a complete forensic analysis dossier to disk."""
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        now_iso = datetime.now(timezone.utc).isoformat()

        case_record = {
            "case_id": case_id,
            "filename": filename,
            "sha256": sha256,
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "created_at": now_iso,
            "updated_at": now_iso,
            "data": full_result,
        }

        case_path = self.cases_dir / f"{case_id}.json"
        try:
            with open(case_path, "w", encoding="utf-8") as f:
                json.dump(case_record, f, indent=2, default=str)
            logger.info("Forensic case saved: %s", case_path)
        except Exception as e:
            logger.error("Failed to save forensic case %s: %s", case_id, e)

        return case_record

    def get_case(self, case_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a stored forensic case by case_id."""
        case_path = self.cases_dir / f"{case_id}.json"
        if not case_path.exists():
            return None
        try:
            with open(case_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("Error reading case %s: %s", case_id, e)
            return None

    def list_cases(self, limit: int = 50) -> list[dict[str, Any]]:
        """List recently analyzed cases (metadata summary)."""
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        cases: list[dict[str, Any]] = []

        for p in self.cases_dir.glob("CASE-*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    rec = json.load(f)
                cases.append({
                    "case_id": rec.get("case_id", p.stem),
                    "filename": rec.get("filename", "Unknown"),
                    "sha256": rec.get("sha256", ""),
                    "verdict": rec.get("verdict", "N/A"),
                    "risk_score": rec.get("risk_score", 0),
                    "risk_level": rec.get("risk_level", "LOW"),
                    "created_at": rec.get("created_at", ""),
                })
            except Exception as e:
                logger.warning("Skipping corrupted case file %s: %s", p, e)

        # Sort newest first
        cases.sort(key=lambda c: c.get("created_at", ""), reverse=True)
        return cases[:limit]


# Global singleton instance
case_service = CaseService()
