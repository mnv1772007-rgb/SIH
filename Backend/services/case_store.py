"""Small SQLite-backed case store. Raw RFC822 email content is never persisted."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class CaseStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    email_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    subject TEXT,
                    sender TEXT,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_risk ON cases(risk_level)"
            )

    def save(self, report: dict[str, Any]) -> None:
        case = report["case"]
        verdict = report["verdict"]
        email = report["email"]
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO cases (
                    case_id, email_hash, created_at, updated_at, subject, sender,
                    risk_score, risk_level, classification, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    subject=excluded.subject,
                    sender=excluded.sender,
                    risk_score=excluded.risk_score,
                    risk_level=excluded.risk_level,
                    classification=excluded.classification,
                    report_json=excluded.report_json
                """,
                (
                    case["case_id"],
                    case["email_hash"],
                    case["analysis_timestamp"],
                    now,
                    email.get("subject"),
                    email.get("from"),
                    verdict["risk_score"],
                    verdict["risk_level"],
                    verdict["classification"],
                    payload,
                ),
            )

    def get(self, case_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT report_json FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
        return json.loads(row["report_json"]) if row else None

    def delete(self, case_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
        return cursor.rowcount > 0

    def list(
        self, query: str | None = None, risk_level: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[str] = []
        if query:
            clauses.append("(subject LIKE ? OR sender LIKE ? OR case_id LIKE ?)")
            wildcard = f"%{query}%"
            parameters.extend([wildcard, wildcard, wildcard])
        if risk_level:
            clauses.append("risk_level = ?")
            parameters.append(risk_level.upper())
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            "SELECT case_id, email_hash, created_at, updated_at, subject, sender, "
            "risk_score, risk_level, classification FROM cases"
            f"{where} ORDER BY updated_at DESC"
        )
        with self._connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [dict(row) for row in rows]

    def all_reports(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT report_json FROM cases").fetchall()
        return [json.loads(row["report_json"]) for row in rows]

    def stats(self) -> dict[str, Any]:
        with self._connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            average = connection.execute(
                "SELECT COALESCE(AVG(risk_score), 0) FROM cases"
            ).fetchone()[0]
            levels = connection.execute(
                "SELECT risk_level, COUNT(*) AS count FROM cases GROUP BY risk_level"
            ).fetchall()
        return {
            "total_cases": total,
            "average_risk_score": round(float(average), 1),
            "by_risk_level": {row["risk_level"]: row["count"] for row in levels},
        }
