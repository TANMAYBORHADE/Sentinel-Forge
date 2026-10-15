"""SQLite storage for scans and findings (Rule 9: keep history of every scan)."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    tool_version TEXT NOT NULL,
    target_url   TEXT,
    src_path     TEXT,
    status       TEXT NOT NULL DEFAULT 'RUNNING',
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    fingerprint   TEXT NOT NULL,
    check_id      TEXT NOT NULL,
    title         TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    TEXT NOT NULL,
    status        TEXT NOT NULL,
    endpoint      TEXT,
    file          TEXT,
    line          INTEGER,
    description   TEXT,
    fix           TEXT,
    evidence_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str):
        self.path = str(path)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def start_scan(self, target_url: Optional[str], src_path: Optional[str], tool_version: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (started_at, tool_version, target_url, src_path) VALUES (?,?,?,?)",
            (_now(), tool_version, target_url, src_path))
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, summary: dict, status: str = "COMPLETED") -> None:
        self.conn.execute(
            "UPDATE scans SET finished_at=?, status=?, summary_json=? WHERE id=?",
            (_now(), status, json.dumps(summary), scan_id))
        self.conn.commit()

    def save_finding(self, scan_id: int, f: Finding) -> None:
        # Evidence is stored redacted: tokens, cookies and passwords never hit the DB.
        evidence = json.dumps([e.to_dict(redact=True) for e in f.evidence])
        self.conn.execute(
            """INSERT INTO findings (scan_id, fingerprint, check_id, title, category, severity,
               confidence, status, endpoint, file, line, description, fix, evidence_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan_id, f.fingerprint, f.id, f.title, f.category, f.severity.value,
             f.confidence.value, f.status.value, f.endpoint, f.file, f.line,
             f.description, f.fix, evidence))
        self.conn.commit()

    def get_scan(self, scan_id: int) -> Optional[dict]:
        row = self.conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def get_findings(self, scan_id: int) -> list:
        rows = self.conn.execute("SELECT * FROM findings WHERE scan_id=? ORDER BY id", (scan_id,))
        return [dict(r) for r in rows]

    def count_scans(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
