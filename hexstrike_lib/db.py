"""Penyimpanan report ke SQLite (stdlib). Aman lintas thread: koneksi per-operasi + WAL.

Skema:
  reports(run_id PK, job_id, kind, target, fail_on, status, gate_failed,
          exit_code, total, critical, high, medium, low, info,
          authenticated, started_at, finished_at, duration_sec)
  findings(id PK, run_id FK, tool, severity, title, location)
"""

import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config import DB_PATH as DEFAULT_DB
from .severity import SEVERITIES

_MAX_FINDINGS_STORED = 500


def _connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(db_path: str = DEFAULT_DB) -> None:
    with _connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS reports (
                run_id       TEXT PRIMARY KEY,
                job_id       TEXT,
                kind         TEXT,
                target       TEXT,
                fail_on      TEXT,
                status       TEXT,
                gate_failed  INTEGER,
                exit_code    INTEGER,
                total        INTEGER,
                critical     INTEGER,
                high         INTEGER,
                medium       INTEGER,
                low          INTEGER,
                info         INTEGER,
                authenticated INTEGER,
                started_at   TEXT,
                finished_at  TEXT,
                duration_sec REAL
            );
            CREATE INDEX IF NOT EXISTS idx_reports_finished ON reports(finished_at);
            CREATE INDEX IF NOT EXISTS idx_reports_kind ON reports(kind);
            CREATE TABLE IF NOT EXISTS findings (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id   TEXT,
                tool     TEXT,
                severity TEXT,
                title    TEXT,
                location TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            """
        )


def _duration(started_at: Optional[str], finished_at: Optional[str]) -> Optional[float]:
    try:
        s = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        f = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
        return round((f - s).total_seconds(), 1)
    except Exception:  # noqa: BLE001
        return None


def save_report(
    db_path: str,
    run_id: str,
    job_id: str,
    kind: str,
    target: str,
    fail_on: str,
    status: str,
    gate_failed: bool,
    exit_code: int,
    counts: Dict[str, int],
    findings: List[Dict[str, str]],
    started_at: Optional[str],
    finished_at: Optional[str],
    authenticated: bool = False,
) -> None:
    total = sum(int(counts.get(s, 0)) for s in SEVERITIES)
    dur = _duration(started_at, finished_at)
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO reports
              (run_id, job_id, kind, target, fail_on, status, gate_failed, exit_code,
               total, critical, high, medium, low, info, authenticated,
               started_at, finished_at, duration_sec)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                run_id, job_id, kind, target, fail_on, status,
                1 if gate_failed else 0, int(exit_code), total,
                int(counts.get("critical", 0)), int(counts.get("high", 0)),
                int(counts.get("medium", 0)), int(counts.get("low", 0)),
                int(counts.get("info", 0)), 1 if authenticated else 0,
                started_at, finished_at, dur,
            ),
        )
        conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
        rows = [
            (run_id, f.get("tool", ""), f.get("severity", "info"),
             (f.get("title", "") or "")[:300], (f.get("location", "") or "")[:300])
            for f in (findings or [])[:_MAX_FINDINGS_STORED]
        ]
        if rows:
            conn.executemany(
                "INSERT INTO findings (run_id, tool, severity, title, location) VALUES (?,?,?,?,?)",
                rows,
            )


def get_metrics(db_path: str = DEFAULT_DB, recent_limit: int = 25) -> Dict[str, Any]:
    with _connect(db_path) as conn:
        agg = conn.execute(
            """
            SELECT
              COUNT(*) AS reports,
              SUM(CASE WHEN kind='code-scan' THEN 1 ELSE 0 END) AS code_scans,
              SUM(CASE WHEN kind='pentest'  THEN 1 ELSE 0 END) AS pentests,
              SUM(gate_failed) AS gate_failed,
              COALESCE(SUM(critical),0) AS critical,
              COALESCE(SUM(high),0)     AS high,
              COALESCE(SUM(medium),0)   AS medium,
              COALESCE(SUM(low),0)      AS low,
              COALESCE(SUM(info),0)     AS info,
              COALESCE(SUM(total),0)    AS total_findings
            FROM reports
            """
        ).fetchone()
        recent = conn.execute(
            "SELECT * FROM reports ORDER BY finished_at DESC LIMIT ?", (recent_limit,)
        ).fetchall()
        by_day = conn.execute(
            """
            SELECT substr(finished_at,1,10) AS day,
                   COUNT(*) AS runs,
                   COALESCE(SUM(critical+high),0) AS crit_high
            FROM reports
            WHERE finished_at IS NOT NULL
            GROUP BY day ORDER BY day DESC LIMIT 14
            """
        ).fetchall()
        top_targets = conn.execute(
            """
            SELECT target, COUNT(*) AS runs, COALESCE(SUM(total),0) AS findings
            FROM reports GROUP BY target ORDER BY findings DESC LIMIT 8
            """
        ).fetchall()

    reports = agg["reports"] or 0
    gate_failed = agg["gate_failed"] or 0
    return {
        "totals": {
            "reports": reports,
            "code_scans": agg["code_scans"] or 0,
            "pentests": agg["pentests"] or 0,
            "gate_failed": gate_failed,
            "gate_passed": reports - gate_failed,
            "pass_rate": round(100.0 * (reports - gate_failed) / reports, 1) if reports else 0.0,
            "total_findings": agg["total_findings"] or 0,
        },
        "severity": {s: agg[s] or 0 for s in SEVERITIES},
        "recent": [dict(r) for r in recent],
        "by_day": [dict(r) for r in reversed(by_day)],
        "top_targets": [dict(r) for r in top_targets],
    }


def get_report(db_path: str, run_id: str) -> Optional[Dict[str, Any]]:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM reports WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            return None
        findings = conn.execute(
            "SELECT tool, severity, title, location FROM findings WHERE run_id = ?", (run_id,)
        ).fetchall()
    out = dict(row)
    out["findings"] = [dict(f) for f in findings]
    return out


def get_reports_by_id(db_path: str, ident: str) -> List[Dict[str, Any]]:
    """Cari report berdasarkan run_id (persis) ATAU job_id (bisa >1 utk action=both)."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE run_id = ? OR job_id = ? ORDER BY finished_at",
            (ident, ident),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for row in rows:
            d = dict(row)
            d["findings"] = [
                dict(f) for f in conn.execute(
                    "SELECT tool, severity, title, location FROM findings WHERE run_id = ?",
                    (row["run_id"],),
                ).fetchall()
            ]
            out.append(d)
    return out
