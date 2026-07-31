#!/usr/bin/env python3
"""
HexStrike AI — SQLite report store + metric dashboard renderer
==============================================================

Menyimpan hasil tiap job scan/pentest ke SQLite dan menyediakan agregat metrik
untuk ditampilkan sebagai dashboard. Memakai `sqlite3` bawaan (tanpa dependency
tambahan). Aman dipakai lintas thread: koneksi dibuka per-operasi + WAL mode.

Skema:
  reports(run_id PK, job_id, kind, target, fail_on, status, gate_failed,
          exit_code, total, critical, high, medium, low, info,
          authenticated, started_at, finished_at, duration_sec)
  findings(id PK, run_id FK, tool, severity, title, location)
"""

import html
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": "#b3123b",
    "high": "#e5484d",
    "medium": "#f5a623",
    "low": "#e8c400",
    "info": "#3aa0ff",
}
DEFAULT_DB = os.environ.get(
    "HEXSTRIKE_DB_PATH",
    os.path.join(os.environ.get("HEXSTRIKE_REPORT_ROOT", "hexstrike-reports"), "hexstrike.db"),
)
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


# --------------------------------------------------------------------------- #
# Dashboard HTML (self-contained, tanpa dependency eksternal)
# --------------------------------------------------------------------------- #
def _bar(label: str, value: int, maximum: int, color: str) -> str:
    pct = int(100 * value / maximum) if maximum else 0
    return (
        f'<div class="bar-row"><span class="bar-label">{html.escape(label)}</span>'
        f'<span class="bar-track"><span class="bar-fill" style="width:{pct}%;background:{color}"></span></span>'
        f'<span class="bar-val">{value}</span></div>'
    )


def _sev_badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "#888")
    return f'<span class="pill" style="background:{c}22;color:{c};border:1px solid {c}55">{html.escape(sev.upper())}</span>'


def render_dashboard(db_path: str = DEFAULT_DB, token: Optional[str] = None) -> str:
    q = f"?token={html.escape(token, quote=True)}" if token else ""
    m = get_metrics(db_path)
    t = m["totals"]
    sev = m["severity"]
    sev_max = max(sev.values()) if any(sev.values()) else 1

    sev_bars = "".join(_bar(s, sev[s], sev_max, SEV_COLOR[s]) for s in SEVERITIES)

    day_max = max((d["runs"] for d in m["by_day"]), default=1) or 1
    day_bars = ""
    for d in m["by_day"]:
        h = int(90 * d["runs"] / day_max)
        day_bars += (
            f'<div class="day"><span class="day-bar" style="height:{h}px" '
            f'title="{d["runs"]} runs, {d["crit_high"]} crit+high"></span>'
            f'<span class="day-lbl">{html.escape(d["day"][5:])}</span></div>'
        )

    rows = ""
    for r in m["recent"]:
        gate = ('<span class="pill pill-fail">FAILED</span>' if r["gate_failed"]
                else '<span class="pill pill-pass">PASSED</span>')
        dur = f'{r["duration_sec"]:.0f}s' if r.get("duration_sec") else "—"
        rid = html.escape(str(r.get("run_id") or ""))
        rows += (
            "<tr>"
            f'<td><a class="lnk" href="/dashboard/{rid}{q}">{html.escape(str(r.get("finished_at") or ""))}</a></td>'
            f'<td>{html.escape(r.get("kind") or "")}</td>'
            f'<td class="tgt" title="{html.escape(r.get("target") or "")}">{html.escape((r.get("target") or "")[:48])}</td>'
            f'<td>{gate}</td>'
            f'<td>{r.get("total",0)}</td>'
            f'<td style="color:{SEV_COLOR["critical"]}">{r.get("critical",0)}</td>'
            f'<td style="color:{SEV_COLOR["high"]}">{r.get("high",0)}</td>'
            f'<td style="color:{SEV_COLOR["medium"]}">{r.get("medium",0)}</td>'
            f'<td>{dur}</td>'
            "</tr>"
        )
    if not rows:
        rows = '<tr><td colspan="9" style="text-align:center;opacity:.6;padding:24px">Belum ada report. Jalankan scan/pentest.</td></tr>'

    tops = ""
    tmax = max((x["findings"] for x in m["top_targets"]), default=1) or 1
    for x in m["top_targets"]:
        tops += _bar((x["target"] or "-")[:40], x["findings"], tmax, "#6b7bff")
    if not tops:
        tops = '<div style="opacity:.6">—</div>'

    return f"""<!doctype html>
<html lang="id"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>HexStrike — Report Dashboard</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--line:#232a34;--fg:#e6edf3;--muted:#8b949e}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px}}
h1{{font-size:20px;margin:0 0 4px}} .sub{{color:var(--muted);margin-bottom:20px}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}}
.kpi{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}}
.kpi .n{{font-size:26px;font-weight:700}} .kpi .l{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}}
@media(max-width:820px){{.grid{{grid-template-columns:1fr}}}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}}
.card h2{{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 12px}}
.bar-row{{display:flex;align-items:center;gap:10px;margin:6px 0}}
.bar-label{{width:110px;font-size:12px;color:var(--muted);text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.bar-track{{flex:1;background:#0b0f14;border-radius:6px;height:12px;overflow:hidden}}
.bar-fill{{display:block;height:100%}} .bar-val{{width:44px;text-align:right;font-variant-numeric:tabular-nums}}
.days{{display:flex;align-items:flex-end;gap:6px;height:110px}}
.day{{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:4px}}
.day-bar{{width:100%;background:#3aa0ff;border-radius:3px 3px 0 0;min-height:2px}}
.day-lbl{{font-size:10px;color:var(--muted)}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:12px}}
th{{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.03em}}
.tgt{{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.pill{{padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600}}
.pill-pass{{background:#1f6f3f33;color:#3fb950;border:1px solid #3fb95055}}
.pill-fail{{background:#b3123b22;color:#e5484d;border:1px solid #e5484d55}}
a.lnk{{color:#58a6ff;text-decoration:none}} a.lnk:hover{{text-decoration:underline}}
</style></head>
<body><div class="wrap">
  <h1>🛡️ HexStrike — Report Dashboard</h1>
  <div class="sub">Auto-refresh 30s · total {t['reports']} report · pass rate {t['pass_rate']}%</div>

  <div class="kpis">
    <div class="kpi"><div class="n">{t['reports']}</div><div class="l">Total Reports</div></div>
    <div class="kpi"><div class="n">{t['code_scans']}</div><div class="l">Code Scans</div></div>
    <div class="kpi"><div class="n">{t['pentests']}</div><div class="l">Pentests</div></div>
    <div class="kpi"><div class="n" style="color:#3fb950">{t['gate_passed']}</div><div class="l">Gate Passed</div></div>
    <div class="kpi"><div class="n" style="color:#e5484d">{t['gate_failed']}</div><div class="l">Gate Failed</div></div>
    <div class="kpi"><div class="n">{t['total_findings']}</div><div class="l">Total Findings</div></div>
  </div>

  <div class="grid">
    <div class="card"><h2>Findings by severity</h2>{sev_bars}</div>
    <div class="card"><h2>Runs — last 14 days</h2><div class="days">{day_bars or '<div style="opacity:.6">—</div>'}</div></div>
  </div>

  <div class="card" style="margin-bottom:16px"><h2>Top targets by findings</h2>{tops}</div>

  <div class="card"><h2>Recent reports</h2>
    <div style="overflow-x:auto"><table>
      <tr><th>Finished</th><th>Kind</th><th>Target</th><th>Gate</th><th>Total</th>
          <th>Crit</th><th>High</th><th>Med</th><th>Dur</th></tr>
      {rows}
    </table></div>
  </div>
</div></body></html>"""


_DETAIL_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--line:#232a34;--fg:#e6edf3;--muted:#8b949e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
a.lnk{color:#58a6ff;text-decoration:none} a.lnk:hover{text-decoration:underline}
h1{font-size:19px;margin:0 0 4px} .sub{color:var(--muted);margin-bottom:18px;word-break:break-all}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:12px 0 18px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .n{font-size:22px;font-weight:700} .kpi .l{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.card h2{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 12px}
table{width:100%;border-collapse:collapse} th,td{padding:7px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:12px;vertical-align:top}
th{color:var(--muted);text-transform:uppercase;font-size:11px}
.pill{padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600}
.pill-pass{background:#1f6f3f33;color:#3fb950;border:1px solid #3fb95055}
.pill-fail{background:#b3123b22;color:#e5484d;border:1px solid #e5484d55}
code{background:#0b0f14;padding:1px 5px;border-radius:4px;font-size:12px;word-break:break-all}
"""


def render_report_detail(db_path: str, ident: str, token: Optional[str] = None) -> str:
    q = f"?token={html.escape(token, quote=True)}" if token else ""
    reports = get_reports_by_id(db_path, ident)
    head = (
        f'<!doctype html><html lang="id"><head><meta charset="utf-8">'
        f'<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>HexStrike — Report {html.escape(ident)}</title><style>{_DETAIL_CSS}</style></head><body><div class="wrap">'
        f'<a class="lnk" href="/dashboard{q}">&larr; Back to dashboard</a>'
    )
    if not reports:
        return head + (
            f'<h1 style="margin-top:16px">Report tidak ditemukan</h1>'
            f'<div class="sub">id: <code>{html.escape(ident)}</code></div></div></body></html>'
        )

    sections = ""
    for r in reports:
        gate = ('<span class="pill pill-fail">GATE FAILED</span>' if r["gate_failed"]
                else '<span class="pill pill-pass">GATE PASSED</span>')
        dur = f'{r["duration_sec"]:.0f}s' if r.get("duration_sec") else "—"
        frows = ""
        for f in sorted(r["findings"], key=lambda x: -(SEVERITIES[::-1].index(x["severity"]) if x["severity"] in SEVERITIES else 0)):
            frows += (
                "<tr>"
                f"<td>{_sev_badge(f['severity'])}</td>"
                f"<td>{html.escape(f.get('tool',''))}</td>"
                f"<td>{html.escape(f.get('title',''))}</td>"
                f"<td><code>{html.escape(f.get('location',''))}</code></td>"
                "</tr>"
            )
        if not frows:
            frows = '<tr><td colspan="4" style="opacity:.6;padding:16px">Tidak ada temuan.</td></tr>'
        sections += f"""
        <h1 style="margin-top:18px">{html.escape(r['kind'])} · {gate}</h1>
        <div class="sub">run_id <code>{html.escape(r['run_id'])}</code> · target <code>{html.escape(r.get('target') or '')}</code>
             · fail_on {html.escape(r.get('fail_on') or '')} · finished {html.escape(str(r.get('finished_at') or ''))} · {dur}</div>
        <div class="kpis">
          <div class="kpi"><div class="n">{r.get('total',0)}</div><div class="l">Total</div></div>
          <div class="kpi"><div class="n" style="color:{SEV_COLOR['critical']}">{r.get('critical',0)}</div><div class="l">Critical</div></div>
          <div class="kpi"><div class="n" style="color:{SEV_COLOR['high']}">{r.get('high',0)}</div><div class="l">High</div></div>
          <div class="kpi"><div class="n" style="color:{SEV_COLOR['medium']}">{r.get('medium',0)}</div><div class="l">Medium</div></div>
          <div class="kpi"><div class="n" style="color:{SEV_COLOR['low']}">{r.get('low',0)}</div><div class="l">Low</div></div>
          <div class="kpi"><div class="n" style="color:{SEV_COLOR['info']}">{r.get('info',0)}</div><div class="l">Info</div></div>
        </div>
        <div class="card"><h2>Findings</h2><div style="overflow-x:auto"><table>
          <tr><th>Severity</th><th>Tool</th><th>Title</th><th>Location</th></tr>{frows}
        </table></div></div>
        """
    return head + sections + "</div></body></html>"
