"""Renderer HTML dashboard metrik (self-contained, tanpa dependency eksternal).
Membaca agregat dari db.py; tidak menyentuh SQLite langsung."""

import html
from typing import Optional

from .config import DB_PATH as DEFAULT_DB
from .db import get_metrics, get_reports_by_id
from .severity import SEV_COLOR, SEVERITIES


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


def render_report_detail(db_path: str = DEFAULT_DB, ident: str = "", token: Optional[str] = None) -> str:
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
