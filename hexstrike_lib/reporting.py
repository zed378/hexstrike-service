"""Penulisan laporan (JSON + Markdown) dan keputusan gate berdasarkan severity."""

import json
import os
from typing import Any, Dict, List, Optional

from .findings import counts_by_severity, now_iso
from .logging_util import make_log
from .severity import SEVERITY_ORDER, rank

log = make_log()


def write_reports(kind: str, target: str, findings: List[Dict[str, str]],
                  report_dir: str, ai_text: Optional[str]) -> Dict[str, Any]:
    os.makedirs(report_dir, exist_ok=True)
    counts = counts_by_severity(findings)
    summary = {
        "kind": kind,
        "target": target,
        "generated_at": now_iso(),
        "counts": counts,
        "total": len(findings),
        "findings": findings,
    }
    json_path = os.path.join(report_dir, f"hexstrike-{kind}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    md_path = os.path.join(report_dir, f"hexstrike-{kind}.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(f"# HexStrike {kind} report\n\n")
        fh.write(f"- Target: `{target}`\n- Generated: {summary['generated_at']}\n")
        fh.write(f"- Total findings: **{len(findings)}**\n\n")
        fh.write("| severity | count |\n|---|---|\n")
        for s in reversed(SEVERITY_ORDER):
            fh.write(f"| {s} | {counts[s]} |\n")
        fh.write("\n## Top findings\n\n")
        for f in sorted(findings, key=lambda x: -rank(x["severity"]))[:50]:
            fh.write(f"- **[{f['severity'].upper()}]** ({f['tool']}) {f['title']} — `{f['location']}`\n")
        if ai_text:
            fh.write("\n## AI triage (advisory)\n\n")
            fh.write(ai_text + "\n")

    log(f"📝 Laporan: {json_path} , {md_path}")
    return summary


def gate(counts: Dict[str, int], fail_on: str) -> int:
    """Kembalikan 1 bila ada temuan >= fail_on, else 0."""
    threshold = rank(fail_on)
    triggered = [s for s in SEVERITY_ORDER if rank(s) >= threshold and counts.get(s, 0) > 0]
    if triggered:
        total = sum(counts.get(s, 0) for s in triggered)
        log(f"❌ GATE GAGAL: {total} temuan >= '{fail_on}' (severity: {', '.join(triggered)})")
        return 1
    log(f"✅ GATE LULUS: tidak ada temuan >= '{fail_on}'")
    return 0
