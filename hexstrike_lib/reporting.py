"""Penulisan laporan (JSON + Markdown) dan keputusan gate berdasarkan severity."""

import json
import os
from typing import Any, Dict, List, Optional

from .findings import counts_by_severity, now_iso
from .logging_util import make_log
from .sarif import write_sarif
from .severity import SEVERITY_ORDER, rank

log = make_log()


def write_reports(kind: str, target: str, findings: List[Dict[str, str]],
                  report_dir: str, ai_text: Optional[str],
                  waived: Optional[List[Dict[str, str]]] = None,
                  new_findings: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """Tulis laporan JSON+MD. `findings` = active (sudah difilter baseline) -> dipakai utk gate.

    `waived`      : temuan yang diredam baseline/allowlist (informatif, tak menggate).
    `new_findings`: subset `findings` yang BELUM muncul di run sebelumnya (diff), bila dihitung.
                    None berarti diff tidak dihitung (mis. belum ada histori run sebelumnya).
    """
    os.makedirs(report_dir, exist_ok=True)
    waived = waived or []
    counts = counts_by_severity(findings)
    summary = {
        "kind": kind,
        "target": target,
        "generated_at": now_iso(),
        "counts": counts,
        "total": len(findings),
        "findings": findings,
        "waived_count": len(waived),
        "waived_findings": waived,
        "new_count": len(new_findings) if new_findings is not None else None,
        "new_findings": new_findings,
    }
    json_path = os.path.join(report_dir, f"hexstrike-{kind}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    new_fps = {id(f) for f in new_findings} if new_findings is not None else None

    md_path = os.path.join(report_dir, f"hexstrike-{kind}.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(f"# HexStrike {kind} report\n\n")
        fh.write(f"- Target: `{target}`\n- Generated: {summary['generated_at']}\n")
        fh.write(f"- Total findings (aktif): **{len(findings)}**\n")
        if waived:
            fh.write(f"- Diredam baseline/allowlist: **{len(waived)}** (lihat bagian terpisah di bawah)\n")
        if new_findings is not None:
            fh.write(f"- Baru dibanding run sebelumnya: **{len(new_findings)}** "
                     f"(existing: {len(findings) - len(new_findings)})\n")
        fh.write("\n| severity | count |\n|---|---|\n")
        for s in reversed(SEVERITY_ORDER):
            fh.write(f"| {s} | {counts[s]} |\n")
        fh.write("\n## Top findings\n\n")
        for f in sorted(findings, key=lambda x: -rank(x["severity"]))[:50]:
            tag = " 🆕" if new_fps is not None and id(f) in new_fps else ""
            fh.write(f"- **[{f['severity'].upper()}]**{tag} ({f['tool']}) {f['title']} — `{f['location']}`\n")
        if waived:
            fh.write("\n## Diredam baseline/allowlist (tidak menggate)\n\n")
            for f in waived[:50]:
                reason = f.get("_waived_reason") or "-"
                fh.write(f"- **[{f['severity'].upper()}]** ({f['tool']}) {f['title']} — `{f['location']}` "
                         f"(alasan: {reason})\n")
        if ai_text:
            fh.write("\n## AI triage (advisory)\n\n")
            fh.write(ai_text + "\n")

    sarif_path = os.path.join(report_dir, f"hexstrike-{kind}.sarif")
    try:
        write_sarif(findings, sarif_path)
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  gagal tulis SARIF: {exc}")
        sarif_path = None

    log(f"📝 Laporan: {json_path} , {md_path}" + (f" , {sarif_path}" if sarif_path else ""))
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
