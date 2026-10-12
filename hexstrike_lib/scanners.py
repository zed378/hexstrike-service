"""Orkestrasi scan: code_scan (SAST) & pentest (DAST). Menggabungkan client,
parser, tool lokal, reporting, dan gating. Mengembalikan exit code (0/1/2)."""

import os
import shlex
from typing import List, Optional

from . import db as db_module
from .ai_summary import ai_summary
from .baseline import apply_baseline, diff_against_previous, load_baseline
from .client import HexStrikeClient
from .config import DB_PATH
from .local_tools import run_gitleaks, run_semgrep
from .logging_util import make_log
from .parsers import parse_checkov, parse_nuclei, parse_trivy
from .reporting import gate, write_reports

log = make_log()


def _previous_findings(kind: str, target: str) -> Optional[List[dict]]:
    """Findings run sebelumnya (utk diff "new vs existing"). None bila DB tak ada/kosong."""
    try:
        return db_module.get_last_findings(DB_PATH, kind, target)
    except Exception as exc:  # noqa: BLE001
        log(f"… diff histori tidak tersedia ({exc}), semua temuan dianggap baru")
        return None


def code_scan(server: str, path: str, report_dir: str, fail_on: str, use_llm: bool = False,
              baseline_path: Optional[str] = None, diff_against_last: bool = False,
              image: Optional[str] = None) -> int:
    hs = HexStrikeClient(server)
    if not hs.wait_healthy():
        log("❌ HexStrike server tidak sehat")
        return 2
    path = os.path.abspath(path)
    findings: List[dict] = []

    log(f"🔬 trivy fs {path} (vuln, secret, misconfig)…")
    tv = hs.post("api/tools/trivy", {
        "scan_type": "fs", "target": path, "output_format": "json",
        "additional_args": "--scanners vuln,secret,misconfig --quiet --no-progress",
    })
    findings += parse_trivy(tv.get("stdout", ""))

    log(f"🔬 checkov -d {path} (IaC)…")
    cv = hs.post("api/tools/checkov", {
        "directory": path, "output_format": "json",
        "additional_args": "--compact --quiet",
    })
    findings += parse_checkov(cv.get("stdout", ""))

    findings += run_semgrep(path)
    findings += run_gitleaks(path)

    if image:
        # Image SUDAH di-build & di-push oleh pipeline/operator di luar HexStrike — kita
        # HANYA memindainya (trivy image), dan TIDAK PERNAH membangunnya sendiri di sini.
        log(f"🔬 trivy image {image} (vuln, secret, misconfig)…")
        tvi = hs.post("api/tools/trivy", {
            "scan_type": "image", "target": image, "output_format": "json",
            "additional_args": "--scanners vuln,secret,misconfig --quiet --no-progress",
        })
        findings += parse_trivy(tvi.get("stdout", ""))

    baseline = load_baseline(baseline_path)
    active, waived = apply_baseline(findings, baseline)
    new_findings = None
    if diff_against_last:
        new_findings, _existing = diff_against_previous(_previous_findings("code-scan", path), active)

    ai_text = ai_summary("code-scan", path, active) if use_llm and active else None
    summary = write_reports("code-scan", path, active, report_dir, ai_text,
                            waived=waived, new_findings=new_findings)
    log(f"📊 Ringkasan: {summary['counts']}" + (f" (diredam: {len(waived)})" if waived else ""))
    return gate(summary["counts"], fail_on)


def _resolve_auth_headers(explicit: Optional[List[str]]) -> List[str]:
    """Gabungkan header auth dari argumen + env HEXSTRIKE_AUTH_HEADERS (dari webhook)."""
    headers = list(explicit or [])
    env_headers = os.environ.get("HEXSTRIKE_AUTH_HEADERS", "")
    if env_headers:
        headers += [h for h in env_headers.splitlines() if h.strip()]
    return headers


def pentest(server: str, target: str, report_dir: str, fail_on: str,
            profile: str = "quick", use_llm: bool = False,
            auth_headers: Optional[List[str]] = None,
            baseline_path: Optional[str] = None, diff_against_last: bool = False) -> int:
    from .findings import finding  # lokal untuk hindari import siklik minor

    hs = HexStrikeClient(server)
    if not hs.wait_healthy():
        log("❌ HexStrike server tidak sehat")
        return 2

    headers = _resolve_auth_headers(auth_headers)
    hdr_args = "".join(f" -H {shlex.quote(h)}" for h in headers)
    if headers:
        log(f"🔑 authenticated scan: {len(headers)} header auth disuntikkan")

    findings: List[dict] = []

    log(f"🌐 wafw00f {target}…")
    hs.post("api/tools/wafw00f", {"target": target})  # informatif

    log(f"🌐 httpx probe {target}…")
    hs.post("api/tools/httpx", {
        "target": target,
        "additional_args": f"-title -tech-detect -status-code -silent{hdr_args}",
    })

    sev = "low,medium,high,critical" if profile == "full" else "medium,high,critical"
    log(f"🔬 nuclei -u {target} -severity {sev}…")
    nu = hs.post("api/tools/nuclei", {
        "target": target, "severity": sev,
        "additional_args": f"-jsonl -silent -no-color{hdr_args}", "use_recovery": True,
    })
    findings += parse_nuclei(nu.get("stdout", ""))

    if profile == "full":
        log(f"🔬 nikto {target}…")
        nk = hs.post("api/tools/nikto", {"target": target})
        raw = nk.get("stdout", "")
        for line in raw.splitlines():
            if line.strip().startswith("+ ") and ("OSVDB" in line or "vuln" in line.lower()):
                findings.append(finding("nikto", "low", line.strip()[:200], target))

    baseline = load_baseline(baseline_path)
    active, waived = apply_baseline(findings, baseline)
    new_findings = None
    if diff_against_last:
        new_findings, _existing = diff_against_previous(_previous_findings("pentest", target), active)

    ai_text = ai_summary("pentest", target, active) if use_llm and active else None
    summary = write_reports("pentest", target, active, report_dir, ai_text,
                            waived=waived, new_findings=new_findings)
    log(f"📊 Ringkasan: {summary['counts']}" + (f" (diredam: {len(waived)})" if waived else ""))
    return gate(summary["counts"], fail_on)


def pentest_batch(server: str, targets: List[str], report_dir: str, fail_on: str,
                   profile: str = "quick", use_llm: bool = False,
                   auth_headers: Optional[List[str]] = None,
                   baseline_path: Optional[str] = None, diff_against_last: bool = False) -> int:
    """Jalankan `pentest` untuk banyak target (satu per subdir report_dir/<slug>/),
    lalu tulis index gabungan di report_dir/hexstrike-pentest-batch.json.
    rc keseluruhan = gagal bila ADA SATU target yang gate-fail."""
    import re as _re

    os.makedirs(report_dir, exist_ok=True)
    overall_rc = 0
    index: List[dict] = []
    for i, target in enumerate(targets):
        target = target.strip()
        if not target:
            continue
        slug = _re.sub(r"[^A-Za-z0-9._-]+", "_", target)[:60] or f"target{i}"
        sub_dir = os.path.join(report_dir, slug)
        log(f"=== [{i + 1}/{len(targets)}] pentest -> {target} ===")
        rc = pentest(server, target, sub_dir, fail_on, profile, use_llm, auth_headers,
                     baseline_path, diff_against_last)
        overall_rc = overall_rc or rc
        summary_path = os.path.join(sub_dir, "hexstrike-pentest.json")
        counts = {}
        if os.path.exists(summary_path):
            import json as _json
            with open(summary_path, "r", encoding="utf-8") as fh:
                counts = _json.load(fh).get("counts", {})
        index.append({"target": target, "report_dir": sub_dir, "gate_failed": rc == 1,
                      "exit_code": rc, "counts": counts})

    import json as _json
    with open(os.path.join(report_dir, "hexstrike-pentest-batch.json"), "w", encoding="utf-8") as fh:
        _json.dump({"targets": index, "total_targets": len(index),
                    "failed_targets": sum(1 for x in index if x["gate_failed"])}, fh,
                   ensure_ascii=False, indent=2)
    failed = sum(1 for x in index if x["gate_failed"])
    log(f"📊 Batch pentest selesai: {len(index)} target, {failed} gate-failed")
    return overall_rc
