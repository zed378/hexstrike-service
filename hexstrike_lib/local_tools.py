"""Runner tool CLI lokal (semgrep, gitleaks) — dijalankan langsung di container."""

import json
import os
import shutil
import subprocess
from typing import Dict, List

from .findings import finding
from .logging_util import make_log

log = make_log()


def _semgrep_sev(s: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get((s or "").upper(), "low")


def run_semgrep(path: str) -> List[Dict[str, str]]:
    if not shutil.which("semgrep"):
        log("… semgrep tidak ada di image, dilewati")
        return []
    log("🔎 semgrep --config auto …")
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", "--timeout", "0", path],
            capture_output=True, text=True, timeout=1800)
        data = json.loads(proc.stdout or "{}")
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  semgrep gagal: {exc}")
        return []
    out: List[Dict[str, str]] = []
    for r in data.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        # security-severity kadang berupa angka CVSS; fallback ke severity teks.
        sev_txt = _semgrep_sev(extra.get("severity", "INFO"))
        out.append(finding("semgrep", sev_txt,
                           r.get("check_id", "rule"),
                           f"{r.get('path','')}:{(r.get('start',{}) or {}).get('line','')}",
                           (extra.get("message", "") or "")))
    return out


def run_gitleaks(path: str) -> List[Dict[str, str]]:
    if not shutil.which("gitleaks"):
        log("… gitleaks tidak ada di image, dilewati")
        return []
    log("🔎 gitleaks detect …")
    report = os.path.join(path, ".gitleaks-report.json")
    # Bila bukan repo git (mis. arsip yang di-upload tanpa .git), pakai --no-git
    # agar gitleaks memindai filesystem, bukan riwayat git.
    cmd = ["gitleaks", "detect", "--source", path, "--no-banner",
           "--report-format", "json", "--report-path", report, "--exit-code", "0"]
    if not os.path.isdir(os.path.join(path, ".git")):
        cmd.insert(2, "--no-git")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        with open(report, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  gitleaks gagal: {exc}")
        return []
    finally:
        if os.path.exists(report):
            os.remove(report)
    out: List[Dict[str, str]] = []
    for leak in data or []:
        out.append(finding("gitleaks", "high",
                           f"Secret: {leak.get('RuleID','')}",
                           f"{leak.get('File','')}:{leak.get('StartLine','')}",
                           leak.get("Description", "")))
    return out
