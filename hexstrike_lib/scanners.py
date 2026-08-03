"""Orkestrasi scan: code_scan (SAST) & pentest (DAST). Menggabungkan client,
parser, tool lokal, reporting, dan gating. Mengembalikan exit code (0/1/2)."""

import os
import shlex
from typing import List, Optional

from .ai_summary import ai_summary
from .client import HexStrikeClient
from .local_tools import run_gitleaks, run_semgrep
from .logging_util import make_log
from .parsers import parse_checkov, parse_nuclei, parse_trivy
from .reporting import gate, write_reports

log = make_log()


def code_scan(server: str, path: str, report_dir: str, fail_on: str, use_llm: bool = False) -> int:
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

    ai_text = ai_summary("code-scan", path, findings) if use_llm and findings else None
    summary = write_reports("code-scan", path, findings, report_dir, ai_text)
    log(f"📊 Ringkasan: {summary['counts']}")
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
            auth_headers: Optional[List[str]] = None) -> int:
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

    ai_text = ai_summary("pentest", target, findings) if use_llm and findings else None
    summary = write_reports("pentest", target, findings, report_dir, ai_text)
    log(f"📊 Ringkasan: {summary['counts']}")
    return gate(summary["counts"], fail_on)
