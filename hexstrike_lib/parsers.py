"""Parser output tool (murni: string -> daftar finding). Tanpa efek samping."""

import json
from typing import Dict, List

from .findings import finding


def parse_trivy(stdout: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        data = json.loads(stdout)
    except Exception:  # noqa: BLE001
        return out
    for res in data.get("Results", []) or []:
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(finding(
                "trivy", v.get("Severity", "UNKNOWN"),
                f"{v.get('VulnerabilityID','')} in {v.get('PkgName','')} {v.get('InstalledVersion','')}",
                tgt, v.get("Title", "")))
        for s in res.get("Secrets", []) or []:
            out.append(finding("trivy-secret", s.get("Severity", "HIGH"),
                               f"Secret: {s.get('RuleID','')}", f"{tgt}:{s.get('StartLine','')}", s.get("Title", "")))
        for m in res.get("Misconfigurations", []) or []:
            out.append(finding("trivy-misconfig", m.get("Severity", "MEDIUM"),
                               f"{m.get('ID','')}: {m.get('Title','')}", tgt, m.get("Message", "")))
    return out


def parse_checkov(stdout: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        data = json.loads(stdout)
    except Exception:  # noqa: BLE001
        return out
    blocks = data if isinstance(data, list) else [data]
    for b in blocks:
        results = (b or {}).get("results", {}) or {}
        for fc in results.get("failed_checks", []) or []:
            sev = (fc.get("severity") or "MEDIUM")
            out.append(finding("checkov", sev,
                               f"{fc.get('check_id','')}: {fc.get('check_name','')}",
                               f"{fc.get('file_path','')}:{fc.get('file_line_range','')}"))
    return out


def parse_nuclei(stdout: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        info = j.get("info", {}) or {}
        out.append(finding("nuclei", info.get("severity", "info"),
                           info.get("name", j.get("template-id", "finding")),
                           j.get("matched-at", j.get("host", "")), info.get("description", "")))
    return out
