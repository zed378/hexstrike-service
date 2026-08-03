"""Model temuan (finding) + agregasi count per severity."""

from datetime import datetime, timezone
from typing import Dict, List

from .severity import SEVERITY_ORDER


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def finding(tool: str, severity: str, title: str, location: str = "", extra: str = "") -> Dict[str, str]:
    return {
        "tool": tool,
        "severity": (severity or "info").lower(),
        "title": title[:300],
        "location": location[:300],
        "extra": extra[:300],
    }


def counts_by_severity(findings: List[Dict[str, str]]) -> Dict[str, int]:
    c = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c
