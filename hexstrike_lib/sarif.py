"""Export findings ke SARIF 2.1.0 — supaya terbaca GitLab/GitHub code-scanning
dashboard (bukan cuma JSON/MD custom kita)."""

import hashlib
import json
import re
from typing import Any, Dict, List

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# severity kita -> level SARIF standar (error/warning/note)
_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# "path:line" atau "path:line-range" di awal location -> dipisah jadi artifact + startLine
_LOC_RE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+)")


def _rule_id(f: Dict[str, str]) -> str:
    base = f"{f.get('tool','')}.{f.get('title','')}"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", base).strip("-")[:120] or hashlib.sha1(
        json.dumps(f, sort_keys=True).encode()).hexdigest()[:12]


def _physical_location(location: str) -> Dict[str, Any]:
    m = _LOC_RE.match(location or "")
    if m:
        region = {"startLine": max(1, int(m.group("line")))}
        return {"physicalLocation": {"artifactLocation": {"uri": m.group("file")}, "region": region}}
    # Target bukan file lokal (mis. URL pentest) -> tetap referensikan sebagai artifactLocation.uri
    return {"physicalLocation": {"artifactLocation": {"uri": location or "unknown"}}}


def to_sarif(findings: List[Dict[str, str]], tool_name: str = "HexStrike AI") -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results = []
    for f in findings:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f.get("title", rid),
                "shortDescription": {"text": f.get("title", rid)[:200]},
                "properties": {"security-severity": str(f.get("severity", "info"))},
            }
        results.append({
            "ruleId": rid,
            "level": _LEVEL.get((f.get("severity") or "info").lower(), "note"),
            "message": {"text": f.get("extra") or f.get("title", "")},
            "locations": [_physical_location(f.get("location", ""))],
            "properties": {"tool": f.get("tool", ""), "severity": f.get("severity", "info")},
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "informationUri": "https://github.com/0x4m4/hexstrike-ai",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif(findings: List[Dict[str, str]], path: str, tool_name: str = "HexStrike AI") -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_sarif(findings, tool_name), fh, ensure_ascii=False, indent=2)
