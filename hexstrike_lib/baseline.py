"""Baseline/allowlist (waiver) findings + diff terhadap run sebelumnya.

Baseline file (JSON), daftar entri:
  [
    {"fingerprint": "<sha1 opsional, kalau tahu>", "tool": "...", "title": "...",
     "location": "...", "reason": "diterima tim appsec", "expires": "2026-12-31"}
  ]
Entri dicocokkan via fingerprint (tool|title|location dinormalisasi). Entri yang
sudah lewat `expires` diabaikan (tidak lagi meredam temuan) supaya waiver tidak
dibiarkan selamanya tanpa review ulang.
"""

import hashlib
import json
import os
from datetime import date
from typing import Any, Dict, List, Optional, Tuple

from .logging_util import make_log

log = make_log()


def fingerprint(f: Dict[str, str]) -> str:
    """Fingerprint stabil dari sebuah finding (tool + title + location dinormalisasi)."""
    key = "|".join([
        (f.get("tool") or "").strip().lower(),
        (f.get("title") or "").strip().lower(),
        (f.get("location") or "").strip().lower(),
    ])
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def _is_expired(entry: Dict[str, Any]) -> bool:
    exp = entry.get("expires")
    if not exp:
        return False
    try:
        return date.fromisoformat(str(exp)) < date.today()
    except ValueError:
        return False


def load_baseline(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """Baca file baseline -> map fingerprint -> entry. Kosong bila path tidak diisi/tidak ada."""
    if not path:
        return {}
    if not os.path.isfile(path):
        log(f"⚠️  baseline '{path}' tidak ditemukan, dilewati")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  gagal baca baseline '{path}': {exc}")
        return {}

    out: Dict[str, Dict[str, Any]] = {}
    for entry in raw or []:
        if _is_expired(entry):
            continue
        fp = entry.get("fingerprint") or fingerprint(entry)
        out[fp] = entry
    return out


def apply_baseline(
    findings: List[Dict[str, str]], baseline: Dict[str, Dict[str, Any]]
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Pisahkan findings jadi (active, waived) berdasarkan baseline. `active` dipakai utk gate."""
    if not baseline:
        return findings, []
    active: List[Dict[str, str]] = []
    waived: List[Dict[str, str]] = []
    for f in findings:
        fp = fingerprint(f)
        if fp in baseline:
            waived.append({**f, "_waived_reason": baseline[fp].get("reason", "")})
        else:
            active.append(f)
    return active, waived


def diff_against_previous(
    previous_findings: Optional[List[Dict[str, str]]], current_findings: List[Dict[str, str]]
) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """Bandingkan dua kumpulan findings -> (new, existing) berdasarkan fingerprint.

    `previous_findings=None` (tidak ada histori) -> semua current dianggap `new`.
    """
    if previous_findings is None:
        return list(current_findings), []
    prev_fps = {fingerprint(f) for f in previous_findings}
    new: List[Dict[str, str]] = []
    existing: List[Dict[str, str]] = []
    for f in current_findings:
        (new if fingerprint(f) not in prev_fps else existing).append(f)
    return new, existing
