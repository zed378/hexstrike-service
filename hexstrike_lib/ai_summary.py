"""Ringkasan triage LLM opsional (vLLM/OpenAI-compatible). Advisory — tak menggate."""

import json
import os
from typing import Dict, List, Optional

from .logging_util import make_log
from .severity import rank

log = make_log()


def ai_summary(kind: str, target: str, findings: List[Dict[str, str]]) -> Optional[str]:
    try:
        from openai import OpenAI
    except ImportError:
        log("… paket openai tidak ada, ringkasan AI dilewati")
        return None
    model = os.environ.get("OPENAI_MODEL", "")
    if not model:
        log("… OPENAI_MODEL kosong, ringkasan AI dilewati")
        return None
    client = OpenAI(
        base_url=os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1"),
        api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"),
    )
    top = sorted(findings, key=lambda f: -rank(f["severity"]))[:40]
    prompt = (
        f"Anda analis keamanan. Ini hasil {kind} untuk '{target}'. "
        f"Ringkas risiko utama, kelompokkan per severity, dan beri rekomendasi remediasi "
        f"yang konkret & bisa ditindaklanjuti. Jawab ringkas dalam Bahasa Indonesia (markdown).\n\n"
        f"Temuan (JSON):\n{json.dumps(top, ensure_ascii=False)}"
    )
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  ringkasan AI gagal: {exc}")
        return None
