"""Klien REST HexStrike — satu-satunya tempat bicara HTTP ke Flask API."""

import time
from typing import Any, Dict

import requests

from .logging_util import make_log

log = make_log()


class HexStrikeClient:
    """Pembungkus tipis REST HexStrike (POST tool endpoints + health)."""

    def __init__(self, base_url: str, timeout: int = 1800):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base}/{endpoint.lstrip('/')}"
        try:
            r = requests.post(url, json=payload, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": str(exc), "stdout": "", "stderr": str(exc)}

    def wait_healthy(self, retries: int = 40, delay: float = 3.0) -> bool:
        for i in range(1, retries + 1):
            try:
                if requests.get(f"{self.base}/health", timeout=10).ok:
                    log(f"✅ HexStrike server sehat (percobaan {i})")
                    return True
            except Exception:  # noqa: BLE001
                pass
            log(f"… menunggu HexStrike server ({i}/{retries})")
            time.sleep(delay)
        return False
