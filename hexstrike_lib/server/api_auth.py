"""Auth sederhana untuk HexStrike Flask API (hexstrike_server.py / port 8888).

Endpoint ini bisa mengeksekusi command (lihat `/api/command`, tool-tool proses),
jadi HARUS dilindungi di environment manapun selain loopback dev murni — terutama
karena bind listener-nya 0.0.0.0 (dibutuhkan agar port mapping Docker berfungsi).

Aktif bila env `HEXSTRIKE_API_KEY` di-set: semua request (kecuali `/health`) wajib
mengirim header `X-API-Key` yang cocok. Kosong -> auth dimatikan (hanya dianjurkan
untuk dev lokal yang benar-benar terisolasi).
"""

import hmac
import logging

from flask import Response, request

from ..config import HEXSTRIKE_API_KEY

logger = logging.getLogger("hexstrike")

# Endpoint yang tetap boleh diakses tanpa API key (murni status, tanpa eksekusi apa pun).
_EXEMPT_PATHS = {"/health"}


def api_key_guard() -> "Response | None":
    """Dipasang sebagai `app.before_request`. Return None supaya request lanjut."""
    if not HEXSTRIKE_API_KEY:
        return None
    if request.path in _EXEMPT_PATHS:
        return None
    provided = request.headers.get("X-API-Key", "")
    if not hmac.compare_digest(provided, HEXSTRIKE_API_KEY):
        logger.warning("🔒 request ditolak (API key salah/tak ada): %s %s", request.method, request.path)
        return Response('{"success": false, "error": "unauthorized"}',
                        status=401, mimetype="application/json")
    return None


def warn_if_unprotected() -> None:
    if not HEXSTRIKE_API_KEY:
        logger.warning(
            "⚠️  HEXSTRIKE_API_KEY belum di-set — API ini bisa eksekusi command dan TERBUKA "
            "tanpa kredensial ke siapa pun yang punya akses network ke port ini. "
            "Set HEXSTRIKE_API_KEY di environment sebelum dipakai di luar dev lokal terisolasi."
        )
