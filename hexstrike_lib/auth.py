"""Autentikasi request webhook.

- request_authorized: untuk aksi menulis (/trigger, /scan/code) — token atau HMAC.
- view_authorized: untuk view read-only (dashboard, /api) — token via header ATAU
  query ?token=... (ramah browser); terbuka bila tak ada token dikonfigurasi.
"""

import hashlib
import hmac

from .config import WEBHOOK_HMAC_SECRET, WEBHOOK_TOKEN


def request_authorized(req) -> bool:
    if WEBHOOK_HMAC_SECRET:
        sig = req.headers.get("X-Hub-Signature-256", "")
        if not sig.startswith("sha256="):
            return False
        digest = hmac.new(WEBHOOK_HMAC_SECRET.encode(), req.get_data(), hashlib.sha256).hexdigest()
        return hmac.compare_digest("sha256=" + digest, sig)
    if WEBHOOK_TOKEN:
        provided = req.headers.get("X-Webhook-Token", "")
        return hmac.compare_digest(provided, WEBHOOK_TOKEN)
    return False  # tidak ada kredensial dikonfigurasi -> tolak semua


def view_authorized(req) -> bool:
    if not WEBHOOK_TOKEN:
        return True
    provided = req.headers.get("X-Webhook-Token", "") or req.args.get("token", "")
    return hmac.compare_digest(provided, WEBHOOK_TOKEN)


def auth_mode() -> str:
    return "hmac" if WEBHOOK_HMAC_SECRET else ("token" if WEBHOOK_TOKEN else "DISABLED")
