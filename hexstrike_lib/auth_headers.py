"""Pembentuk header auth untuk authenticated scan dari payload `auth` request."""

import base64
from typing import Any, Dict, List, Optional


def build_auth_headers(auth: Optional[Dict[str, Any]]) -> List[str]:
    """Ubah objek auth -> daftar string header HTTP. Kosong bila tidak valid.

    bearer  -> Authorization: Bearer <token>
    basic   -> Authorization: Basic base64(user:pass)
    cookie  -> Cookie: <cookie>
    header  -> header mentah (list/str)
    """
    if not auth or not isinstance(auth, dict):
        return []
    atype = (auth.get("type") or "").lower()
    if atype == "bearer" and auth.get("token"):
        return [f"Authorization: Bearer {auth['token']}"]
    if atype == "basic" and auth.get("username") is not None:
        raw = f"{auth.get('username','')}:{auth.get('password','')}".encode()
        return [f"Authorization: Basic {base64.b64encode(raw).decode()}"]
    if atype == "cookie" and auth.get("cookie"):
        return [f"Cookie: {auth['cookie']}"]
    if atype == "header":
        h = auth.get("headers") or auth.get("header") or []
        if isinstance(h, str):
            h = [h]
        return [str(x) for x in h]
    return []
