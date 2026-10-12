"""Konfigurasi berbasis environment (dibaca sekali saat import)."""

import os

# Root repo = parent dari direktori package ini
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI_SCRIPT = os.path.join(ROOT, "hexstrike_ci.py")
SERVER_SCRIPT = os.path.join(ROOT, "hexstrike_server.py")

# HexStrike Flask API
HEXSTRIKE_SERVER = os.environ.get("HEXSTRIKE_SERVER", "http://localhost:8888")

# Penyimpanan laporan + SQLite
REPORT_ROOT = os.environ.get("HEXSTRIKE_REPORT_ROOT", os.path.join(ROOT, "hexstrike-reports"))
DB_PATH = os.environ.get("HEXSTRIKE_DB_PATH", os.path.join(REPORT_ROOT, "hexstrike.db"))

# Direktori file baseline/allowlist yang boleh dirujuk lewat webhook (hanya nama file,
# tanpa path traversal — isinya dikurasi operator, bukan diupload lewat request).
BASELINE_DIR = os.environ.get("HEXSTRIKE_BASELINE_DIR", os.path.join(ROOT, "baselines"))

# API key wajib untuk memanggil HexStrike Flask API (hexstrike_server.py / port 8888)
# langsung — endpoint itu bisa eksekusi command, jadi tidak boleh terbuka tanpa kredensial
# di environment manapun selain localhost murni. Kosong => auth dimatikan (hanya utk dev lokal).
HEXSTRIKE_API_KEY = os.environ.get("HEXSTRIKE_API_KEY", "")

# Webhook
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")
WEBHOOK_HMAC_SECRET = os.environ.get("WEBHOOK_HMAC_SECRET", "")
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "9000"))
MAX_UPLOAD_MB = int(os.environ.get("HEXSTRIKE_MAX_UPLOAD_MB", "300"))
AUTOSTART_SERVER = os.environ.get("HEXSTRIKE_AUTOSTART_SERVER", "").lower() in {"1", "true", "yes"}

# Default gating
DEFAULT_FAIL_ON = os.environ.get("HEXSTRIKE_DEFAULT_FAIL_ON", "high")

# Validasi input request
VALID_ACTIONS = {"pentest", "code-scan", "both"}
VALID_PROFILES = {"quick", "full"}
VALID_FAIL_ON = {"none", "info", "low", "medium", "high", "critical"}
