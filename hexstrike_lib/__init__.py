"""
HexStrike AI — integration library (single-responsibility modules).

Layer integrasi (CI scanner, webhook service, dashboard, agent LLM) dipecah
menjadi modul-modul kecil bertanggung jawab tunggal. Entrypoint tipis di root
(hexstrike_ci.py, hexstrike_webhook.py, hexstrike_openai_agent.py) hanya memanggil
modul di sini.

Peta modul:
  severity       konstanta & ranking severity (dipakai bersama)
  config         konfigurasi berbasis environment
  logging_util   helper log sederhana
  # --- CI scanner ---
  client         klien REST HexStrike
  findings       model temuan + agregasi count
  parsers        parser output tool (trivy/checkov/nuclei)
  local_tools    runner tool CLI lokal (semgrep/gitleaks)
  ai_summary     ringkasan triage LLM (opsional)
  reporting      tulis laporan JSON/MD + gating
  scanners       orkestrasi code-scan & pentest
  cli            antarmuka baris perintah CI
  # --- storage & dashboard ---
  db             penyimpanan SQLite
  dashboard      renderer HTML dashboard metrik
  # --- webhook service ---
  auth           autentikasi request & view (token/HMAC)
  auth_headers   pembentuk header auth utk authenticated scan
  archive        ekstraksi arsip upload yang aman
  jobs           manajer job background
  server_control autostart hexstrike_server
  webhook_app    Flask app factory + main webhook
  # --- agent ---
  agent          agent OpenAI-compatible (vLLM) via MCP
"""

__version__ = "6.0.0"
