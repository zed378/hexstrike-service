#!/usr/bin/env python3
"""Entrypoint tipis — webhook service (trigger scan/pentest + dashboard).

Semua logika ada di paket `hexstrike_lib` (single-responsibility modules):
  webhook_app, jobs, auth, auth_headers, archive, server_control, db, dashboard.
"""

from hexstrike_lib.webhook_app import main

if __name__ == "__main__":
    raise SystemExit(main())
