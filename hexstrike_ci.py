#!/usr/bin/env python3
"""Entrypoint tipis — CI/CD scanner (code-scan & pentest).

Semua logika ada di paket `hexstrike_lib` (single-responsibility modules):
  scanners, client, parsers, local_tools, reporting, ai_summary, cli.
"""

from hexstrike_lib.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
