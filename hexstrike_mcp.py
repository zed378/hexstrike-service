#!/usr/bin/env python3
"""Entrypoint tipis — HexStrike MCP bridge (FastMCP client untuk AI agent).

Semua logika ada di paket `hexstrike_lib.mcp`:
  colors  presentasi/logging
  client  transport REST ke HexStrike API
  server  registrasi @mcp.tool + runtime (setup_mcp_server, main)
"""

from hexstrike_lib.mcp.server import main

if __name__ == "__main__":
    main()
