#!/usr/bin/env python3
"""Entrypoint tipis — agent LLM lokal OpenAI-compatible (vLLM) via MCP.

Semua logika ada di `hexstrike_lib.agent`.
"""

from hexstrike_lib.agent import main

if __name__ == "__main__":
    raise SystemExit(main())
