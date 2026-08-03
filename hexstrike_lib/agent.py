#!/usr/bin/env python3
"""
HexStrike AI — OpenAI-compatible Agent Bridge
=============================================

Menghubungkan LLM lokal yang OpenAI-compatible (mis. vLLM, Ollama, LM Studio,
LocalAI) ke SELURUH tool HexStrike, tanpa perlu client MCP seperti Claude/Cursor.

Cara kerja:
  1. Script ini men-spawn `hexstrike_mcp.py --server <FLASK>` sebagai proses
     MCP (stdio). Dengan begitu SEMUA @mcp.tool() yang sudah ada otomatis
     terpakai — tidak ada definisi tool yang diduplikasi di sini.
  2. Daftar tool MCP dikonversi ke format "tools" (function-calling) OpenAI.
  3. Agent loop: kirim pesan + tools ke endpoint /v1/chat/completions milik Anda,
     eksekusi setiap tool_call lewat MCP, umpankan hasilnya kembali ke model,
     ulangi sampai model memberi jawaban akhir.

Konfigurasi lewat ENV (atau flag CLI):
  OPENAI_BASE_URL   default: http://localhost:8000/v1   (vLLM)
  OPENAI_API_KEY    default: EMPTY                       (vLLM tidak butuh key)
  OPENAI_MODEL      wajib diisi (nama model di server Anda)
  HEXSTRIKE_SERVER  default: http://localhost:8888       (Flask API HexStrike)

Contoh:
  export OPENAI_BASE_URL=http://localhost:8000/v1
  export OPENAI_MODEL=Qwen/Qwen2.5-7B-Instruct
  python3 hexstrike_openai_agent.py "Recon ringan terhadap scanme.nmap.org"

  # Mode interaktif (REPL):
  python3 hexstrike_openai_agent.py

CATATAN vLLM: agar function-calling aktif, jalankan server vLLM dengan
  --enable-auto-tool-choice --tool-call-parser hermes   (sesuaikan parser model).
"""

import argparse
import asyncio
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

try:
    from openai import AsyncOpenAI
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "❌ Paket 'openai' belum terpasang. Jalankan: pip install 'openai>=1.30.0'\n"
    )
    raise

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "❌ Paket 'mcp' belum terpasang. Ia ikut dengan 'fastmcp' di requirements.txt.\n"
    )
    raise


# --------------------------------------------------------------------------- #
# Util tampilan sederhana (tanpa dependensi tambahan)
# --------------------------------------------------------------------------- #
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;196m"
    GREEN = "\033[38;5;46m"
    CYAN = "\033[38;5;51m"
    ORANGE = "\033[38;5;208m"
    PURPLE = "\033[38;5;129m"


def _c(text: str, color: str) -> str:
    if os.environ.get("NO_COLOR"):
        return text
    return f"{color}{text}{C.RESET}"


DEFAULT_SYSTEM_PROMPT = (
    "You are HexStrike, an autonomous security-testing assistant operating a large "
    "arsenal of offensive/defensive tools exposed as callable functions. "
    "Only act on assets the user is authorized to test. "
    "Plan briefly, then call the appropriate tools to gather real evidence instead "
    "of guessing. Prefer non-destructive reconnaissance first. When you call a tool, "
    "choose sensible parameters. After tools return, summarize findings clearly with "
    "concrete next steps. If a tool is missing or fails, adapt and try an alternative."
)

# Batas panjang output tool yang diumpankan balik ke model (jaga context window).
MAX_TOOL_OUTPUT_CHARS = int(os.environ.get("HEXSTRIKE_MAX_TOOL_CHARS", "12000"))
_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]")


# --------------------------------------------------------------------------- #
# Konversi tool MCP -> tool OpenAI
# --------------------------------------------------------------------------- #
def _sanitize_tool_name(name: str, taken: set) -> str:
    """OpenAI function name: ^[a-zA-Z0-9_-]{1,64}$ dan harus unik."""
    clean = _NAME_RE.sub("_", name)[:64] or "tool"
    base = clean
    i = 1
    while clean in taken:
        suffix = f"_{i}"
        clean = base[: 64 - len(suffix)] + suffix
        i += 1
    taken.add(clean)
    return clean


def build_openai_tools(mcp_tools) -> (List[Dict[str, Any]], Dict[str, str]):
    """Kembalikan (tools_schema, mapping nama_openai -> nama_mcp_asli)."""
    tools_schema: List[Dict[str, Any]] = []
    name_map: Dict[str, str] = {}
    taken: set = set()

    for t in mcp_tools:
        schema = t.inputSchema or {"type": "object", "properties": {}}
        # Beberapa server LLM rewel bila "type" tidak ada di root schema.
        if "type" not in schema:
            schema = {**schema, "type": "object"}
        oai_name = _sanitize_tool_name(t.name, taken)
        name_map[oai_name] = t.name
        tools_schema.append(
            {
                "type": "function",
                "function": {
                    "name": oai_name,
                    "description": (t.description or t.name)[:1024],
                    "parameters": schema,
                },
            }
        )
    return tools_schema, name_map


def _extract_text(call_result) -> str:
    """Ambil teks dari hasil MCP CallToolResult."""
    parts: List[str] = []
    for item in getattr(call_result, "content", []) or []:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
        else:
            parts.append(str(item))
    out = "\n".join(parts) if parts else "(tool returned no textual content)"
    if len(out) > MAX_TOOL_OUTPUT_CHARS:
        out = out[:MAX_TOOL_OUTPUT_CHARS] + f"\n… [truncated {len(out) - MAX_TOOL_OUTPUT_CHARS} chars]"
    return out


# --------------------------------------------------------------------------- #
# Agent loop
# --------------------------------------------------------------------------- #
async def run_agent(args: argparse.Namespace) -> int:
    llm = AsyncOpenAI(base_url=args.base_url, api_key=args.api_key)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[args.mcp_script, "--server", args.server],
        env=os.environ.copy(),
    )

    print(_c("⚙️  Menyambungkan ke bridge MCP HexStrike…", C.CYAN))
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            tools_schema, name_map = build_openai_tools(listed.tools)
            print(
                _c(
                    f"✅ {len(tools_schema)} tool HexStrike siap dipakai model "
                    f"'{args.model}' @ {args.base_url}",
                    C.GREEN,
                )
            )

            messages: List[Dict[str, Any]] = [
                {"role": "system", "content": args.system}
            ]

            async def one_turn(user_text: str) -> None:
                messages.append({"role": "user", "content": user_text})
                for step in range(1, args.max_steps + 1):
                    resp = await llm.chat.completions.create(
                        model=args.model,
                        messages=messages,
                        tools=tools_schema,
                        tool_choice="auto",
                        temperature=args.temperature,
                    )
                    msg = resp.choices[0].message
                    tool_calls = msg.tool_calls or []

                    # Simpan giliran assistant (termasuk tool_calls) ke history.
                    messages.append(
                        {
                            "role": "assistant",
                            "content": msg.content or "",
                            "tool_calls": [
                                {
                                    "id": tc.id,
                                    "type": "function",
                                    "function": {
                                        "name": tc.function.name,
                                        "arguments": tc.function.arguments,
                                    },
                                }
                                for tc in tool_calls
                            ]
                            if tool_calls
                            else None,
                        }
                    )

                    if not tool_calls:
                        print("\n" + _c("🤖 Jawaban:", C.BOLD))
                        print(msg.content or "(kosong)")
                        return

                    for tc in tool_calls:
                        oai_name = tc.function.name
                        mcp_name = name_map.get(oai_name, oai_name)
                        try:
                            call_args = json.loads(tc.function.arguments or "{}")
                        except json.JSONDecodeError:
                            call_args = {}
                        print(
                            _c(f"\n🛠️  [step {step}] {mcp_name}", C.PURPLE)
                            + _c(f"  args={json.dumps(call_args, ensure_ascii=False)[:300]}", C.DIM)
                        )
                        try:
                            result = await session.call_tool(mcp_name, call_args)
                            content = _extract_text(result)
                            status = _c("done", C.GREEN)
                        except Exception as exc:  # noqa: BLE001
                            content = f"ERROR executing tool '{mcp_name}': {exc}"
                            status = _c("error", C.RED)
                        print(_c(f"   ↳ {status} ({len(content)} chars)", C.DIM))
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tc.id,
                                "content": content,
                            }
                        )
                print(
                    _c(
                        f"\n⚠️  Mencapai batas {args.max_steps} langkah tanpa jawaban akhir.",
                        C.ORANGE,
                    )
                )

            # Sekali jalan (task diberikan) atau REPL interaktif.
            if args.task:
                await one_turn(args.task)
            else:
                print(_c("Mode interaktif. Ketik tugas Anda (Ctrl-C / 'exit' untuk keluar).", C.CYAN))
                while True:
                    try:
                        user_text = input(_c("\nhexstrike> ", C.BOLD)).strip()
                    except (EOFError, KeyboardInterrupt):
                        print()
                        break
                    if user_text.lower() in {"exit", "quit"}:
                        break
                    if user_text:
                        await one_turn(user_text)
    return 0


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    # Root repo = parent dari direktori package (hexstrike_lib/)
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = argparse.ArgumentParser(
        description="HexStrike agent untuk LLM lokal OpenAI-compatible (vLLM dll.)",
    )
    p.add_argument("task", nargs="?", help="Tugas untuk dikerjakan. Kosong = mode interaktif.")
    p.add_argument(
        "--base-url",
        default=os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1"),
        help="Endpoint OpenAI-compatible (default vLLM: http://localhost:8000/v1)",
    )
    p.add_argument(
        "--api-key",
        default=os.environ.get("OPENAI_API_KEY", "EMPTY"),
        help="API key (vLLM biasanya tidak butuh; default 'EMPTY')",
    )
    p.add_argument(
        "--model",
        default=os.environ.get("OPENAI_MODEL", ""),
        help="Nama model di server Anda (wajib)",
    )
    p.add_argument(
        "--server",
        default=os.environ.get("HEXSTRIKE_SERVER", "http://localhost:8888"),
        help="URL Flask API HexStrike (default http://localhost:8888)",
    )
    p.add_argument(
        "--mcp-script",
        default=os.environ.get("HEXSTRIKE_MCP_SCRIPT", os.path.join(here, "hexstrike_mcp.py")),
        help="Path ke hexstrike_mcp.py",
    )
    p.add_argument("--system", default=os.environ.get("HEXSTRIKE_SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT))
    p.add_argument("--max-steps", type=int, default=int(os.environ.get("HEXSTRIKE_MAX_STEPS", "20")))
    p.add_argument("--temperature", type=float, default=float(os.environ.get("HEXSTRIKE_TEMPERATURE", "0.2")))
    return p.parse_args(argv)


def main() -> int:
    args = parse_args()
    if not args.model:
        sys.stderr.write(
            _c("❌ --model / OPENAI_MODEL wajib diisi (nama model di server vLLM Anda).\n", C.RED)
        )
        return 2
    if not os.path.exists(args.mcp_script):
        sys.stderr.write(_c(f"❌ Tidak menemukan MCP script: {args.mcp_script}\n", C.RED))
        return 2
    try:
        return asyncio.run(run_agent(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
