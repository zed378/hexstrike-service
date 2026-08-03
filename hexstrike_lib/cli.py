"""Antarmuka baris perintah scanner CI (code-scan & pentest)."""

import argparse
import os

from . import scanners
from .severity import SEVERITY_ORDER


def _cmd_code_scan(args: argparse.Namespace) -> int:
    return scanners.code_scan(
        server=args.server, path=args.path, report_dir=args.report_dir,
        fail_on=args.fail_on, use_llm=args.use_llm,
    )


def _cmd_pentest(args: argparse.Namespace) -> int:
    return scanners.pentest(
        server=args.server, target=args.target, report_dir=args.report_dir,
        fail_on=args.fail_on, profile=args.profile, use_llm=args.use_llm,
        auth_headers=args.auth_header,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="HexStrike CI/CD scanner (code-scan & pentest)")
    p.add_argument("--server", default=os.environ.get("HEXSTRIKE_SERVER", "http://localhost:8888"))
    p.add_argument("--report-dir", default=os.environ.get("HEXSTRIKE_REPORT_DIR", "hexstrike-reports"))
    p.add_argument("--fail-on", default=os.environ.get("HEXSTRIKE_FAIL_ON", "high"),
                   choices=SEVERITY_ORDER + ["none"])
    p.add_argument("--use-llm", action="store_true",
                   default=os.environ.get("HEXSTRIKE_USE_LLM", "").lower() in {"1", "true", "yes"},
                   help="Tambahkan ringkasan/triage dari vLLM (advisory)")
    sub = p.add_subparsers(dest="cmd", required=True)

    cs = sub.add_parser("code-scan", help="SAST-style: cek kode sebelum deploy")
    cs.add_argument("--path", default=os.environ.get("CI_PROJECT_DIR", "."))
    cs.set_defaults(func=_cmd_code_scan)

    pt = sub.add_parser("pentest", help="DAST-style: scan hasil deploy")
    pt.add_argument("--target", required=True, help="URL/host hasil deploy")
    pt.add_argument("--profile", default=os.environ.get("HEXSTRIKE_PENTEST_PROFILE", "quick"),
                    choices=["quick", "full"])
    pt.add_argument("--auth-header", action="append", default=None,
                    help="Header auth utk authenticated scan (boleh berkali-kali), "
                         "mis. --auth-header 'Authorization: Bearer xxx'")
    pt.set_defaults(func=_cmd_pentest)
    return p


def main() -> int:
    args = build_parser().parse_args()
    never_fail = False
    if args.fail_on == "none":
        # 'none' => tidak pernah gagal karena severity; naikkan threshold ke maksimum
        args.fail_on = "critical"
        never_fail = True
    rc = args.func(args)
    return 0 if never_fail else rc
