"""Antarmuka baris perintah scanner CI (code-scan & pentest)."""

import argparse
import os
from typing import List

from . import scanners
from .severity import SEVERITY_ORDER


def _cmd_code_scan(args: argparse.Namespace) -> int:
    return scanners.code_scan(
        server=args.server, path=args.path, report_dir=args.report_dir,
        fail_on=args.fail_on, use_llm=args.use_llm,
        baseline_path=args.baseline, diff_against_last=args.diff_against_last,
        image=args.image,
    )


def _cmd_pentest(args: argparse.Namespace) -> int:
    targets = list(args.target_list or [])
    if args.target:
        targets.append(args.target)
    if not targets:
        raise SystemExit("pentest: butuh --target (atau --target-list)")
    if len(targets) == 1:
        return scanners.pentest(
            server=args.server, target=targets[0], report_dir=args.report_dir,
            fail_on=args.fail_on, profile=args.profile, use_llm=args.use_llm,
            auth_headers=args.auth_header,
            baseline_path=args.baseline, diff_against_last=args.diff_against_last,
        )
    return scanners.pentest_batch(
        server=args.server, targets=targets, report_dir=args.report_dir,
        fail_on=args.fail_on, profile=args.profile, use_llm=args.use_llm,
        auth_headers=args.auth_header,
        baseline_path=args.baseline, diff_against_last=args.diff_against_last,
    )


def _read_target_list(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="HexStrike CI/CD scanner (code-scan & pentest)")
    p.add_argument("--server", default=os.environ.get("HEXSTRIKE_SERVER", "http://localhost:8888"))
    p.add_argument("--report-dir", default=os.environ.get("HEXSTRIKE_REPORT_DIR", "hexstrike-reports"))
    p.add_argument("--fail-on", default=os.environ.get("HEXSTRIKE_FAIL_ON", "high"),
                   choices=SEVERITY_ORDER + ["none"])
    p.add_argument("--use-llm", action="store_true",
                   default=os.environ.get("HEXSTRIKE_USE_LLM", "").lower() in {"1", "true", "yes"},
                   help="Tambahkan ringkasan/triage dari vLLM (advisory)")
    p.add_argument("--baseline", default=os.environ.get("HEXSTRIKE_BASELINE", "") or None,
                   help="File JSON allowlist/waiver — temuan yang cocok diredam & tidak menggate")
    p.add_argument("--diff-against-last", action="store_true",
                   default=os.environ.get("HEXSTRIKE_DIFF_AGAINST_LAST", "").lower() in {"1", "true", "yes"},
                   help="Tandai temuan yang BARU dibanding run sebelumnya (kind+target sama) di laporan, "
                        "butuh HEXSTRIKE_DB_PATH/riwayat SQLite")
    sub = p.add_subparsers(dest="cmd", required=True)

    cs = sub.add_parser("code-scan", help="SAST-style: cek kode sebelum deploy")
    cs.add_argument("--path", default=os.environ.get("CI_PROJECT_DIR", "."))
    cs.add_argument("--image", default=os.environ.get("HEXSTRIKE_SCAN_IMAGE", "") or None,
                    help="Referensi image yang SUDAH dibuild & di-push (mis. registry/app:tag) — "
                         "akan dipindai (trivy image); HexStrike TIDAK PERNAH membangun image ini")
    cs.set_defaults(func=_cmd_code_scan)

    pt = sub.add_parser("pentest", help="DAST-style: scan hasil deploy")
    pt.add_argument("--target", default=None, help="URL/host hasil deploy")
    pt.add_argument("--target-list", default=None, type=_read_target_list, dest="target_list",
                    help="File teks berisi satu target per baris (batch scan multi-target/microservices)")
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
