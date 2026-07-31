#!/usr/bin/env python3
"""
HexStrike AI — CI/CD scanner (gate deterministik + ringkasan AI opsional)
========================================================================

Dipakai di dalam pipeline CI/CD, DI DALAM image HexStrike (semua tool tersedia).
Dua sub-perintah:

  code-scan   Cek KODE sebelum deploy (SAST-style):
                - trivy fs   -> CVE dependency, secret, misconfig   (via REST HexStrike)
                - checkov    -> IaC (terraform/k8s/dockerfile)       (via REST HexStrike)
                - semgrep    -> SAST rules                            (CLI lokal, bila ada)
                - gitleaks   -> secret di git/working tree           (CLI lokal, bila ada)

  pentest     Scan HASIL DEPLOY (DAST-style) terhadap URL:
                - wafw00f, httpx, nuclei, nikto                      (via REST HexStrike)

Gate (lulus/gagal pipeline) ditentukan dari temuan tool NYATA (deterministik),
BUKAN dari LLM. Opsi --use-llm hanya menambah ringkasan/triage yang ditulis
model vLLM Anda (advisory, tidak mempengaruhi exit code).

Exit code: 0 = di bawah ambang; 1 = ada temuan >= --fail-on; 2 = error setup.

ENV utama:
  HEXSTRIKE_SERVER   default http://localhost:8888
  OPENAI_BASE_URL / OPENAI_MODEL / OPENAI_API_KEY   (untuk --use-llm)
"""

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _rank(sev: str) -> int:
    return SEV_RANK.get((sev or "info").strip().lower(), 0)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# Klien REST HexStrike
# --------------------------------------------------------------------------- #
class HexStrike:
    def __init__(self, base_url: str, timeout: int = 1800):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.base}/{endpoint.lstrip('/')}"
        try:
            r = requests.post(url, json=payload, timeout=self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "error": str(exc), "stdout": "", "stderr": str(exc)}

    def wait_healthy(self, retries: int = 40, delay: float = 3.0) -> bool:
        import time
        for i in range(1, retries + 1):
            try:
                r = requests.get(f"{self.base}/health", timeout=10)
                if r.ok:
                    log(f"✅ HexStrike server sehat (percobaan {i})")
                    return True
            except Exception:  # noqa: BLE001
                pass
            log(f"… menunggu HexStrike server ({i}/{retries})")
            time.sleep(delay)
        return False


# --------------------------------------------------------------------------- #
# Struktur temuan
# --------------------------------------------------------------------------- #
def finding(tool: str, severity: str, title: str, location: str = "", extra: str = "") -> Dict[str, str]:
    return {
        "tool": tool,
        "severity": (severity or "info").lower(),
        "title": title[:300],
        "location": location[:300],
        "extra": extra[:300],
    }


def counts_by_severity(findings: List[Dict[str, str]]) -> Dict[str, int]:
    c = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


# --------------------------------------------------------------------------- #
# Parser tool
# --------------------------------------------------------------------------- #
def parse_trivy(stdout: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        data = json.loads(stdout)
    except Exception:  # noqa: BLE001
        return out
    for res in data.get("Results", []) or []:
        tgt = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            out.append(finding(
                "trivy", v.get("Severity", "UNKNOWN"),
                f"{v.get('VulnerabilityID','')} in {v.get('PkgName','')} {v.get('InstalledVersion','')}",
                tgt, v.get("Title", "")))
        for s in res.get("Secrets", []) or []:
            out.append(finding("trivy-secret", s.get("Severity", "HIGH"),
                               f"Secret: {s.get('RuleID','')}", f"{tgt}:{s.get('StartLine','')}", s.get("Title", "")))
        for m in res.get("Misconfigurations", []) or []:
            out.append(finding("trivy-misconfig", m.get("Severity", "MEDIUM"),
                               f"{m.get('ID','')}: {m.get('Title','')}", tgt, m.get("Message", "")))
    return out


def parse_checkov(stdout: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    try:
        data = json.loads(stdout)
    except Exception:  # noqa: BLE001
        return out
    blocks = data if isinstance(data, list) else [data]
    for b in blocks:
        results = (b or {}).get("results", {}) or {}
        for fc in results.get("failed_checks", []) or []:
            sev = (fc.get("severity") or "MEDIUM")
            out.append(finding("checkov", sev,
                               f"{fc.get('check_id','')}: {fc.get('check_name','')}",
                               f"{fc.get('file_path','')}:{fc.get('file_line_range','')}"))
    return out


def parse_nuclei(stdout: str) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except Exception:  # noqa: BLE001
            continue
        info = j.get("info", {}) or {}
        out.append(finding("nuclei", info.get("severity", "info"),
                           info.get("name", j.get("template-id", "finding")),
                           j.get("matched-at", j.get("host", "")), info.get("description", "")))
    return out


def _semgrep_sev(s: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get((s or "").upper(), "low")


def run_semgrep(path: str) -> List[Dict[str, str]]:
    if not shutil.which("semgrep"):
        log("… semgrep tidak ada di image, dilewati")
        return []
    log("🔎 semgrep --config auto …")
    try:
        proc = subprocess.run(
            ["semgrep", "--config", "auto", "--json", "--quiet", "--timeout", "0", path],
            capture_output=True, text=True, timeout=1800)
        data = json.loads(proc.stdout or "{}")
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  semgrep gagal: {exc}")
        return []
    out: List[Dict[str, str]] = []
    for r in data.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        sev = (extra.get("metadata", {}) or {}).get("security-severity") or extra.get("severity", "INFO")
        # security-severity kadang berupa angka CVSS; fallback ke severity teks.
        sev_txt = _semgrep_sev(extra.get("severity", "INFO"))
        out.append(finding("semgrep", sev_txt,
                           r.get("check_id", "rule"),
                           f"{r.get('path','')}:{(r.get('start',{}) or {}).get('line','')}",
                           (extra.get("message", "") or "")))
    return out


def run_gitleaks(path: str) -> List[Dict[str, str]]:
    if not shutil.which("gitleaks"):
        log("… gitleaks tidak ada di image, dilewati")
        return []
    log("🔎 gitleaks detect …")
    report = os.path.join(path, ".gitleaks-report.json")
    # Bila bukan repo git (mis. arsip yang di-upload tanpa .git), pakai --no-git
    # agar gitleaks memindai filesystem, bukan riwayat git.
    cmd = ["gitleaks", "detect", "--source", path, "--no-banner",
           "--report-format", "json", "--report-path", report, "--exit-code", "0"]
    if not os.path.isdir(os.path.join(path, ".git")):
        cmd.insert(2, "--no-git")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        with open(report, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  gitleaks gagal: {exc}")
        return []
    finally:
        if os.path.exists(report):
            os.remove(report)
    out: List[Dict[str, str]] = []
    for leak in data or []:
        out.append(finding("gitleaks", "high",
                           f"Secret: {leak.get('RuleID','')}",
                           f"{leak.get('File','')}:{leak.get('StartLine','')}",
                           leak.get("Description", "")))
    return out


# --------------------------------------------------------------------------- #
# Ringkasan AI opsional (vLLM) — advisory, tidak mempengaruhi gate
# --------------------------------------------------------------------------- #
def ai_summary(kind: str, target: str, findings: List[Dict[str, str]]) -> Optional[str]:
    try:
        from openai import OpenAI
    except ImportError:
        log("… paket openai tidak ada, ringkasan AI dilewati")
        return None
    model = os.environ.get("OPENAI_MODEL", "")
    if not model:
        log("… OPENAI_MODEL kosong, ringkasan AI dilewati")
        return None
    client = OpenAI(
        base_url=os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1"),
        api_key=os.environ.get("OPENAI_API_KEY", "EMPTY"),
    )
    top = sorted(findings, key=lambda f: -_rank(f["severity"]))[:40]
    prompt = (
        f"Anda analis keamanan. Ini hasil {kind} untuk '{target}'. "
        f"Ringkas risiko utama, kelompokkan per severity, dan beri rekomendasi remediasi "
        f"yang konkret & bisa ditindaklanjuti. Jawab ringkas dalam Bahasa Indonesia (markdown).\n\n"
        f"Temuan (JSON):\n{json.dumps(top, ensure_ascii=False)}"
    )
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as exc:  # noqa: BLE001
        log(f"⚠️  ringkasan AI gagal: {exc}")
        return None


# --------------------------------------------------------------------------- #
# Penulisan laporan & gating
# --------------------------------------------------------------------------- #
def write_reports(kind: str, target: str, findings: List[Dict[str, str]],
                  report_dir: str, ai_text: Optional[str]) -> Dict[str, Any]:
    os.makedirs(report_dir, exist_ok=True)
    counts = counts_by_severity(findings)
    summary = {
        "kind": kind,
        "target": target,
        "generated_at": _now(),
        "counts": counts,
        "total": len(findings),
        "findings": findings,
    }
    json_path = os.path.join(report_dir, f"hexstrike-{kind}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2)

    md_path = os.path.join(report_dir, f"hexstrike-{kind}.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(f"# HexStrike {kind} report\n\n")
        fh.write(f"- Target: `{target}`\n- Generated: {summary['generated_at']}\n")
        fh.write(f"- Total findings: **{len(findings)}**\n\n")
        fh.write("| severity | count |\n|---|---|\n")
        for s in reversed(SEVERITY_ORDER):
            fh.write(f"| {s} | {counts[s]} |\n")
        fh.write("\n## Top findings\n\n")
        for f in sorted(findings, key=lambda x: -_rank(x["severity"]))[:50]:
            fh.write(f"- **[{f['severity'].upper()}]** ({f['tool']}) {f['title']} — `{f['location']}`\n")
        if ai_text:
            fh.write("\n## AI triage (advisory)\n\n")
            fh.write(ai_text + "\n")

    log(f"📝 Laporan: {json_path} , {md_path}")
    return summary


def gate(counts: Dict[str, int], fail_on: str) -> int:
    threshold = _rank(fail_on)
    triggered = [s for s in SEVERITY_ORDER if _rank(s) >= threshold and counts.get(s, 0) > 0]
    if triggered:
        total = sum(counts.get(s, 0) for s in triggered)
        log(f"❌ GATE GAGAL: {total} temuan >= '{fail_on}' (severity: {', '.join(triggered)})")
        return 1
    log(f"✅ GATE LULUS: tidak ada temuan >= '{fail_on}'")
    return 0


# --------------------------------------------------------------------------- #
# Sub-perintah
# --------------------------------------------------------------------------- #
def cmd_code_scan(args: argparse.Namespace) -> int:
    hs = HexStrike(args.server)
    if not hs.wait_healthy():
        log("❌ HexStrike server tidak sehat")
        return 2
    path = os.path.abspath(args.path)
    findings: List[Dict[str, str]] = []

    log(f"🔬 trivy fs {path} (vuln, secret, misconfig)…")
    tv = hs.post("api/tools/trivy", {
        "scan_type": "fs", "target": path, "output_format": "json",
        "additional_args": "--scanners vuln,secret,misconfig --quiet --no-progress",
    })
    findings += parse_trivy(tv.get("stdout", ""))

    log(f"🔬 checkov -d {path} (IaC)…")
    cv = hs.post("api/tools/checkov", {
        "directory": path, "output_format": "json",
        "additional_args": "--compact --quiet",
    })
    findings += parse_checkov(cv.get("stdout", ""))

    findings += run_semgrep(path)
    findings += run_gitleaks(path)

    ai_text = ai_summary("code-scan", path, findings) if args.use_llm and findings else None
    summary = write_reports("code-scan", path, findings, args.report_dir, ai_text)
    log(f"📊 Ringkasan: {summary['counts']}")
    return gate(summary["counts"], args.fail_on)


def cmd_pentest(args: argparse.Namespace) -> int:
    hs = HexStrike(args.server)
    if not hs.wait_healthy():
        log("❌ HexStrike server tidak sehat")
        return 2
    target = args.target
    findings: List[Dict[str, str]] = []

    # Header auth opsional (authenticated scan): dari --auth-header dan/atau
    # env HEXSTRIKE_AUTH_HEADERS (dikirim webhook). Di-quote agar aman di shell.
    headers = list(getattr(args, "auth_header", None) or [])
    env_headers = os.environ.get("HEXSTRIKE_AUTH_HEADERS", "")
    if env_headers:
        headers += [h for h in env_headers.splitlines() if h.strip()]
    hdr_args = "".join(f" -H {shlex.quote(h)}" for h in headers)
    if headers:
        log(f"🔑 authenticated scan: {len(headers)} header auth disuntikkan")

    log(f"🌐 wafw00f {target}…")
    hs.post("api/tools/wafw00f", {"target": target})  # informatif

    log(f"🌐 httpx probe {target}…")
    hs.post("api/tools/httpx", {
        "target": target,
        "additional_args": f"-title -tech-detect -status-code -silent{hdr_args}",
    })

    sev = "low,medium,high,critical" if args.profile == "full" else "medium,high,critical"
    log(f"🔬 nuclei -u {target} -severity {sev}…")
    nu = hs.post("api/tools/nuclei", {
        "target": target, "severity": sev,
        "additional_args": f"-jsonl -silent -no-color{hdr_args}", "use_recovery": True,
    })
    findings += parse_nuclei(nu.get("stdout", ""))

    if args.profile == "full":
        log(f"🔬 nikto {target}…")
        nk = hs.post("api/tools/nikto", {"target": target})
        # nikto output non-terstruktur; catat sebagai info bila ada 'OSVDB'/'+ '
        raw = nk.get("stdout", "")
        for line in raw.splitlines():
            if line.strip().startswith("+ ") and ("OSVDB" in line or "vuln" in line.lower()):
                findings.append(finding("nikto", "low", line.strip()[:200], target))

    ai_text = ai_summary("pentest", target, findings) if args.use_llm and findings else None
    summary = write_reports("pentest", target, findings, args.report_dir, ai_text)
    log(f"📊 Ringkasan: {summary['counts']}")
    return gate(summary["counts"], args.fail_on)


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
    cs.set_defaults(func=cmd_code_scan)

    pt = sub.add_parser("pentest", help="DAST-style: scan hasil deploy")
    pt.add_argument("--target", required=True, help="URL/host hasil deploy")
    pt.add_argument("--profile", default=os.environ.get("HEXSTRIKE_PENTEST_PROFILE", "quick"),
                    choices=["quick", "full"])
    pt.add_argument("--auth-header", action="append", default=None,
                    help="Header auth utk authenticated scan (boleh berkali-kali), "
                         "mis. --auth-header 'Authorization: Bearer xxx'")
    pt.set_defaults(func=cmd_pentest)
    return p


def main() -> int:
    args = build_parser().parse_args()
    if args.fail_on == "none":
        # 'none' => tidak pernah gagal karena severity; set threshold di atas maksimum
        args.fail_on = "critical"
        os.environ["_HS_NEVER_FAIL"] = "1"
    rc = args.func(args)
    if os.environ.get("_HS_NEVER_FAIL") == "1":
        return 0
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
