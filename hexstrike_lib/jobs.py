"""Manajer job background: submit job, jalankan scanner CI sebagai subprocess,
kumpulkan ringkasan, simpan ke SQLite, dan pelihara status di memori."""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from . import db
from .config import CI_SCRIPT, DB_PATH, HEXSTRIKE_SERVER, REPORT_ROOT
from .logging_util import make_log

log = make_log("webhook")


def _utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class JobManager:
    def __init__(self) -> None:
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    # --- akses status ---
    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        return self._jobs.get(job_id)

    def all(self) -> List[Dict[str, Any]]:
        return list(self._jobs.values())

    def count(self) -> int:
        return len(self._jobs)

    # --- submit ---
    def submit(self, meta_extra: Dict[str, Any], params: Dict[str, Any],
               auth_headers: List[str]) -> str:
        job_id = uuid.uuid4().hex[:12]
        meta = {"id": job_id, "status": "queued", "started_at": _utcnow(), **meta_extra}
        with self._lock:
            self._jobs[job_id] = meta
        threading.Thread(target=self._run, args=(job_id, params, auth_headers), daemon=True).start()
        return job_id

    # --- eksekusi (thread) ---
    def _run(self, job_id: str, params: Dict[str, Any], auth_headers: List[str]) -> None:
        job = self._jobs[job_id]
        report_dir = os.path.join(REPORT_ROOT, job_id)
        os.makedirs(report_dir, exist_ok=True)

        env = os.environ.copy()
        if auth_headers:
            # Dikirim via env (tidak muncul di argv/ps, tidak di-log)
            env["HEXSTRIKE_AUTH_HEADERS"] = "\n".join(auth_headers)

        actions = ["code-scan", "pentest"] if params["action"] == "both" else [params["action"]]
        overall_rc = 0
        job["status"] = "running"
        for action in actions:
            rc = self._run_action(job_id, action, params, report_dir, env)
            overall_rc = overall_rc or rc
            self._collect(job, job_id, action, params, report_dir, rc, bool(auth_headers))

        job["status"] = "completed"
        job["exit_code"] = overall_rc
        job["gate_failed"] = overall_rc == 1
        job["finished_at"] = _utcnow()
        cleanup = params.get("cleanup_path")
        if cleanup and os.path.isdir(cleanup):
            shutil.rmtree(cleanup, ignore_errors=True)
        log(f"job {job_id}: selesai rc={overall_rc}")

    def _run_action(self, job_id: str, action: str, params: Dict[str, Any],
                    report_dir: str, env: Dict[str, str]) -> int:
        cmd = [
            sys.executable, CI_SCRIPT,
            "--server", HEXSTRIKE_SERVER,
            "--report-dir", report_dir,
            "--fail-on", params["fail_on"],
        ]
        if params.get("use_llm"):
            cmd.append("--use-llm")
        if action == "pentest":
            cmd += ["pentest", "--target", params["target"], "--profile", params["profile"]]
        else:
            cmd += ["code-scan", "--path", params.get("path", ".")]

        log(f"job {job_id}: menjalankan {action} -> {params.get('target')}")
        logfile = os.path.join(report_dir, f"{action}.log")
        try:
            with open(logfile, "w", encoding="utf-8") as lf:
                proc = subprocess.run(cmd, env=env, stdout=lf, stderr=subprocess.STDOUT, timeout=7200)
            return proc.returncode
        except Exception as exc:  # noqa: BLE001
            with open(logfile, "a", encoding="utf-8") as lf:
                lf.write(f"\nERROR: {exc}\n")
            return 2

    def _collect(self, job: Dict[str, Any], job_id: str, action: str,
                 params: Dict[str, Any], report_dir: str, rc: int, authenticated: bool) -> None:
        summary_path = os.path.join(report_dir, f"hexstrike-{action}.json")
        if not os.path.exists(summary_path):
            return
        try:
            with open(summary_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:  # noqa: BLE001
            return
        counts = data.get("counts", {})
        job.setdefault("results", {})[action] = {
            "counts": counts,
            "total": data.get("total", 0),
            "gate_failed": rc == 1,
        }
        try:
            db.save_report(
                DB_PATH, run_id=f"{job_id}:{action}", job_id=job_id, kind=action,
                target=params.get("target", ""), fail_on=params["fail_on"],
                status="completed", gate_failed=(rc == 1), exit_code=rc,
                counts=counts, findings=data.get("findings", []),
                started_at=job.get("started_at"), finished_at=_utcnow(),
                authenticated=authenticated,
            )
        except Exception as exc:  # noqa: BLE001
            log(f"⚠️  gagal simpan ke DB: {exc}")
