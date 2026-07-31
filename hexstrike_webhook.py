#!/usr/bin/env python3
"""
HexStrike AI — Webhook trigger (post-deploy)
============================================

Service kecil (Flask) untuk MEMICU security scan / pentest on-demand via HTTP,
mis. dipanggil otomatis oleh sistem CD Anda setelah deploy selesai.

Endpoint:
  GET  /health                 -> status service
  POST /trigger                -> mulai scan (butuh token) ; balas {job_id}
  GET  /status/<job_id>        -> status & ringkasan temuan sebuah job
  GET  /jobs                   -> daftar job

Contoh panggilan:
  curl -X POST http://webhook-host:9000/trigger \
    -H "X-Webhook-Token: $WEBHOOK_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
          "target": "https://staging.aplikasi-saya.example",
          "action": "pentest",
          "profile": "quick",
          "fail_on": "high",
          "auth": { "type": "bearer", "token": "eyJ..." }
        }'

Bentuk "auth" (opsional, untuk authenticated scan):
  {"type":"bearer","token":"..."}                         -> Authorization: Bearer ...
  {"type":"basic","username":"u","password":"p"}          -> Authorization: Basic base64(u:p)
  {"type":"cookie","cookie":"sid=abc; other=1"}           -> Cookie: ...
  {"type":"header","headers":["X-Api-Key: k","X-Env: qa"]} -> header mentah (list/str)

KEAMANAN:
  - Wajib set WEBHOOK_TOKEN (atau WEBHOOK_HMAC_SECRET untuk verifikasi HMAC).
  - Creds TIDAK di-log dan TIDAK muncul di daftar proses (dikirim via env ke subprocess).
  - Target divalidasi untuk menolak karakter shell berbahaya.
  - Jalankan HANYA terhadap aset yang Anda miliki/berwenang.

ENV:
  WEBHOOK_TOKEN            token bearer sederhana (header X-Webhook-Token)
  WEBHOOK_HMAC_SECRET      (opsional) rahasia HMAC; verifikasi X-Hub-Signature-256
  WEBHOOK_PORT             default 9000
  HEXSTRIKE_SERVER         default http://localhost:8888
  HEXSTRIKE_AUTOSTART_SERVER  "1" -> nyalakan hexstrike_server.py otomatis
  HEXSTRIKE_REPORT_ROOT    default ./hexstrike-reports
  HEXSTRIKE_DEFAULT_FAIL_ON  default high
"""

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import uuid
import zipfile
from typing import Any, Dict, List, Optional

import requests
from flask import Flask, jsonify, request, Response

import hexstrike_db as db

HERE = os.path.dirname(os.path.abspath(__file__))
CI_SCRIPT = os.path.join(HERE, "hexstrike_ci.py")
SERVER_SCRIPT = os.path.join(HERE, "hexstrike_server.py")

HEXSTRIKE_SERVER = os.environ.get("HEXSTRIKE_SERVER", "http://localhost:8888")
REPORT_ROOT = os.environ.get("HEXSTRIKE_REPORT_ROOT", os.path.join(HERE, "hexstrike-reports"))
DB_PATH = os.environ.get("HEXSTRIKE_DB_PATH", os.path.join(REPORT_ROOT, "hexstrike.db"))
DEFAULT_FAIL_ON = os.environ.get("HEXSTRIKE_DEFAULT_FAIL_ON", "high")
WEBHOOK_TOKEN = os.environ.get("WEBHOOK_TOKEN", "")
WEBHOOK_HMAC_SECRET = os.environ.get("WEBHOOK_HMAC_SECRET", "")
WEBHOOK_PORT = int(os.environ.get("WEBHOOK_PORT", "9000"))
MAX_UPLOAD_MB = int(os.environ.get("HEXSTRIKE_MAX_UPLOAD_MB", "300"))

VALID_ACTIONS = {"pentest", "code-scan", "both"}
VALID_PROFILES = {"quick", "full"}
VALID_FAIL_ON = {"none", "info", "low", "medium", "high", "critical"}
# Target aman: scheme opsional, host domain/IP, port, path sederhana. Tolak char shell.
TARGET_RE = re.compile(r"^(?:https?://)?[A-Za-z0-9._\-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~:/%?#\[\]@!$&'()*+,;=\-]*)?$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
_JOBS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()


def log(msg: str) -> None:
    print(f"[webhook] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Autentikasi request
# --------------------------------------------------------------------------- #
def authorized(req) -> bool:
    if WEBHOOK_HMAC_SECRET:
        sig = req.headers.get("X-Hub-Signature-256", "")
        if not sig.startswith("sha256="):
            return False
        digest = hmac.new(WEBHOOK_HMAC_SECRET.encode(), req.get_data(), hashlib.sha256).hexdigest()
        return hmac.compare_digest("sha256=" + digest, sig)
    if WEBHOOK_TOKEN:
        provided = req.headers.get("X-Webhook-Token", "")
        return hmac.compare_digest(provided, WEBHOOK_TOKEN)
    return False  # tidak ada kredensial dikonfigurasi -> tolak semua


# --------------------------------------------------------------------------- #
# Bangun header auth (untuk authenticated scan) tanpa membocorkan ke log
# --------------------------------------------------------------------------- #
def build_auth_headers(auth: Optional[Dict[str, Any]]) -> List[str]:
    if not auth or not isinstance(auth, dict):
        return []
    atype = (auth.get("type") or "").lower()
    if atype == "bearer" and auth.get("token"):
        return [f"Authorization: Bearer {auth['token']}"]
    if atype == "basic" and auth.get("username") is not None:
        raw = f"{auth.get('username','')}:{auth.get('password','')}".encode()
        return [f"Authorization: Basic {base64.b64encode(raw).decode()}"]
    if atype == "cookie" and auth.get("cookie"):
        return [f"Cookie: {auth['cookie']}"]
    if atype == "header":
        h = auth.get("headers") or auth.get("header") or []
        if isinstance(h, str):
            h = [h]
        return [str(x) for x in h]
    return []


# --------------------------------------------------------------------------- #
# Jalankan scan di background
# --------------------------------------------------------------------------- #
def run_job(job_id: str, params: Dict[str, Any], auth_headers: List[str]) -> None:
    job = _JOBS[job_id]
    report_dir = os.path.join(REPORT_ROOT, job_id)
    os.makedirs(report_dir, exist_ok=True)

    env = os.environ.copy()
    if auth_headers:
        # Dikirim via env (tidak muncul di argv/ps, tidak di-log webhook)
        env["HEXSTRIKE_AUTH_HEADERS"] = "\n".join(auth_headers)

    actions = ["code-scan", "pentest"] if params["action"] == "both" else [params["action"]]
    overall_rc = 0
    job["status"] = "running"
    for action in actions:
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

        log(f"job {job_id}: menjalankan {action} -> {params['target']}")
        logfile = os.path.join(report_dir, f"{action}.log")
        try:
            with open(logfile, "w", encoding="utf-8") as lf:
                proc = subprocess.run(cmd, env=env, stdout=lf, stderr=subprocess.STDOUT, timeout=7200)
            rc = proc.returncode
        except Exception as exc:  # noqa: BLE001
            rc = 2
            with open(logfile, "a", encoding="utf-8") as lf:
                lf.write(f"\nERROR: {exc}\n")
        overall_rc = overall_rc or rc

        # Baca ringkasan bila ada + simpan ke SQLite untuk dashboard
        summary_path = os.path.join(report_dir, f"hexstrike-{action}.json")
        if os.path.exists(summary_path):
            try:
                with open(summary_path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
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
                        started_at=job.get("started_at"),
                        finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        authenticated=bool(auth_headers),
                    )
                except Exception as exc:  # noqa: BLE001
                    log(f"⚠️  gagal simpan ke DB: {exc}")
            except Exception:  # noqa: BLE001
                pass

    job["status"] = "completed"
    job["exit_code"] = overall_rc
    job["gate_failed"] = overall_rc == 1
    job["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # Hapus source yang di-upload (bila ada) setelah selesai
    cleanup = params.get("cleanup_path")
    if cleanup and os.path.isdir(cleanup):
        shutil.rmtree(cleanup, ignore_errors=True)
    log(f"job {job_id}: selesai rc={overall_rc}")


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.route("/health", methods=["GET"])
def health():
    server_ok = False
    try:
        server_ok = requests.get(f"{HEXSTRIKE_SERVER}/health", timeout=5).ok
    except Exception:  # noqa: BLE001
        server_ok = False
    return jsonify({
        "status": "ok",
        "hexstrike_server": HEXSTRIKE_SERVER,
        "hexstrike_server_healthy": server_ok,
        "auth": "hmac" if WEBHOOK_HMAC_SECRET else ("token" if WEBHOOK_TOKEN else "DISABLED"),
        "jobs": len(_JOBS),
    })


@app.route("/trigger", methods=["POST"])
def trigger():
    if not authorized(request):
        return jsonify({"error": "unauthorized"}), 401

    body = request.get_json(silent=True) or {}
    target = (body.get("target") or "").strip()
    action = (body.get("action") or "pentest").lower()
    profile = (body.get("profile") or "quick").lower()
    fail_on = (body.get("fail_on") or DEFAULT_FAIL_ON).lower()

    if action not in VALID_ACTIONS:
        return jsonify({"error": f"action invalid (pilih: {sorted(VALID_ACTIONS)})"}), 400
    if profile not in VALID_PROFILES:
        return jsonify({"error": "profile invalid (quick|full)"}), 400
    if fail_on not in VALID_FAIL_ON:
        return jsonify({"error": "fail_on invalid"}), 400
    # target wajib untuk pentest/both
    if action in {"pentest", "both"}:
        if not target or not TARGET_RE.match(target):
            return jsonify({"error": "target (domain/IP/URL) wajib & harus valid tanpa karakter shell"}), 400

    auth_headers = build_auth_headers(body.get("auth"))

    job_id = uuid.uuid4().hex[:12]
    params = {
        "target": target,
        "action": action,
        "profile": profile,
        "fail_on": fail_on,
        "path": body.get("path", "."),
        "use_llm": bool(body.get("use_llm", False)),
    }
    with _LOCK:
        _JOBS[job_id] = {
            "id": job_id,
            "status": "queued",
            "action": action,
            "target": target,          # target dicatat; creds TIDAK
            "profile": profile,
            "fail_on": fail_on,
            "authenticated": bool(auth_headers),
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    threading.Thread(target=run_job, args=(job_id, params, auth_headers), daemon=True).start()
    return jsonify({"job_id": job_id, "status": "accepted"}), 202


def _safe_extract(archive_path: str, dest: str) -> None:
    """Ekstrak tar.gz/tgz/zip dengan aman (cegah path traversal)."""
    os.makedirs(dest, exist_ok=True)
    lower = archive_path.lower()
    if lower.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive_path) as tf:
            tf.extractall(dest, filter="data")  # Python 3.12+: filter cegah traversal
    elif lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            for member in zf.namelist():
                target = os.path.realpath(os.path.join(dest, member))
                if not target.startswith(os.path.realpath(dest) + os.sep) and target != os.path.realpath(dest):
                    raise ValueError(f"unsafe path in zip: {member}")
            zf.extractall(dest)
    else:
        raise ValueError("format arsip harus .tar.gz/.tgz/.tar/.zip")


@app.route("/scan/code", methods=["POST"])
def scan_code():
    """Upload arsip repo lalu jalankan code-scan (SAST) di server.

    multipart/form-data:
      file      : arsip repo (.tar.gz/.tgz/.zip)
      fail_on   : (opsional) none|info|low|medium|high|critical
      use_llm   : (opsional) "true"/"false"
    """
    if not authorized(request):
        return jsonify({"error": "unauthorized"}), 401
    if "file" not in request.files:
        return jsonify({"error": "field 'file' (arsip repo) wajib"}), 400

    fail_on = (request.form.get("fail_on") or DEFAULT_FAIL_ON).lower()
    if fail_on not in VALID_FAIL_ON:
        return jsonify({"error": "fail_on invalid"}), 400
    use_llm = str(request.form.get("use_llm", "false")).lower() in {"1", "true", "yes"}

    job_id = uuid.uuid4().hex[:12]
    job_dir = os.path.join(REPORT_ROOT, job_id)
    src_dir = os.path.join(job_dir, "src")
    os.makedirs(src_dir, exist_ok=True)
    upload = request.files["file"]
    archive_name = upload.filename or "upload.tar.gz"
    archive_path = os.path.join(job_dir, os.path.basename(archive_name))
    upload.save(archive_path)
    try:
        _safe_extract(archive_path, src_dir)
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(job_dir, ignore_errors=True)
        return jsonify({"error": f"gagal ekstrak arsip: {exc}"}), 400
    finally:
        if os.path.exists(archive_path):
            os.remove(archive_path)

    params = {
        "target": archive_name,
        "action": "code-scan",
        "profile": "quick",
        "fail_on": fail_on,
        "path": src_dir,
        "cleanup_path": src_dir,
        "use_llm": use_llm,
    }
    with _LOCK:
        _JOBS[job_id] = {
            "id": job_id,
            "status": "queued",
            "action": "code-scan",
            "target": archive_name,
            "fail_on": fail_on,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    threading.Thread(target=run_job, args=(job_id, params, []), daemon=True).start()
    return jsonify({"job_id": job_id, "status": "accepted"}), 202


# --------------------------------------------------------------------------- #
# Dashboard metrik + API (baca dari SQLite)
# Proteksi: bila WEBHOOK_TOKEN di-set, view butuh token via header X-Webhook-Token
# atau query ?token=... (ramah browser). Bila tak ada token dikonfigurasi -> terbuka
# (mode dev) — di produksi lindungi juga di reverse proxy (NPM Access List).
# --------------------------------------------------------------------------- #
def view_authorized(req) -> bool:
    if not WEBHOOK_TOKEN:
        return True
    provided = req.headers.get("X-Webhook-Token", "") or req.args.get("token", "")
    return hmac.compare_digest(provided, WEBHOOK_TOKEN)


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if not view_authorized(request):
        return Response("unauthorized (append ?token=...)", status=401, mimetype="text/plain")
    return Response(db.render_dashboard(DB_PATH, token=request.args.get("token")), mimetype="text/html")


@app.route("/dashboard/<path:ident>", methods=["GET"])
def dashboard_detail(ident: str):
    if not view_authorized(request):
        return Response("unauthorized (append ?token=...)", status=401, mimetype="text/plain")
    return Response(db.render_report_detail(DB_PATH, ident, token=request.args.get("token")), mimetype="text/html")


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    if not view_authorized(request):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(db.get_metrics(DB_PATH))


@app.route("/api/reports", methods=["GET"])
def api_reports():
    if not view_authorized(request):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(db.get_metrics(DB_PATH).get("recent", []))


@app.route("/api/reports/<path:ident>", methods=["GET"])
def api_report_detail(ident: str):
    if not view_authorized(request):
        return jsonify({"error": "unauthorized"}), 401
    reports = db.get_reports_by_id(DB_PATH, ident)
    if not reports:
        return jsonify({"error": "report tidak ditemukan"}), 404
    return jsonify(reports)


@app.route("/status/<job_id>", methods=["GET"])
def status(job_id: str):
    job = _JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job tidak ditemukan"}), 404
    return jsonify(job)


@app.route("/jobs", methods=["GET"])
def jobs():
    return jsonify({"jobs": list(_JOBS.values())})


# --------------------------------------------------------------------------- #
# Autostart HexStrike server (opsional)
# --------------------------------------------------------------------------- #
def maybe_autostart_server() -> None:
    if os.environ.get("HEXSTRIKE_AUTOSTART_SERVER", "").lower() not in {"1", "true", "yes"}:
        return
    if not os.path.exists(SERVER_SCRIPT):
        log(f"AUTOSTART: {SERVER_SCRIPT} tidak ada, dilewati")
        return
    log("AUTOSTART: menyalakan hexstrike_server.py di background…")
    subprocess.Popen(
        [sys.executable, SERVER_SCRIPT, "--port", "8888"],
        stdout=open(os.path.join(HERE, "hexstrike-autostart.log"), "w"),
        stderr=subprocess.STDOUT,
        cwd=HERE,
    )
    for i in range(1, 41):
        try:
            if requests.get(f"{HEXSTRIKE_SERVER}/health", timeout=5).ok:
                log(f"AUTOSTART: server sehat (percobaan {i})")
                return
        except Exception:  # noqa: BLE001
            pass
        time.sleep(3)
    log("AUTOSTART: server belum sehat setelah menunggu (lanjut tetap)")


def main() -> int:
    os.makedirs(REPORT_ROOT, exist_ok=True)
    db.init_db(DB_PATH)
    if not WEBHOOK_TOKEN and not WEBHOOK_HMAC_SECRET:
        log("⚠️  WEBHOOK_TOKEN / WEBHOOK_HMAC_SECRET belum di-set — /trigger akan menolak semua request.")
    maybe_autostart_server()
    log(f"📊 dashboard: http://0.0.0.0:{WEBHOOK_PORT}/dashboard  (db: {DB_PATH})")
    log(f"listening on 0.0.0.0:{WEBHOOK_PORT} (HexStrike server: {HEXSTRIKE_SERVER})")
    app.run(host="0.0.0.0", port=WEBHOOK_PORT, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
