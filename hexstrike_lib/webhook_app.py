"""Flask app factory untuk service webhook + main(). Hanya merangkai modul lain
(auth, jobs, archive, dashboard, db); tidak berisi logika scan.

Endpoint:
  GET  /health
  POST /trigger                -> mulai scan/pentest (butuh token)
  POST /scan/code              -> upload arsip repo -> code-scan (butuh token)
  GET  /status/<job_id>        -> status job
  GET  /jobs                   -> daftar job
  GET  /dashboard[/<id>]       -> dashboard metrik / detail (view auth)
  GET  /api/metrics|reports    -> agregat JSON (view auth)
"""

import os
import re
import shutil

import requests
from flask import Flask, Response, jsonify, request

from . import config, dashboard, db
from .auth import auth_mode, request_authorized, view_authorized
from .auth_headers import build_auth_headers
from .archive import safe_extract
from .jobs import JobManager
from .logging_util import make_log
from .server_control import maybe_autostart_server

log = make_log("webhook")

# Target aman: scheme opsional, host domain/IP, port, path sederhana. Tolak char shell.
TARGET_RE = re.compile(r"^(?:https?://)?[A-Za-z0-9._\-]+(?::\d{1,5})?(?:/[A-Za-z0-9._~:/%?#\[\]@!$&'()*+,;=\-]*)?$")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_UPLOAD_MB * 1024 * 1024
    jobs = JobManager()

    # ----------------------------- health ---------------------------------- #
    @app.route("/health", methods=["GET"])
    def health():
        try:
            server_ok = requests.get(f"{config.HEXSTRIKE_SERVER}/health", timeout=5).ok
        except Exception:  # noqa: BLE001
            server_ok = False
        return jsonify({
            "status": "ok",
            "hexstrike_server": config.HEXSTRIKE_SERVER,
            "hexstrike_server_healthy": server_ok,
            "auth": auth_mode(),
            "jobs": jobs.count(),
        })

    # ----------------------------- trigger --------------------------------- #
    @app.route("/trigger", methods=["POST"])
    def trigger():
        if not request_authorized(request):
            return jsonify({"error": "unauthorized"}), 401

        body = request.get_json(silent=True) or {}
        target = (body.get("target") or "").strip()
        action = (body.get("action") or "pentest").lower()
        profile = (body.get("profile") or "quick").lower()
        fail_on = (body.get("fail_on") or config.DEFAULT_FAIL_ON).lower()

        if action not in config.VALID_ACTIONS:
            return jsonify({"error": f"action invalid (pilih: {sorted(config.VALID_ACTIONS)})"}), 400
        if profile not in config.VALID_PROFILES:
            return jsonify({"error": "profile invalid (quick|full)"}), 400
        if fail_on not in config.VALID_FAIL_ON:
            return jsonify({"error": "fail_on invalid"}), 400
        if action in {"pentest", "both"} and (not target or not TARGET_RE.match(target)):
            return jsonify({"error": "target (domain/IP/URL) wajib & harus valid tanpa karakter shell"}), 400

        auth_headers = build_auth_headers(body.get("auth"))
        params = {
            "target": target, "action": action, "profile": profile, "fail_on": fail_on,
            "path": body.get("path", "."), "use_llm": bool(body.get("use_llm", False)),
        }
        meta = {"action": action, "target": target, "profile": profile,
                "fail_on": fail_on, "authenticated": bool(auth_headers)}
        job_id = jobs.submit(meta, params, auth_headers)
        return jsonify({"job_id": job_id, "status": "accepted"}), 202

    # ----------------------------- scan/code ------------------------------- #
    @app.route("/scan/code", methods=["POST"])
    def scan_code():
        if not request_authorized(request):
            return jsonify({"error": "unauthorized"}), 401
        if "file" not in request.files:
            return jsonify({"error": "field 'file' (arsip repo) wajib"}), 400

        fail_on = (request.form.get("fail_on") or config.DEFAULT_FAIL_ON).lower()
        if fail_on not in config.VALID_FAIL_ON:
            return jsonify({"error": "fail_on invalid"}), 400
        use_llm = str(request.form.get("use_llm", "false")).lower() in {"1", "true", "yes"}

        # Simpan & ekstrak upload ke dir sementara (job_id sementara utk penamaan)
        import uuid
        tmp_id = uuid.uuid4().hex[:12]
        job_dir = os.path.join(config.REPORT_ROOT, tmp_id)
        src_dir = os.path.join(job_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        upload = request.files["file"]
        archive_name = upload.filename or "upload.tar.gz"
        archive_path = os.path.join(job_dir, os.path.basename(archive_name))
        upload.save(archive_path)
        try:
            safe_extract(archive_path, src_dir)
        except Exception as exc:  # noqa: BLE001
            shutil.rmtree(job_dir, ignore_errors=True)
            return jsonify({"error": f"gagal ekstrak arsip: {exc}"}), 400
        finally:
            if os.path.exists(archive_path):
                os.remove(archive_path)

        params = {
            "target": archive_name, "action": "code-scan", "profile": "quick",
            "fail_on": fail_on, "path": src_dir, "cleanup_path": src_dir, "use_llm": use_llm,
        }
        meta = {"action": "code-scan", "target": archive_name, "fail_on": fail_on}
        job_id = jobs.submit(meta, params, [])
        return jsonify({"job_id": job_id, "status": "accepted"}), 202

    # ----------------------------- status/jobs ----------------------------- #
    @app.route("/status/<job_id>", methods=["GET"])
    def status(job_id: str):
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "job tidak ditemukan"}), 404
        return jsonify(job)

    @app.route("/jobs", methods=["GET"])
    def list_jobs():
        return jsonify({"jobs": jobs.all()})

    # ----------------------------- dashboard/api --------------------------- #
    @app.route("/dashboard", methods=["GET"])
    def dashboard_home():
        if not view_authorized(request):
            return Response("unauthorized (append ?token=...)", status=401, mimetype="text/plain")
        return Response(dashboard.render_dashboard(config.DB_PATH, token=request.args.get("token")),
                        mimetype="text/html")

    @app.route("/dashboard/<path:ident>", methods=["GET"])
    def dashboard_detail(ident: str):
        if not view_authorized(request):
            return Response("unauthorized (append ?token=...)", status=401, mimetype="text/plain")
        return Response(dashboard.render_report_detail(config.DB_PATH, ident, token=request.args.get("token")),
                        mimetype="text/html")

    @app.route("/api/metrics", methods=["GET"])
    def api_metrics():
        if not view_authorized(request):
            return jsonify({"error": "unauthorized"}), 401
        return jsonify(db.get_metrics(config.DB_PATH))

    @app.route("/api/reports", methods=["GET"])
    def api_reports():
        if not view_authorized(request):
            return jsonify({"error": "unauthorized"}), 401
        return jsonify(db.get_metrics(config.DB_PATH).get("recent", []))

    @app.route("/api/reports/<path:ident>", methods=["GET"])
    def api_report_detail(ident: str):
        if not view_authorized(request):
            return jsonify({"error": "unauthorized"}), 401
        reports = db.get_reports_by_id(config.DB_PATH, ident)
        if not reports:
            return jsonify({"error": "report tidak ditemukan"}), 404
        return jsonify(reports)

    return app


def main() -> int:
    os.makedirs(config.REPORT_ROOT, exist_ok=True)
    db.init_db(config.DB_PATH)
    if not config.WEBHOOK_TOKEN and not config.WEBHOOK_HMAC_SECRET:
        log("⚠️  WEBHOOK_TOKEN / WEBHOOK_HMAC_SECRET belum di-set — /trigger akan menolak semua request.")
    maybe_autostart_server()
    log(f"📊 dashboard: http://0.0.0.0:{config.WEBHOOK_PORT}/dashboard  (db: {config.DB_PATH})")
    log(f"listening on 0.0.0.0:{config.WEBHOOK_PORT} (HexStrike server: {config.HEXSTRIKE_SERVER})")
    create_app().run(host="0.0.0.0", port=config.WEBHOOK_PORT, threaded=True)
    return 0
