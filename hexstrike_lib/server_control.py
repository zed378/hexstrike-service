"""Autostart proses hexstrike_server.py di background (opsional, utk image webhook)."""

import os
import subprocess
import sys
import time

import requests

from .config import AUTOSTART_SERVER, HEXSTRIKE_SERVER, ROOT, SERVER_SCRIPT
from .logging_util import make_log

log = make_log("webhook")


def maybe_autostart_server() -> None:
    if not AUTOSTART_SERVER:
        return
    if not os.path.exists(SERVER_SCRIPT):
        log(f"AUTOSTART: {SERVER_SCRIPT} tidak ada, dilewati")
        return
    log("AUTOSTART: menyalakan hexstrike_server.py di background…")
    subprocess.Popen(
        [sys.executable, SERVER_SCRIPT, "--port", "8888"],
        stdout=open(os.path.join(ROOT, "hexstrike-autostart.log"), "w"),
        stderr=subprocess.STDOUT,
        cwd=ROOT,
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
