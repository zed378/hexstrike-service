"""Namespace bersama untuk semua route blueprint (`from ...deps import *`).

Meng-ekspor SEMUA yang mungkin dirujuk body route: execute_command core, seluruh
singleton, scan helpers, ModernVisualEngine, model, KELAS subsistem (CTFChallenge,
BugBountyTarget, dll.), util Flask, dan stdlib — agar tak ada NameError lintas file.
"""

import base64  # noqa: F401
import hashlib  # noqa: F401
import json  # noqa: F401
import logging
import os  # noqa: F401
import re  # noqa: F401
import subprocess  # noqa: F401
import sys  # noqa: F401
import time  # noqa: F401
from datetime import datetime  # noqa: F401
from typing import Any, Dict, List, Optional, Set, Tuple, Union  # noqa: F401

import requests  # noqa: F401
from flask import (  # noqa: F401
    Blueprint, Response, abort, jsonify, make_response, request, send_file,
)

# execute_command core + runtime singletons + config
from .execution import *          # noqa: F401,F403
# registry singletons (decision_engine, cve_intelligence, exploit_generator, dst.)
from .context import *            # noqa: F401,F403
# shared scan helpers (execute_*_scan)
from .scan_helpers import *       # noqa: F401,F403
from .visual import ModernVisualEngine  # noqa: F401
# enums & dataclasses
from .models import *             # noqa: F401,F403
# KELAS subsistem yang dirujuk langsung oleh body route (CTFChallenge, BugBountyTarget, dll.)
from .ctf import *                # noqa: F401,F403
from .bugbounty import *          # noqa: F401,F403
from .cve_intel import *          # noqa: F401,F403
from .decision_engine import *    # noqa: F401,F403
from .errors import *             # noqa: F401,F403
from .analyzers import *          # noqa: F401,F403
from .correlator import *         # noqa: F401,F403
from .file_ops import *           # noqa: F401,F403
from .http_framework import *     # noqa: F401,F403
from .browser_agent import *      # noqa: F401,F403
from .exploits import *           # noqa: F401,F403
from .payload_generator import *  # noqa: F401,F403

API_PORT = int(os.environ.get("HEXSTRIKE_PORT", 8888))
API_HOST = os.environ.get("HEXSTRIKE_HOST", "127.0.0.1")
logger = logging.getLogger("hexstrike")
