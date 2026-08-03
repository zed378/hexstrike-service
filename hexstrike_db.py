#!/usr/bin/env python3
"""Shim kompatibilitas — kode dipindah ke paket hexstrike_lib.

  penyimpanan  -> hexstrike_lib.db
  dashboard    -> hexstrike_lib.dashboard

Dipertahankan agar import lama `import hexstrike_db` tetap berfungsi.
"""

from hexstrike_lib.db import (  # noqa: F401
    get_metrics,
    get_report,
    get_reports_by_id,
    init_db,
    save_report,
)
from hexstrike_lib.dashboard import (  # noqa: F401
    render_dashboard,
    render_report_detail,
)
