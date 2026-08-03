"""Ekstraksi arsip upload (tar.gz/tgz/tar/zip) dengan aman (cegah path traversal)."""

import os
import tarfile
import zipfile


def safe_extract(archive_path: str, dest: str) -> None:
    os.makedirs(dest, exist_ok=True)
    lower = archive_path.lower()
    if lower.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive_path) as tf:
            tf.extractall(dest, filter="data")  # Python 3.12+: filter cegah traversal
    elif lower.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as zf:
            root = os.path.realpath(dest)
            for member in zf.namelist():
                target = os.path.realpath(os.path.join(dest, member))
                if not target.startswith(root + os.sep) and target != root:
                    raise ValueError(f"unsafe path in zip: {member}")
            zf.extractall(dest)
    else:
        raise ValueError("format arsip harus .tar.gz/.tgz/.tar/.zip")
