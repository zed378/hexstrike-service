"""Helper log sederhana (stdout, flush) dengan prefix opsional."""

from typing import Callable


def make_log(prefix: str = "") -> Callable[[str], None]:
    tag = f"[{prefix}] " if prefix else ""

    def log(msg: str) -> None:
        print(f"{tag}{msg}", flush=True)

    return log
