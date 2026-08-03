"""Konstanta & utilitas severity — satu sumber kebenaran untuk seluruh library."""

# Urutan menaik (paling rendah -> paling tinggi)
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
# Urutan menurun (paling tinggi -> paling rendah) untuk tampilan/kolom
SEVERITIES = list(reversed(SEVERITY_ORDER))

SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

SEV_COLOR = {
    "critical": "#b3123b",
    "high": "#e5484d",
    "medium": "#f5a623",
    "low": "#e8c400",
    "info": "#3aa0ff",
}


def rank(sev: str) -> int:
    """Peringkat numerik severity (info=0 … critical=4). Tidak dikenal -> 0."""
    return SEV_RANK.get((sev or "info").strip().lower(), 0)
