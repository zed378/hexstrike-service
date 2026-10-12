"""VulnerabilityCorrelator (dipisah dari hexstrike_server.py)."""

import json  # noqa: F401
import logging
import os  # noqa: F401
import re  # noqa: F401
import shutil  # noqa: F401
import subprocess  # noqa: F401
import time  # noqa: F401
from datetime import datetime  # noqa: F401
from pathlib import Path  # noqa: F401
from typing import Any, Dict, List, Optional, Set, Tuple, Union  # noqa: F401

import requests  # noqa: F401

from .visual import ModernVisualEngine  # noqa: F401

logger = logging.getLogger(__name__)


class VulnerabilityCorrelator:
    """Correlate vulnerabilities for multi-stage attack chain discovery.

    `cve_manager`: instance opsional CVEIntelligenceManager (lihat cve_intel.py) yang
    dipakai untuk query NVD REAL per software/pattern. Tanpa itu, correlator tidak
    akan mengarang CVE palsu — dia mengembalikan hasil kosong dan bilang kenapa,
    daripada menyodorkan data mock yang kelihatan seperti temuan asli.
    """

    def __init__(self, cve_manager=None):
        self.cve_manager = cve_manager
        self.attack_patterns = {
            "privilege_escalation": ["local", "kernel", "suid", "sudo", "privilege"],
            "remote_execution": ["remote", "network", "rce", "code execution", "injection"],
            "persistence": ["service", "registry", "scheduled", "startup", "backdoor"],
            "lateral_movement": ["smb", "wmi", "ssh", "rdp", "lateral"],
            "data_exfiltration": ["file", "database", "memory", "disclosure", "exfiltration"],
        }

        self.software_relationships = {
            "windows": ["iis", "office", "exchange", "sharepoint"],
            "linux": ["apache", "nginx", "mysql", "postgresql"],
            "web": ["php", "nodejs", "python", "java"],
            "database": ["mysql", "postgresql", "oracle", "mssql"]
        }

    def find_attack_chains(self, target_software, max_depth=3):
        """Find multi-vulnerability attack chains berdasarkan CVE NYATA (NVD) bila
        `cve_manager` tersedia; jika tidak, hanya mengembalikan struktur kosong +
        alasan, TANPA fallback ke data mock (lihat juga `correlate_scan_findings`
        untuk korelasi dari hasil scan HexStrike, bukan dari nama software saja)."""
        try:
            if not self.cve_manager:
                return {
                    "success": True,
                    "target_software": target_software,
                    "total_chains": 0,
                    "attack_chains": [],
                    "recommendation": (
                        "CVE intelligence manager tidak terpasang — tidak ada data CVE nyata "
                        "untuk dikorelasikan, jadi tidak ada chain yang dibuat (lihat "
                        "server/context.py: VulnerabilityCorrelator(cve_intelligence))."
                    ),
                }

            chains = []

            # Example attack chain discovery logic
            base_software = target_software.lower()

            # Find initial access vulnerabilities
            initial_vulns = self._find_vulnerabilities_by_pattern(base_software, "remote_execution")

            for initial_vuln in initial_vulns[:3]:  # Limit for demo
                chain = {
                    "chain_id": f"chain_{len(chains) + 1}",
                    "target": target_software,
                    "stages": [
                        {
                            "stage": 1,
                            "objective": "Initial Access",
                            "vulnerability": initial_vuln,
                            "success_probability": 0.75
                        }
                    ],
                    "overall_probability": 0.75,
                    "complexity": "MEDIUM"
                }

                # Find privilege escalation
                priv_esc_vulns = self._find_vulnerabilities_by_pattern(base_software, "privilege_escalation")
                if priv_esc_vulns:
                    chain["stages"].append({
                        "stage": 2,
                        "objective": "Privilege Escalation",
                        "vulnerability": priv_esc_vulns[0],
                        "success_probability": 0.60
                    })
                    chain["overall_probability"] *= 0.60

                # Find persistence
                persistence_vulns = self._find_vulnerabilities_by_pattern(base_software, "persistence")
                if persistence_vulns and len(chain["stages"]) < max_depth:
                    chain["stages"].append({
                        "stage": 3,
                        "objective": "Persistence",
                        "vulnerability": persistence_vulns[0],
                        "success_probability": 0.80
                    })
                    chain["overall_probability"] *= 0.80

                chains.append(chain)

            return {
                "success": True,
                "target_software": target_software,
                "total_chains": len(chains),
                "attack_chains": chains,
                "recommendation": self._generate_chain_recommendations(chains)
            }

        except Exception as e:
            logger.error(f"Error finding attack chains: {str(e)}")
            return {"success": False, "error": str(e)}

    def _find_vulnerabilities_by_pattern(self, software, pattern_type):
        """Cari CVE NYATA (NVD, via cve_manager) untuk `software` yang cocok dengan
        salah satu keyword pattern `pattern_type`. Mengembalikan [] bila tidak ada
        hasil/CVE manager tak tersedia — tidak pernah mengarang data."""
        if not self.cve_manager:
            return []
        keywords = self.attack_patterns.get(pattern_type, [])
        try:
            # fetch_latest_cves tidak menerima keyword software secara langsung, jadi kita
            # query NVD langsung dengan keywordSearch (software + salah satu keyword pattern)
            # supaya hasilnya benar-benar relevan dengan software+pola yang dicari.
            import requests as _requests  # local import: hindari dependency keras di modul ini

            for kw in keywords[:3]:  # batasi kombinasi query demi rate-limit NVD
                resp = _requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": f"{software} {kw}", "resultsPerPage": 5},
                    timeout=20,
                )
                if resp.status_code != 200:
                    continue
                vulns = resp.json().get("vulnerabilities", [])
                out = []
                for item in vulns:
                    cve = item.get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_score, severity = 0.0, "UNKNOWN"
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if metrics.get(key):
                            data = metrics[key][0]["cvssData"]
                            cvss_score = data.get("baseScore", 0.0)
                            severity = data.get("baseSeverity", severity)
                            break
                    descriptions = cve.get("descriptions", [])
                    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
                    out.append({
                        "cve_id": cve.get("id", "UNKNOWN"),
                        "description": description,
                        "cvss_score": cvss_score,
                        "exploitability": severity,
                    })
                if out:
                    return out
            return []
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"⚠️ NVD query gagal utk '{software}'/{pattern_type}: {exc}")
            return []

    def correlate_scan_findings(self, findings, max_targets=20):
        """Korelasi NYATA dari hasil scan HexStrike (bukan nama software generik):
        kelompokkan finding per location/target, tag tiap finding dengan attack
        pattern berdasarkan kata kunci di title/extra, lalu bangun chain hanya
        dari pola yang BENAR-BENAR ditemukan bersamaan pada target yang sama.
        """
        by_target: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings or []:
            target = (f.get("location") or f.get("target") or "unknown").strip() or "unknown"
            by_target.setdefault(target, []).append(f)

        chains = []
        for target, group in list(by_target.items())[:max_targets]:
            tagged: Dict[str, List[Dict[str, Any]]] = {}
            for f in group:
                text = f"{f.get('title','')} {f.get('extra','')}".lower()
                for pattern, keywords in self.attack_patterns.items():
                    if any(kw in text for kw in keywords):
                        tagged.setdefault(pattern, []).append(f)

            if len(tagged) < 2:
                continue  # perlu >=2 pola berbeda pada target yang sama utk disebut "chain"

            stages = [
                {"stage": i + 1, "objective": pattern, "findings": matches,
                 "finding_count": len(matches)}
                for i, (pattern, matches) in enumerate(tagged.items())
            ]
            chains.append({
                "chain_id": f"chain_{len(chains) + 1}",
                "target": target,
                "stages": stages,
                "pattern_count": len(tagged),
                "total_findings": len(group),
            })

        return {
            "success": True,
            "total_chains": len(chains),
            "attack_chains": sorted(chains, key=lambda c: -c["pattern_count"]),
            "recommendation": (
                f"Ditemukan {len(chains)} target dengan >=2 pola attack-chain berdasarkan "
                f"temuan scan NYATA (bukan data mock)." if chains else
                "Tidak ada target dengan kombinasi pola attack-chain pada run ini."
            ),
        }

    def _generate_chain_recommendations(self, chains):
        """Generate recommendations for attack chains"""
        if not chains:
            return "No viable attack chains found for target"

        recommendations = [
            f"Found {len(chains)} potential attack chains",
            f"Highest probability chain: {max(chains, key=lambda x: x['overall_probability'])['overall_probability']:.2%}",
            "Recommendations:",
            "- Test chains in order of probability",
            "- Prepare fallback methods for each stage",
            "- Consider detection evasion at each stage"
        ]

        return "\n".join(recommendations)

# Global intelligence managers
