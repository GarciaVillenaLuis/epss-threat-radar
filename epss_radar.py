#!/usr/bin/env python3
"""
FIRST EPSS (Exploit Prediction Scoring System) Threat Radar & Priority Calculator.

Author: Luis Garcia Villena <garciavillenaluis@gmail.com>
Role: Security Transformation Analyst @ Accenture | CCSP & CCGP (ISMS Forum)
License: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

FIRST_EPSS_API_URL = "https://api.first.org/data/v1/epss"


@dataclass
class VulnerabilityRiskProfile:
    cve_id: str
    epss_score: float
    percentile: float
    cvss_score: float
    exploit_risk_index: float
    remediation_priority: str
    rationale: str
    cisa_kev_linked: bool = False


class EPSSRadar:
    """Predictive threat prioritization engine using FIRST EPSS models."""

    def __init__(self, high_risk_threshold: float = 0.75):
        self.high_risk_threshold = high_risk_threshold
        self.profiles: List[VulnerabilityRiskProfile] = []

    def calculate_priority(
        self,
        cve_id: str,
        epss_score: float,
        percentile: float,
        cvss_score: float = 8.0,
        cisa_kev_linked: bool = False
    ) -> VulnerabilityRiskProfile:
        """
        Computes composite Exploit Risk Index (ERI) and actionable priority.
        ERI = (EPSS * 0.65) + ((CVSS / 10.0) * 0.35)
        If in CISA KEV or actively weaponized, an acceleration factor (+0.10, capped at 1.0) is applied.
        """
        base_eri = (epss_score * 0.65) + ((cvss_score / 10.0) * 0.35)
        if cisa_kev_linked:
            base_eri = min(1.0, base_eri + 0.10)

        eri = round(base_eri, 3)

        if epss_score >= self.high_risk_threshold or eri >= 0.80 or cisa_kev_linked:
            priority = "P0-IMMEDIATE"
            rationale = "High probability of active weaponization (<30d) or verified in-the-wild exploitation. SLA: 24-48h."
        elif epss_score >= 0.40 or eri >= 0.60:
            priority = "P1-URGENT"
            rationale = "Elevated exploit probability. Target for prioritized patch cycle. SLA: 7 days."
        elif epss_score >= 0.15 or eri >= 0.40:
            priority = "P2-ELEVATED"
            rationale = "Moderate risk. Include in standard enterprise patch cadence. SLA: 15 days."
        else:
            priority = "P3-ROUTINE"
            rationale = "Low weaponization likelihood. Routine maintenance window. SLA: 30-60 days."

        return VulnerabilityRiskProfile(
            cve_id=cve_id.strip().upper(),
            epss_score=round(epss_score, 4),
            percentile=round(percentile, 4),
            cvss_score=round(cvss_score, 1),
            exploit_risk_index=eri,
            remediation_priority=priority,
            rationale=rationale,
            cisa_kev_linked=cisa_kev_linked
        )

    def fetch_live_epss(self, cves: List[str], timeout: int = 10) -> List[Dict[str, Any]]:
        """Queries the official FIRST EPSS API."""
        query_str = ",".join(cve.strip().upper() for cve in cves)
        url = f"{FIRST_EPSS_API_URL}?cve={query_str}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "EPSSThreatRadar/2.0 (Security Engineering CLI)"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("data", [])
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            sys.stderr.write(f"[WARN] Live FIRST EPSS API unreachable: {e}. Falling back to offline profiles.\n")
            return []

    def evaluate_cves(
        self,
        cve_entries: List[Dict[str, Any]],
        try_live_api: bool = False
    ) -> List[VulnerabilityRiskProfile]:
        """Evaluates a batch of CVE candidates."""
        results: List[VulnerabilityRiskProfile] = []

        # If live API requested, fetch fresh scores
        live_lookup: Dict[str, Dict[str, Any]] = {}
        if try_live_api:
            cve_names = [item["cve"] for item in cve_entries if "cve" in item]
            live_items = self.fetch_live_epss(cve_names)
            for item in live_items:
                live_lookup[item.get("cve", "").upper()] = item

        for item in cve_entries:
            cve_id = item.get("cve", "CVE-UNKNOWN").upper()
            cvss = float(item.get("cvss", 8.0))
            is_kev = bool(item.get("cisa_kev", False))

            if cve_id in live_lookup:
                epss_val = float(live_lookup[cve_id].get("epss", 0.0))
                percentile_val = float(live_lookup[cve_id].get("percentile", 0.0))
            else:
                epss_val = float(item.get("epss_score", item.get("epss", 0.5)))
                percentile_val = float(item.get("percentile", 0.8))

            profile = self.calculate_priority(
                cve_id=cve_id,
                epss_score=epss_val,
                percentile=percentile_val,
                cvss_score=cvss,
                cisa_kev_linked=is_kev
            )
            results.append(profile)

        self.profiles = sorted(results, key=lambda p: p.exploit_risk_index, reverse=True)
        return self.profiles


def format_radar_table(profiles: List[VulnerabilityRiskProfile]) -> str:
    """ASCII table output."""
    if not profiles:
        return "No vulnerabilities evaluated."

    headers = ["CVE ID", "EPSS Prob.", "Percentile", "CVSS", "Risk Index (ERI)", "Priority", "In KEV?"]
    rows = []
    for p in profiles:
        rows.append([
            p.cve_id,
            f"{p.epss_score:.3f} ({p.epss_score*100:.1f}%)",
            f"{p.percentile:.3f}",
            f"{p.cvss_score:.1f}",
            f"{p.exploit_risk_index:.3f}",
            p.remediation_priority,
            "YES (Active)" if p.cisa_kev_linked else "No"
        ])

    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(val)))

    line_sep = "+-" + "-+-".join("-" * w for w in col_widths) + "-+"
    header_str = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"

    output = [line_sep, header_str, line_sep]
    for row in rows:
        row_str = "| " + " | ".join(str(val).ljust(col_widths[i]) for i, val in enumerate(row)) + " |"
        output.append(row_str)
    output.append(line_sep)
    return "\n".join(output)


def get_default_sample_cves() -> List[Dict[str, Any]]:
    return [
        {"cve": "CVE-2024-3400", "epss_score": 0.967, "percentile": 0.999, "cvss": 10.0, "cisa_kev": True},
        {"cve": "CVE-2024-21887", "epss_score": 0.938, "percentile": 0.995, "cvss": 9.1, "cisa_kev": True},
        {"cve": "CVE-2023-46805", "epss_score": 0.910, "percentile": 0.991, "cvss": 8.2, "cisa_kev": True},
        {"cve": "CVE-2023-38606", "epss_score": 0.412, "percentile": 0.920, "cvss": 7.8, "cisa_kev": False},
        {"cve": "CVE-2024-1086", "epss_score": 0.185, "percentile": 0.840, "cvss": 7.8, "cisa_kev": False},
        {"cve": "CVE-2023-2825", "epss_score": 0.021, "percentile": 0.450, "cvss": 5.5, "cisa_kev": False}
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="FIRST EPSS Threat Radar & Vulnerability Prioritization CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python epss_radar.py
  python epss_radar.py --cve CVE-2024-3400 --epss 0.967 --cvss 10.0
  python epss_radar.py --input-file samples/sample_cves.json --threshold 0.75
  python epss_radar.py --input-file samples/sample_cves.json --format json --output radar_report.json
        """
    )
    parser.add_argument("--input-file", "-i", type=str, help="JSON file containing CVE lists with scores")
    parser.add_argument("--cve", type=str, help="Single CVE to score")
    parser.add_argument("--epss", type=float, default=0.5, help="EPSS score for single CVE (0.0 to 1.0)")
    parser.add_argument("--cvss", type=float, default=8.0, help="CVSS base score for single CVE (0.0 to 10.0)")
    parser.add_argument("--kev", action="store_true", help="Flag if vulnerability is in CISA KEV catalog")
    parser.add_argument("--threshold", "-t", type=float, default=0.75, help="High-risk EPSS threshold (default: 0.75)")
    parser.add_argument("--live", action="store_true", help="Attempt live lookup against FIRST.org EPSS API")
    parser.add_argument("--format", choices=["table", "json", "markdown"], default="table", help="Output format")
    parser.add_argument("--output", "-o", type=str, help="Write results to file")

    args = parser.parse_args()
    radar = EPSSRadar(high_risk_threshold=args.threshold)

    if args.cve:
        cve_entries = [{
            "cve": args.cve,
            "epss_score": args.epss,
            "percentile": 0.95,
            "cvss": args.cvss,
            "cisa_kev": args.kev
        }]
    elif args.input_file:
        if not os.path.exists(args.input_file):
            sys.stderr.write(f"[ERROR] Input file '{args.input_file}' not found.\n")
            sys.exit(1)
        with open(args.input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            cve_entries = data.get("critical_cves_flagged", data.get("cves", data if isinstance(data, list) else []))
    else:
        cve_entries = get_default_sample_cves()

    profiles = radar.evaluate_cves(cve_entries, try_live_api=args.live)

    if args.format == "json":
        out_content = json.dumps([asdict(p) for p in profiles], indent=2)
    elif args.format == "markdown":
        md_lines = [
            "# Vulnerability Prioritization Radar (EPSS + CVSS)",
            f"*Generated*: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "| CVE ID | EPSS Score | Percentile | CVSS | Exploit Risk Index | Priority | Remediation SLA |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :--- |"
        ]
        for p in profiles:
            sla = "24-48 Hours" if "P0" in p.remediation_priority else ("7 Days" if "P1" in p.remediation_priority else "15-30 Days")
            md_lines.append(f"| **{p.cve_id}** | `{p.epss_score}` | `{p.percentile}` | `{p.cvss_score}` | **`{p.exploit_risk_index}`** | `{p.remediation_priority}` | {sla} |")
        out_content = "\n".join(md_lines)
    else:
        table_str = format_radar_table(profiles)
        p0_count = sum(1 for p in profiles if "P0" in p.remediation_priority)
        p1_count = sum(1 for p in profiles if "P1" in p.remediation_priority)
        header_banner = [
            "==========================================================================================",
            "   FIRST EPSS THREAT RADAR & REMEDIATION MATRIX",
            "==========================================================================================",
            f"Vulnerabilities Analyzed: {len(profiles)}",
            f"P0-IMMEDIATE Action Required: {p0_count} | P1-URGENT Action Required: {p1_count}",
            "Formula: Exploit Risk Index (ERI) = (EPSS * 0.65) + (CVSS/10 * 0.35) [+0.10 if KEV]",
            "------------------------------------------------------------------------------------------",
            table_str,
            "=========================================================================================="
        ]
        out_content = "\n".join(header_banner)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_content + "\n")
        print(f"[SUCCESS] Threat radar output written to {args.output}")
    else:
        print(out_content)


if __name__ == "__main__":
    main()
