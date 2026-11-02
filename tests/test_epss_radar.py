#!/usr/bin/env python3
"""
Unit tests for EPSS Threat Radar.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from epss_radar import EPSSRadar, format_radar_table, get_default_sample_cves


class TestEPSSRadar(unittest.TestCase):
    def setUp(self):
        self.radar = EPSSRadar(high_risk_threshold=0.75)

    def test_p0_immediate_classification(self):
        profile = self.radar.calculate_priority(
            cve_id="CVE-2024-3400",
            epss_score=0.967,
            percentile=0.999,
            cvss_score=10.0,
            cisa_kev_linked=True
        )
        self.assertEqual(profile.remediation_priority, "P0-IMMEDIATE")
        self.assertGreaterEqual(profile.exploit_risk_index, 0.9)
        self.assertTrue(profile.cisa_kev_linked)

    def test_p1_urgent_classification(self):
        profile = self.radar.calculate_priority(
            cve_id="CVE-2023-38606",
            epss_score=0.45,
            percentile=0.92,
            cvss_score=7.8,
            cisa_kev_linked=False
        )
        self.assertEqual(profile.remediation_priority, "P1-URGENT")

    def test_p3_routine_classification(self):
        profile = self.radar.calculate_priority(
            cve_id="CVE-2023-2825",
            epss_score=0.02,
            percentile=0.45,
            cvss_score=5.0,
            cisa_kev_linked=False
        )
        self.assertEqual(profile.remediation_priority, "P3-ROUTINE")

    def test_evaluate_batch(self):
        cves = get_default_sample_cves()
        results = self.radar.evaluate_cves(cves, try_live_api=False)
        self.assertEqual(len(results), len(cves))
        # Ensure results are sorted descending by risk index
        for i in range(len(results) - 1):
            self.assertGreaterEqual(results[i].exploit_risk_index, results[i + 1].exploit_risk_index)

    def test_format_table(self):
        cves = get_default_sample_cves()[:2]
        profiles = self.radar.evaluate_cves(cves, try_live_api=False)
        out = format_radar_table(profiles)
        self.assertIn("CVE-2024-3400", out)
        self.assertIn("P0-IMMEDIATE", out)
        self.assertTrue(out.encode("ascii", errors="strict"))

    def test_radar_file_loading_if_exists(self):
        radar_file = os.path.join(os.path.dirname(__file__), "..", "radar", "epss_high_risk.json")
        if os.path.exists(radar_file):
            with open(radar_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            cves = data.get("critical_cves_flagged", [])
            profiles = self.radar.evaluate_cves(cves, try_live_api=False)
            self.assertEqual(len(profiles), len(cves))
            self.assertEqual(profiles[0].remediation_priority, "P0-IMMEDIATE")


if __name__ == "__main__":
    unittest.main()
