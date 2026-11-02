# EPSS Threat Radar 🎯

[![CI/CD Pipeline](https://github.com/GarciaVillenaLuis/epss-threat-radar/actions/workflows/ci.yml/badge.svg)](https://github.com/GarciaVillenaLuis/epss-threat-radar/actions/workflows/ci.yml)
[![EPSS Engine](https://img.shields.io/badge/EPSS%20Model-v2024.03.01-informational?style=flat-square&logo=target&logoColor=white)](https://www.first.org/epss/)
[![Monitoring Status](https://img.shields.io/badge/Status-Active%20Monitoring-success?style=flat-square&logo=opsgenie&logoColor=white)](https://github.com/GarciaVillenaLuis/epss-threat-radar)
[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green?style=flat-square)](LICENSE)
[![Framework](https://img.shields.io/badge/Standard-FIRST%20EPSS%20%2B%20CVSS%20v3.1-orange?style=flat-square)](https://www.first.org/)

Exploit Prediction Scoring System (**FIRST EPSS**) prioritization engine for enterprise vulnerability management. Calculates mathematical weaponization probabilities and dynamically aligns remediation SLAs.

Engineered and maintained by **Luis García Villena** (*Security Transformation Analyst @ Accenture | CCSP® & CCGP ISMS Forum*).

---

## 🔬 Mathematical Foundation & Methodology

Traditional **CVSS (Common Vulnerability Scoring System)** scores measure theoretical technical severity, but provide no signal on whether threat actors are actively weaponizing an exploit.

In contrast, **FIRST EPSS** calculates the empirical probability ($0.0 \le P \le 1.0$) that a vulnerability will be exploited in the wild within the next 30 days.

### Composite Exploit Risk Index (ERI)
This engine computes the **Exploit Risk Index (ERI)**, synthesizing probabilistic exploitation with CVSS impact and active threat intelligence:

$$\text{ERI} = (\text{EPSS} \times 0.65) + \left(\frac{\text{CVSS}}{10.0} \times 0.35\right) + \Delta_{\text{KEV}}$$

Where $\Delta_{\text{KEV}} = +0.10$ if the CVE is listed in CISA's Known Exploited Vulnerabilities catalog.

### Remediation SLA Matrix
| Priority Tier | ERI / EPSS Threshold | Operational SLA | Action Required |
| :--- | :---: | :---: | :--- |
| `P0-IMMEDIATE` | $\text{EPSS} \ge 0.75$ or $\text{ERI} \ge 0.80$ | **24 - 48 Hours** | Emergency patch deployment, WAF rule lockdown |
| `P1-URGENT` | $\text{EPSS} \ge 0.40$ or $\text{ERI} \ge 0.60$ | **7 Days** | Prioritized sprint mitigation |
| `P2-ELEVATED` | $\text{EPSS} \ge 0.15$ or $\text{ERI} \ge 0.40$ | **15 Days** | Next regular patching cycle |
| `P3-ROUTINE` | $\text{EPSS} < 0.15$ | **30 - 60 Days** | Standard maintenance window |

---

## 🚀 Quick Start & CLI Usage

### Available Flags & Parameters

```bash
python epss_radar.py [OPTIONS]
```

| Parameter | Type | Description |
| :--- | :---: | :--- |
| `--cve CVE_ID` | `string` | Single CVE identifier to score |
| `--epss SCORE` | `float` | EPSS probability score ($0.0 - 1.0$) |
| `--cvss SCORE` | `float` | CVSS base severity score ($0.0 - 10.0$) |
| `--kev` | `flag` | Mark CVE as confirmed in CISA KEV |
| `--input-file FILE` | `string` | Load and prioritize a batch of CVEs from JSON |
| `--threshold VAL` | `float` | High-risk cutoff threshold (default: `0.75`) |
| `--live` | `flag` | Query live scores from FIRST.org API |
| `--format FMT` | `choice` | Output format: `table`, `json`, or `markdown` |
| `--output FILE` | `string` | Save report to file |

---

## 💻 Usage Examples

### 1. Evaluate single zero-day vulnerability
```bash
python epss_radar.py --cve CVE-2024-3400 --epss 0.967 --cvss 10.0 --kev
```

### 2. Prioritize enterprise vulnerability backlog
```bash
python epss_radar.py --input-file samples/sample_cves.json --format table
```
**Sample Output:**
```text
==========================================================================================
   FIRST EPSS THREAT RADAR & REMEDIATION MATRIX
==========================================================================================
Vulnerabilities Analyzed: 6
P0-IMMEDIATE Action Required: 3 | P1-URGENT Action Required: 1
Formula: Exploit Risk Index (ERI) = (EPSS * 0.65) + (CVSS/10 * 0.35) [+0.10 if KEV]
------------------------------------------------------------------------------------------
+---------------+------------------+------------+------+------------------+--------------+-------------+
| CVE ID        | EPSS Prob.       | Percentile | CVSS | Risk Index (ERI) | Priority     | In KEV?     |
+---------------+------------------+------------+------+------------------+--------------+-------------+
| CVE-2024-3400 | 0.967 (96.7%)    | 0.999      | 10.0 | 1.000            | P0-IMMEDIATE | YES (Active)|
| CVE-2024-21887| 0.938 (93.8%)    | 0.995      | 9.1  | 1.000            | P0-IMMEDIATE | YES (Active)|
| CVE-2023-46805| 0.910 (91.0%)    | 0.991      | 8.2  | 0.978            | P0-IMMEDIATE | YES (Active)|
| CVE-2023-38606| 0.412 (41.2%)    | 0.920      | 7.8  | 0.541            | P1-URGENT    | No          |
| CVE-2024-1086 | 0.185 (18.5%)    | 0.840      | 7.8  | 0.393            | P2-ELEVATED  | No          |
| CVE-2023-2825 | 0.021 (2.1%)     | 0.450      | 5.5  | 0.206            | P3-ROUTINE   | No          |
+---------------+------------------+------------+------+------------------+--------------+-------------+
==========================================================================================
```

### 3. Generate Markdown summary for executive reporting
```bash
python epss_radar.py --input-file samples/sample_cves.json --format markdown -o radar_summary.md
```

---

## 🧪 Unit Testing

Execute tests with standard `unittest`:

```bash
python -m unittest tests/test_epss_radar.py
```

---

## 🎯 Continuous Telemetry

Real-time scoring index updated daily in:
- [`radar/epss_high_risk.json`](./radar/epss_high_risk.json)
