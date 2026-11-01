# EPSS Threat Radar 🎯

Exploit Prediction Scoring System (**FIRST EPSS**) prioritization engine for enterprise vulnerability management.

## Overview
Traditional CVSS scores measure vulnerability severity but not active exploit probability. **EPSS** calculates the mathematical probability ($0.0 - 1.0$) of a CVE being weaponized and exploited in the wild within 30 days.

## Capabilities
- **Probabilistic Risk Scoring**: Focuses remediation on the <5% of CVEs that pose real active threat.
- **Daily EPSS Percentile Tracking**: Evaluates percentile rank relative to all cataloged vulnerabilities.
- **Prioritization Matrix**: Real-time scoring index updated daily in [`radar/epss_high_risk.json`](./radar/epss_high_risk.json).
