# Cybersecurity Layer Specifications & Integration Guide

## 1. Selected NVD/CVE Security Features (`data/cve_raw.csv`)
- **Records Count:** 25,000 real CVSS v3.1 vulnerability records fetched from NIST NVD API 2.0.
- **Identifiers & Classification:** `CVE_ID`, `Threat_Category` (`Application Vulnerability`, `Access Control Breach`, `Cryptographic Weakness`, `Data Leakage`, `Network / Infrastructure Threat`, `Availability / DoS`).
- **Exploitability Metrics (Likelihood Drivers):** `Attack_Vector`, `Attack_Complexity`, `Privileges_Required`, `User_Interaction`, `Exploitability_Score`.
- **CIA Triad Impact Metrics (Impact Drivers):** `Confidentiality_Impact`, `Integrity_Impact`, `Availability_Impact`, `CVSS_Base_Score`.

## 2. Translation Logic to ISO 31000 / ISO 27001 Risk Matrix (1–5 Scale)
- **Likelihood ($L \in [1..5]$):** Derived from CVSS v3.1 Exploitability sub-score (`0.0 – 3.9`) normalized to a 1–5 scale.
- **Impact ($I \in [1..5]$):** Derived from CVSS v3.1 CIA Impact sub-score (`0.0 – 6.0`) normalized to a 1–5 scale.
- **Composite Risk Score ($R = L \times I \in [1..25]$):**
  - **Critical ($R \ge 15$):** Immediate Mitigation (7-day SLA)
  - **High ($10 \le R \le 14$):** Priority Mitigation (14-day SLA)
  - **Medium ($5 \le R \le 9$):** Scheduled Control / Monitoring (30-day SLA)
  - **Low ($R < 5$):** Risk Acceptance (90-day SLA)

## 3. Compliance & ISO 27001:2022 Annex A Mapping (`compliance_engine.py`)
Import and call `evaluate_and_map_compliance(asset_id, asset_name, cve_id, threat_category, likelihood, impact)` to automatically generate:
- `risk_register_entry`: Formatted row for the **Risk Register**.
- `soa_entry`: Mapped **ISO 27001:2022 Annex A** control (`A.8.8`, `A.5.15`, `A.8.24`, `A.8.12`, `A.8.20`, `A.8.13`), applicability, status, and audit justification.
- `rtp_entry`: **ISO 31000 Risk Treatment Plan** including treatment option, action plan, target completion date, and calculated residual risk.
