from datetime import datetime, timedelta

# قاموس ضوابط ISO/IEC 27001:2022 Annex A المعتمد في المشروع
ISO_27001_CONTROLS = {
    "Application Vulnerability": {
        "control_id": "A.8.8",
        "control_title": "Management of Technical Vulnerabilities",
        "justification": "Automated NVD/CVE scanning, patch management, and ML risk prioritization required across production applications.",
        "treatment_action": "Apply vendor security patches, deploy WAF rules, and enforce secure code review."
    },
    "Access Control Breach": {
        "control_id": "A.5.15",
        "control_title": "Access Control",
        "justification": "Strict Role-Based Access Control (RBAC) and Multi-Factor Authentication (MFA) mandated to mitigate privilege escalation.",
        "treatment_action": "Enforce MFA, audit privileged accounts, and apply principle of least privilege."
    },
    "Cryptographic Weakness": {
        "control_id": "A.8.24",
        "control_title": "Use of Cryptography",
        "justification": "Strong encryption (AES-256 at rest and TLS 1.3 in transit) required to protect Critical CIA assets.",
        "treatment_action": "Upgrade deprecated cipher suites, enforce TLS 1.3, and rotate cryptographic keys."
    },
    "Data Leakage": {
        "control_id": "A.8.12",
        "control_title": "Data Leakage Prevention (DLP)",
        "justification": "Triggered by high ML Impact score (I >= 4) on repositories storing PII, financial, or sensitive enterprise records.",
        "treatment_action": "Enable DLP policies, monitor outbound traffic, and classify sensitive data repositories."
    },
    "Network / Infrastructure Threat": {
        "control_id": "A.8.20",
        "control_title": "Networks Security",
        "justification": "Micro-segmentation and Zero-Trust network filtering required for external-facing and critical infrastructure endpoints.",
        "treatment_action": "Configure strict firewall ACLs, isolate vulnerable network segments, and enable IDS/IPS."
    },
    "Availability / DoS": {
        "control_id": "A.8.13",
        "control_title": "Information Backup",
        "justification": "Immutable, air-gapped backups and redundancy mechanisms required to ensure business continuity and Availability resilience.",
        "treatment_action": "Verify automated offline backups, configure rate-limiting, and test failover recovery."
    }
}

def classify_risk_score(likelihood: int, impact: int) -> dict:
    """
    حساب درجة الخطر المركبة R = L * I وتحديد مستوى الخطورة وخطة العلاج حسب ISO 31000
    """
    risk_score = int(likelihood) * int(impact)
    
    if risk_score >= 15:
        severity = "Critical"
        color = "#D32F2F"  # Dark Red
        treatment_option = "Mitigate (Immediate)"
        sla_days = 7
    elif risk_score >= 10:
        severity = "High"
        color = "#F57C00"  # Orange
        treatment_option = "Mitigate (Priority)"
        sla_days = 14
    elif risk_score >= 5:
        severity = "Medium"
        color = "#FBC02D"  # Yellow
        treatment_option = "Mitigate / Monitor"
        sla_days = 30
    else:
        severity = "Low"
        color = "#388E3C"  # Green
        treatment_option = "Accept"
        sla_days = 90

    return {
        "likelihood": int(likelihood),
        "impact": int(impact),
        "risk_score": risk_score,
        "severity": severity,
        "color": color,
        "treatment_option": treatment_option,
        "target_date": (datetime.now() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
    }

def evaluate_and_map_compliance(asset_id: str, asset_name: str, cve_id: str, threat_category: str, likelihood: int, impact: int) -> dict:
    """
    الواجهة البرمجية الرئيسية التي تربط مخرجات الـ ML بملفات الامتثال:
    1. Risk Register
    2. Statement of Applicability (SoA)
    3. Risk Treatment Plan (RTP)
    """
    risk_eval = classify_risk_score(likelihood, impact)
    control_info = ISO_27001_CONTROLS.get(threat_category, ISO_27001_CONTROLS["Network / Infrastructure Threat"])
    
    # تحديد حالة التطبيق في SoA بناءً على شدة الخطر
    is_applicable = "Yes" if risk_eval["risk_score"] >= 5 else "Conditional"
    impl_status = "Planned (Urgent)" if risk_eval["risk_score"] >= 15 else ("Implemented" if risk_eval["risk_score"] < 10 else "In Progress")
    
    # حساب الخطر المتبقي (Residual Risk) بعد تطبيق الضابط الأمني
    residual_score = max(1, round(risk_eval["risk_score"] * 0.35))

    return {
        "risk_register_entry": {
            "Asset_ID": asset_id,
            "Asset_Name": asset_name,
            "Threat_CVE_ID": cve_id,
            "Threat_Category": threat_category,
            "Predicted_Likelihood": risk_eval["likelihood"],
            "Predicted_Impact": risk_eval["impact"],
            "Risk_Score": risk_eval["risk_score"],
            "Severity_Class": risk_eval["severity"],
            "Color_Code": risk_eval["color"]
        },
        "soa_entry": {
            "Control_ID": control_info["control_id"],
            "Control_Title": control_info["control_title"],
            "Applicability_Status": is_applicable,
            "Linked_Asset": f"{asset_name} ({cve_id})",
            "Implementation_Status": impl_status,
            "Justification_Basis": control_info["justification"]
        },
        "rtp_entry": {
            "Asset_ID": asset_id,
            "Threat_CVE_ID": cve_id,
            "Initial_Risk_Score": risk_eval["risk_score"],
            "Treatment_Option": risk_eval["treatment_option"],
            "Assigned_Control": f"{control_info['control_id']} - {control_info['control_title']}",
            "Action_Plan": control_info["treatment_action"],
            "Target_Completion_Date": risk_eval["target_date"],
            "Residual_Risk_Score": residual_score
        }
    }

# اختبار ذاتي للتأكد من عمل المحرك الأمني
if __name__ == "__main__":
    import json
    sample_output = evaluate_and_map_compliance(
        asset_id="AST-001",
        asset_name="Core Banking Database",
        cve_id="CVE-2026-2194",
        threat_category="Application Vulnerability",
        likelihood=5,
        impact=5
    )
    print("[✓] Cybersecurity Compliance Engine Test Output:")
    print(json.dumps(sample_output, indent=2))
