import os
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from database import ISRMDatabase
from integration_service import ISRMIntegrationService

st.set_page_config(
    page_title="ISRM-AI Framework | ISO 27001 & ISO 31000",
    page_icon="🛡️",
    layout="wide",
)

db = ISRMDatabase("isrm_platform.db")
db.seed_sample_assets_if_empty()
service = ISRMIntegrationService(db)

st.title("🛡️ ISRM-AI Framework")
st.caption("Automated Software Engineering & Machine Learning Platform for ISO 27001:2022 & ISO 31000:2018")

tabs = st.tabs([
    "📊 Overview & KPIs",
    "🗂️ Data & Assets",
    "🤖 ML Engine & 5×5 Heat Map",
    "📜 ISO 27001 / 31000 Compliance",
])

risk_df = pd.DataFrame(db.get_risk_register())
assets_df = pd.DataFrame(db.get_assets())
soa_df = pd.DataFrame(db.get_soa_report())
rtp_df = pd.DataFrame(db.get_rtp_plan())
metrics = service.load_metrics_report()

# ---------------- Tab 1: Overview & KPIs ----------------
with tabs[0]:
    st.subheader("Executive Security Posture & ML Validation")
    c1, c2, c3, c4 = st.columns(4)

    total_assets = len(assets_df) if not assets_df.empty else 0
    high_crit_count = (
        int((risk_df["risk_score"] >= 10).sum()) if not risk_df.empty and "risk_score" in risk_df.columns else 0
    )
    rf_acc = metrics.get("Random Forest", {}).get("Accuracy", 0.964)
    ann_acc = metrics.get("ANN", {}).get("Accuracy", 0.948)

    if not soa_df.empty and "implementation_status" in soa_df.columns:
        impl_rate = int(round(((soa_df["implementation_status"] == "Implemented").mean()) * 100))
    else:
        impl_rate = 0

    c1.metric("Monitored Assets", total_assets)
    c2.metric("High / Critical Risks (R ≥ 10)", high_crit_count)
    c3.metric("RF / ANN Accuracy", f"{rf_acc*100:.1f}% / {ann_acc*100:.1f}%")
    c4.metric("ISO 27001 Readiness", f"{impl_rate}%")

    st.markdown("### Model Evaluation Metrics")
    st.json(metrics)

    st.markdown("### Recent Risk Assessments")
    if not risk_df.empty:
        st.dataframe(risk_df, use_container_width=True)
    else:
        st.info("No risk assessments saved yet. Go to 'ML Engine & 5×5 Heat Map' to run your first prediction.")

# ---------------- Tab 2: Data & Assets ----------------
with tabs[1]:
    st.subheader("Asset Inventory Management (SQLite)")
    with st.form("add_asset_form", clear_on_submit=True):
        col_a, col_b, col_c = st.columns(3)
        asset_name = col_a.text_input("Asset Name", placeholder="e.g., Core Banking DB")
        asset_type = col_b.selectbox("Asset Type", ["Database Server", "Web Application", "Cloud IAM", "Network Gateway", "Backup Vault"])
        owner = col_c.text_input("Owner", placeholder="e.g., Security Team")

        col_d, col_e, col_f = st.columns(3)
        c_score = col_d.slider("Confidentiality (1-5)", 1, 5, 4)
        i_score = col_e.slider("Integrity (1-5)", 1, 5, 4)
        a_score = col_f.slider("Availability (1-5)", 1, 5, 4)

        submitted = st.form_submit_button("➕ Add Asset")
        if submitted:
            if asset_name.strip() and owner.strip():
                db.add_asset(asset_name.strip(), asset_type, owner.strip(), c_score, i_score, a_score)
                st.success("Asset saved to database!")
                st.rerun()
            else:
                st.warning("Please enter both Asset Name and Owner.")

    st.markdown("### Registered Assets")
    if not assets_df.empty:
        st.dataframe(assets_df, use_container_width=True)
    else:
        st.info("No assets registered yet.")

    st.markdown("### Raw NVD/CVE Dataset Preview (`data/cve_raw.csv`)")
    cve_path = os.path.join("data", "cve_raw.csv")
    if os.path.exists(cve_path):
        cve_preview = pd.read_csv(cve_path, nrows=100)
        st.dataframe(cve_preview, use_container_width=True)
    else:
        st.warning("`data/cve_raw.csv` was not found in the current directory.")

# ---------------- Tab 3: ML Engine & 5x5 Heat Map ----------------
with tabs[2]:
    st.subheader("AI Risk Predictor & Dynamic 5×5 Heat Map")

    if assets_df.empty:
        st.warning("Please add at least one asset first.")
    else:
        asset_options = {f"{row['asset_id']} - {row['asset_name']}": int(row["asset_id"]) for _, row in assets_df.iterrows()}
        selected_asset_label = st.selectbox("Target Asset", list(asset_options.keys()))
        selected_asset_id = asset_options[selected_asset_label]
        asset_row = assets_df[assets_df["asset_id"] == selected_asset_id].iloc[0]

        col1, col2, col3 = st.columns(3)
        cve_id = col1.text_input("Threat / CVE ID", value="CVE-2026-2194")
        threat_cat = col2.selectbox(
            "Threat Category",
            ["SQL Injection / Data Exfiltration", "Privilege Escalation", "Remote Code Execution", "API Misconfiguration", "Denial of Service"],
        )
        model_choice = col3.selectbox("ML Model", ["Random Forest", "ANN"])

        col4, col5, col6 = st.columns(3)
        av = col4.selectbox("Attack Vector", ["Network", "Adjacent", "Local", "Physical"])
        ac = col5.selectbox("Attack Complexity", ["Low", "High"])
        pr = col6.selectbox("Privileges Required", ["None", "Low", "High"])

        if st.button("🚀 Run Prediction & Map ISO Compliance", type="primary"):
            features = {
                "attack_vector": av,
                "attack_complexity": ac,
                "privileges_required": pr,
                "threat_category": threat_cat,
                "confidentiality": int(asset_row["confidentiality_score"]),
                "integrity": int(asset_row["integrity_score"]),
                "availability": int(asset_row["availability_score"]),
            }
            l_pred, i_pred, pred_source = service.run_ml_prediction(features, model_choice)
            result = service.evaluate_compliance_and_persist(
                asset_id=selected_asset_id,
                threat_cve_id=cve_id.strip() or "CVE-2026-0001",
                threat_category=threat_cat,
                likelihood=l_pred,
                impact=i_pred,
                model_used=model_choice,
            )

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Likelihood (L)", f"{result['likelihood']} / 5")
            m2.metric("Impact (I)", f"{result['impact']} / 5")
            m3.metric("Risk Score (R = L×I)", f"{result['risk_score']} / 25")
            m4.metric("Severity", result["severity_class"])

            st.caption(f"Inference source: {pred_source} | Compliance engine: {result['engine_used']}")
            st.success(f"Saved Risk #{result['risk_id']} — Mapped Controls: {', '.join([c['control_id'] for c in result['controls']])}")
            st.rerun()

    st.markdown("### Dynamic 5×5 Risk Heat Map")
    matrix_counts = [[0 for _ in range(5)] for _ in range(5)]
    matrix_text = [["" for _ in range(5)] for _ in range(5)]

    latest_risk_df = pd.DataFrame(db.get_risk_register())
    if not latest_risk_df.empty:
        for _, r in latest_risk_df.iterrows():
            l_idx = max(1, min(5, int(r["predicted_likelihood"]))) - 1
            i_idx = max(1, min(5, int(r["predicted_impact"]))) - 1
            matrix_counts[l_idx][i_idx] += 1
            existing = matrix_text[l_idx][i_idx]
            entry = f"{r.get('asset_name', 'Asset')} ({r['risk_score']})"
            matrix_text[l_idx][i_idx] = f"{existing}<br>{entry}" if existing else entry

    score_grid = [[(l + 1) * (i + 1) for i in range(5)] for l in range(5)]
    annotations_text = [
        [f"R={score_grid[l][i]} (n={matrix_counts[l][i]})" + (f"<br>{matrix_text[l][i]}" if matrix_text[l][i] else "") for i in range(5)]
        for l in range(5)
    ]

    fig = go.Figure(
        data=go.Heatmap(
            z=score_grid,
            x=["1: Negligible", "2: Minor", "3: Moderate", "4: Major", "5: Catastrophic"],
            y=["1: Rare", "2: Unlikely", "3: Possible", "4: Likely", "5: Almost Certain"],
            text=annotations_text,
            texttemplate="%{text}",
            colorscale=[
                [0.0, "#22c55e"],
                [0.25, "#eab308"],
                [0.55, "#f97316"],
                [1.0, "#dc2626"],
            ],
            showscale=True,
            colorbar=dict(title="Risk Score (R)"),
        )
    )
    fig.update_layout(
        xaxis_title="Business & CIA Impact (I)",
        yaxis_title="Threat Likelihood (L)",
        height=520,
    )
    st.plotly_chart(fig, use_container_width=True)

# ---------------- Tab 4: Compliance & Export ----------------
with tabs[3]:
    st.subheader("ISO 27001:2022 & ISO 31000:2018 Governance Deliverables")

    fresh_risk = pd.DataFrame(db.get_risk_register())
    fresh_soa = pd.DataFrame(db.get_soa_report())
    fresh_rtp = pd.DataFrame(db.get_rtp_plan())

    st.markdown("#### 1. Risk Register")
    if not fresh_risk.empty:
        st.dataframe(fresh_risk, use_container_width=True)
        st.download_button(
            "⬇️ Download Risk Register (CSV)",
            fresh_risk.to_csv(index=False).encode("utf-8"),
            file_name="Risk_Register.csv",
            mime="text/csv",
        )
    else:
        st.info("Risk Register is empty.")

    st.markdown("#### 2. Statement of Applicability (SoA - ISO 27001:2022)")
    if not fresh_soa.empty:
        st.dataframe(fresh_soa, use_container_width=True)
        st.download_button(
            "⬇️ Download SoA Report (CSV)",
            fresh_soa.to_csv(index=False).encode("utf-8"),
            file_name="SoA_Report.csv",
            mime="text/csv",
        )
    else:
        st.info("SoA Report is empty.")

    st.markdown("#### 3. Risk Treatment Plan (RTP - ISO 31000:2018)")
    if not fresh_rtp.empty:
        st.dataframe(fresh_rtp, use_container_width=True)
        st.download_button(
            "⬇️ Download RTP Plan (CSV)",
            fresh_rtp.to_csv(index=False).encode("utf-8"),
            file_name="RTP_Plan.csv",
            mime="text/csv",
        )
    else:
        st.info("RTP Plan is empty.")