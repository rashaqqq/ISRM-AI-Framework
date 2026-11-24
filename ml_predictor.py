import joblib
import pandas as pd

rf_likelihood = joblib.load('models/rf_likelihood.joblib')
ann_likelihood = joblib.load('models/ann_likelihood.joblib')
rf_impact = joblib.load('models/rf_impact.joblib')
ann_impact = joblib.load('models/ann_impact.joblib')
feature_cols = joblib.load('models/feature_columns.joblib')

def predict_risk_scores(
    threat_category: str,
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    confidentiality_impact: str,
    integrity_impact: str,
    availability_impact: str,
    exploitability_score: float,
    cvss_base_score: float,
    model_type: str = "RF"
) -> dict:
    raw_input = {
        'threat_category': threat_category,
        'attack_vector': attack_vector,
        'attack_complexity': attack_complexity,
        'privileges_required': privileges_required,
        'user_interaction': user_interaction,
        'confidentiality_impact': confidentiality_impact,
        'integrity_impact': integrity_impact,
        'availability_impact': availability_impact,
        'exploitability_score': float(exploitability_score),
        'cvss_base_score': float(cvss_base_score)
    }
    
    # مطابقة أسماء الأعمدة تلقائياً مع التي تدرب عليها النموذج
    mapped_row = {col: raw_input[col.lower()] for col in feature_cols}
    input_df = pd.DataFrame([mapped_row])

    if model_type.upper() == "ANN":
        likelihood = int(ann_likelihood.predict(input_df)[0])
        impact = int(ann_impact.predict(input_df)[0])
    else:
        likelihood = int(rf_likelihood.predict(input_df)[0])
        impact = int(rf_impact.predict(input_df)[0])

    return {
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": likelihood * impact,
        "model_used": model_type.upper()
    }