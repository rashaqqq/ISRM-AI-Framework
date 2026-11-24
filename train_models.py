import os
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.preprocessing import MinMaxScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# 1. تحميل البيانات وتنظيفها
df = pd.read_csv('data/cve_raw.csv')
df = df.drop_duplicates().dropna()

# توحيد أسماء الأعمدة تلقائياً لتجنب أي خطأ في حالة الأحرف (Capital/Small)
col_map = {c.lower().strip(): c for c in df.columns}

def get_col(candidates):
    for cand in candidates:
        if cand.lower() in col_map:
            return col_map[cand.lower()]
    raise KeyError(f"لم يتم العثور على العمود ضمن: {candidates}. الأعمدة الموجودة: {list(df.columns)}")

categorical_cols = [
    get_col(['Threat_Category', 'threat_category']),
    get_col(['Attack_Vector', 'attack_vector']),
    get_col(['Attack_Complexity', 'attack_complexity']),
    get_col(['Privileges_Required', 'privileges_required']),
    get_col(['User_Interaction', 'user_interaction']),
    get_col(['Confidentiality_Impact', 'confidentiality_impact']),
    get_col(['Integrity_Impact', 'integrity_impact']),
    get_col(['Availability_Impact', 'availability_impact'])
]
numerical_cols = [
    get_col(['Exploitability_Score', 'exploitability_score']),
    get_col(['CVSS_Base_Score', 'cvss_base_score', 'cvss_score'])
]

target_l_col = get_col(['Likelihood', 'likelihood', 'Likelihood_Score'])
target_i_col = get_col(['Impact', 'impact', 'Impact_Score'])

X = df[categorical_cols + numerical_cols]
y_likelihood = df[target_l_col].astype(int)
y_impact = df[target_i_col].astype(int)

# 2. تجهيز المعالجة المسبقة
preprocessor = ColumnTransformer(
    transformers=[
        ('num', MinMaxScaler(feature_range=(0, 1)), numerical_cols),
        ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
    ]
)

def build_rf_pipeline():
    return Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier(n_estimators=150, random_state=42, n_jobs=-1))
    ])

def build_ann_pipeline():
    return Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', MLPClassifier(hidden_layer_sizes=(64, 32), activation='relu', max_iter=300, random_state=42))
    ])

# 3. التدريب والتقييم (80/20 Split + 5-Fold Cross-Validation)
def train_and_evaluate(model, X, y, model_name, target_name):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scoring = ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted']
    cv_results = cross_validate(model, X_train, y_train, cv=cv, scoring=scoring, n_jobs=-1)
    
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    metrics = {
        '5_fold_cv_accuracy': round(float(cv_results['test_accuracy'].mean()) * 100, 2),
        'test_accuracy': round(float(accuracy_score(y_test, y_pred)) * 100, 2),
        'test_precision': round(float(precision_score(y_test, y_pred, average='weighted', zero_division=0)) * 100, 2),
        'test_recall': round(float(recall_score(y_test, y_pred, average='weighted', zero_division=0)) * 100, 2),
        'test_f1_score': round(float(f1_score(y_test, y_pred, average='weighted', zero_division=0)) * 100, 2)
    }
    
    print(f"=== {model_name} | Target: {target_name} ===")
    for k, v in metrics.items():
        print(f"  {k}: {v}%")
    print()
    
    return model, metrics

if __name__ == "__main__":
    os.makedirs('models', exist_ok=True)
    report = {}

    rf_l, report['RF_Likelihood'] = train_and_evaluate(build_rf_pipeline(), X, y_likelihood, "Random Forest", "Likelihood")
    ann_l, report['ANN_Likelihood'] = train_and_evaluate(build_ann_pipeline(), X, y_likelihood, "ANN (MLP)", "Likelihood")

    rf_i, report['RF_Impact'] = train_and_evaluate(build_rf_pipeline(), X, y_impact, "Random Forest", "Impact")
    ann_i, report['ANN_Impact'] = train_and_evaluate(build_ann_pipeline(), X, y_impact, "ANN (MLP)", "Impact")

    joblib.dump(rf_l, 'models/rf_likelihood.joblib')
    joblib.dump(ann_l, 'models/ann_likelihood.joblib')
    joblib.dump(rf_i, 'models/rf_impact.joblib')
    joblib.dump(ann_i, 'models/ann_impact.joblib')
    joblib.dump(categorical_cols + numerical_cols, 'models/feature_columns.joblib')

    with open('models/metrics_report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=4)

    print("تم تدريب وحفظ جميع النماذج وتقرير الدقة بنجاح في مجلد models/")