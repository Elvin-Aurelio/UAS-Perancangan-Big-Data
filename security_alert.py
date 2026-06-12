import time
import pandas as pd
from datetime import datetime
import os

try:
    import xgboost as xgb
    from xgboost import XGBClassifier
except Exception:
    xgb = None
    XGBClassifier = None

# Model paths (expecting model files under workspace `model/` folder)
_MODEL_DIR = os.path.join(os.path.dirname(__file__), 'model')
_BIN_MODEL_PATH = os.path.join(_MODEL_DIR, 'xgb_anomaly_binary_model_production.json')
_MULTI_MODEL_PATH = os.path.join(_MODEL_DIR, 'xgb_anomaly_model_production.json')

_xgb_bin_model = None
_xgb_multi_model = None

def _load_models():
    global _xgb_bin_model, _xgb_multi_model
    if XGBClassifier is None:
        return
    try:
        if os.path.exists(_BIN_MODEL_PATH):
            _xgb_bin_model = XGBClassifier()
            _xgb_bin_model.load_model(_BIN_MODEL_PATH)
    except Exception:
        _xgb_bin_model = None
    try:
        if os.path.exists(_MULTI_MODEL_PATH):
            _xgb_multi_model = XGBClassifier()
            _xgb_multi_model.load_model(_MULTI_MODEL_PATH)
    except Exception:
        _xgb_multi_model = None


_load_models()


def _extract_features_for_ml(row):
    is_clearance_violation = (
        row.get('clearance') in ['public', 'internal'] and 
        row.get('data_classification') in ['restricted', 'confidential']
    )
    is_terminated_access = row.get('employee_status') == 'terminated'
    is_high_risk_action = row.get('action') in ['permission_change', 'delete']
    # If rolling aggregates are not available, fall back to per-event fields
    rolling_bytes_1h = row.get('rolling_bytes_1h', row.get('bytes_out', 0))
    rolling_failed_logins_1h = row.get('rolling_failed_logins_1h', 0)
    event_count_1h = row.get('event_count_1h', 1)
    return [
        int(is_clearance_violation),
        int(is_terminated_access),
        int(is_high_risk_action),
        rolling_bytes_1h,
        rolling_failed_logins_1h,
        event_count_1h,
    ]


def _ml_anomaly_score(row):
    if _xgb_bin_model is None:
        return None
    try:
        feat = _extract_features_for_ml(row)
        import numpy as np
        X = np.array(feat).reshape(1, -1)
        if hasattr(_xgb_bin_model, 'predict_proba'):
            score = float(_xgb_bin_model.predict_proba(X)[:, 1][0])
        else:
            score = float(_xgb_bin_model.predict(X)[0])
        return score
    except Exception:
        return None


def generate_security_alert(row):
    """
    Mengevaluasi satu baris log event dan mengembalikan level risiko (severity).
    Fungsi ini berjalan secara hierarkis (Top-Down):
    Mengecek kondisi paling kritis terlebih dahulu, lalu turun ke risiko yang lebih rendah.
    Jika model XGBoost tersedia, tambahkan pengecekan ML anomaly score sebelum
    mengembalikan 'Normal'.
    """

    # 1. Hitung dulu skor ML di awal (Jika model tersedia)
    ml_score = _ml_anomaly_score(row)
    if ml_score is not None:
        row['ml_anomaly_score'] = ml_score
        
    # Mapping level ke angka untuk mencari nilai tertinggi (Max Escalation)
    severity_map = {'Normal': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
    reverse_map = {v: k for k, v in severity_map.items()}
    
    current_severity = 0 # Default mulai dari Normal
    
    # 2. Evaluasi Probabilitas ML
    if ml_score is not None:
        if ml_score >= 0.90:
            current_severity = max(current_severity, 4) # CRITICAL
        elif ml_score >= 0.75:
            current_severity = max(current_severity, 3) # HIGH
        elif ml_score >= 0.50:
            current_severity = max(current_severity, 2) # MEDIUM

    # 3. Evaluasi Aturan Heuristik (Bisa Meng-override ML ke tingkat lebih tinggi)
    
    # TIER CRITICAL
    if row.get('employee_status') == 'terminated':
        current_severity = max(current_severity, 4)
    if (row.get('action') == 'download' and 
        row.get('data_classification') in ['restricted', 'confidential'] and 
        row.get('bytes_out', 0) > 1_000_000):
        current_severity = max(current_severity, 4)

    # TIER HIGH
    if (row.get('action') in ['permission_change', 'delete'] and 
        row.get('data_classification') in ['restricted', 'confidential']):
        current_severity = max(current_severity, 3)
    if row.get('rolling_failed_logins_1h', 0) >= 5 and row.get('status') == 'success':
        current_severity = max(current_severity, 3)

    # TIER MEDIUM
    is_clearance_violation = (row.get('clearance') in ['public', 'internal'] and 
                              row.get('data_classification') in ['restricted', 'confidential'])
    if is_clearance_violation:
        current_severity = max(current_severity, 2)
    if row.get('rolling_failed_logins_1h', 0) >= 3 and row.get('status') == 'failed':
        current_severity = max(current_severity, 2)

    # TIER LOW / Normal
    if row.get('status') == 'failed':
        current_severity = max(current_severity, 1)

    # Kembalikan level tertinggi yang terdeteksi oleh sistem
    return reverse_map[current_severity]