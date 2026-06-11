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

    # ---------------------------------------------------------
    # 1. TIER CRITICAL (Insiden Fatal & Pasti Berbahaya)
    # ---------------------------------------------------------
    # Kondisi A: Karyawan yang sudah dipecat/keluar masih bisa akses sistem
    if row.get('employee_status') == 'terminated':
        return 'CRITICAL'

    # Kondisi B: Eksfiltrasi data masif pada aset rahasia (> 1 MB)
    if (
        row.get('action') == 'download'
        and row.get('data_classification') in ['restricted', 'confidential']
        and row.get('bytes_out', 0) > 1_000_000
    ):
        return 'CRITICAL'

    # ---------------------------------------------------------
    # 2. TIER HIGH (Ancaman Aktif yang Membutuhkan Respon Cepat)
    # ---------------------------------------------------------
    # Kondisi C: Perubahan hak akses atau penghapusan pada kode/database
    if (
        row.get('action') in ['permission_change', 'delete']
        and row.get('data_classification') in ['restricted', 'confidential']
    ):
        return 'HIGH'

    # Kondisi D: Indikasi Brute-Force yang BERHASIL
    # (Banyak gagal sebelumnya, tapi status saat ini success)
    if row.get('rolling_failed_logins_1h', 0) >= 5 and row.get('status') == 'success':
        return 'HIGH'

    # ---------------------------------------------------------
    # 3. TIER MEDIUM (Aktivitas Mencurigakan, Perlu Pemantauan)
    # ---------------------------------------------------------
    # Kondisi E: Pelanggaran batas clearance (Akses tidak sah yang mungkin tidak sengaja)
    is_clearance_violation = (
        row.get('clearance') in ['public', 'internal']
        and row.get('data_classification') in ['restricted', 'confidential']
    )
    if is_clearance_violation:
        return 'MEDIUM'

    # Kondisi F: Indikasi Brute-Force yang MASIH GAGAL
    if row.get('rolling_failed_logins_1h', 0) >= 3 and row.get('status') == 'failed':
        return 'MEDIUM'

    # ---------------------------------------------------------
    # 4. TIER Normal (Aktivitas Normal atau Kesalahan Operasional Ringan)
    # ---------------------------------------------------------
    # Kondisi G: Gagal login biasa atau error sistem (bukan bagian dari rentetan serangan)
    if row.get('status') == 'failed':
        return 'Normal'

    # If we reach here, run ML model (if available) to see if it's anomalous
    ml_score = _ml_anomaly_score(row)
    if ml_score is not None:
        row['ml_anomaly_score'] = ml_score
        if ml_score >= 0.9:
            return 'CRITICAL'
        if ml_score >= 0.75:
            return 'HIGH'
        if ml_score >= 0.5:
            return 'MEDIUM'

    # Default: Segala aktivitas normal lainnya yang berhasil
    return 'Normal'