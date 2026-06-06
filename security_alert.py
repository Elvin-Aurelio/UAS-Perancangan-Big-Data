import time
import pandas as pd
from datetime import datetime

def generate_security_alert(row):
    """
    Mengevaluasi satu baris log event dan mengembalikan level risiko (severity).
    Fungsi ini berjalan secara hierarkis (Top-Down): 
    Mengecek kondisi paling kritis terlebih dahulu, lalu turun ke risiko yang lebih rendah.
    """
    
    # ---------------------------------------------------------
    # 1. TIER CRITICAL (Insiden Fatal & Pasti Berbahaya)
    # ---------------------------------------------------------
    # Kondisi A: Karyawan yang sudah dipecat/keluar masih bisa akses sistem
    if row.get('employee_status') == 'terminated':
        return 'CRITICAL'
        
    # Kondisi B: Eksfiltrasi data masif pada aset rahasia (> 1 MB)
    if (row.get('action') == 'download' and 
        row.get('data_classification') in ['restricted', 'confidential'] and 
        row.get('bytes_out', 0) > 1_000_000):
        return 'CRITICAL'

    # ---------------------------------------------------------
    # 2. TIER HIGH (Ancaman Aktif yang Membutuhkan Respon Cepat)
    # ---------------------------------------------------------
    # Kondisi C: Perubahan hak akses atau penghapusan pada kode/database
    if (row.get('action') in ['permission_change', 'delete'] and 
        row.get('data_classification') in ['restricted', 'confidential']):
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
        row.get('clearance') in ['public', 'internal'] and 
        row.get('data_classification') in ['restricted', 'confidential']
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
        
    # Default: Segala aktivitas normal lainnya yang berhasil
    return 'Normal'