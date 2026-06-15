# UAS Perancangan Big Data - Security Analytics Platform 🔒

Platform simulasi dan monitoring real-time untuk **Data Security Analytics** dengan fokus pada deteksi anomali, streaming data, dan alert management.

## 📋 Daftar Isi
- [Gambaran Umum](#gambaran-umum)
- [Arsitektur Sistem](#arsitektur-sistem)
- [Struktur File & Fungsi](#struktur-file--fungsi)
- [Instalasi & Setup](#instalasi--setup)
- [Cara Penggunaan](#cara-penggunaan)
- [Fitur Utama](#fitur-utama)
- [Teknologi & Dependencies](#teknologi--dependencies)

---

## 🎯 Gambaran Umum

Proyek ini adalah sistem **Big Data Security Analytics** yang mensimulasikan aktivitas pengguna di dalam organisasi dan mendeteksi potensi ancaman keamanan secara real-time. Platform ini menggunakan kombinasi:

- **Data Streaming**: Menghasilkan synthetic security events yang realistis
- **Rule-Based Detection**: Evaluasi berbasis aturan heuristik untuk alert classification
- **Machine Learning** (Optional): XGBoost untuk anomaly scoring
- **Interactive Dashboard**: Monitoring dengan Streamlit untuk visualisasi real-time

### Use Cases
✅ Deteksi **data exfiltration** (pencurian data)  
✅ Identifikasi **compromised accounts** (akun yang dikompromis)  
✅ Monitoring **privilege abuse** (penyalahgunaan hak istimewa)  
✅ Analisis **clearance level violations** (pelanggaran level akses)  
✅ Real-time alert untuk security incidents  

---

## 🏗️ Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────┐
│                  SECURITY ANALYTICS PLATFORM             │
└─────────────────────────────────────────────────────────┘
                              │
                              ├── Streaming Layer
                              │   └── stream_generator.py
                              │       └── Generates synthetic events
                              │
                              ├── Processing Layer
                              │   ├── stream_processor.py
                              │   │   └── Real-time alerts (CLI)
                              │   │
                              │   └── security_alert.py
                              │       └── Alert evaluation & scoring
                              │
                              └── Presentation Layer
                                  ├── app.py
                                  │   └── Streamlit Dashboard
                                  │
                                  └── data/
                                      └── Output events & storage
```

### Flow Diagram

```
1. EVENT GENERATION (stream_generator.py)
   │
   ├─ build_users() → Membuat profil user synthetic
   ├─ event_stream() → Generate security events stream
   └─ Output: JSON Lines (1 event per baris)
   
   │
   ▼
   
2. STREAM PROCESSING & ALERT DETECTION (stream_processor.py + security_alert.py)
   │
   ├─ Consume event dari stream
   ├─ Track rolling statistics (failed logins, bytes out)
   ├─ Evaluate alert rules (generate_security_alert)
   └─ Output: CRITICAL, HIGH, MEDIUM, LOW, atau Normal
   
   │
   ▼
   
3. VISUALIZATION & MONITORING (app.py)
   │
   ├─ Process events through alert engine
   ├─ Display real-time metrics & charts
   ├─ Show alert summary & distribution
   └─ Interactive Streamlit dashboard
```

---

## 📁 Struktur File & Fungsi

### 1. **stream_generator.py** (1,480 baris)
**Tujuan**: Menghasilkan synthetic security event stream yang realistis

#### Komponen Utama:

**`build_users(n=150, seed=42)`**
- Membuat daftar user synthetic dengan atribut:
  - `user_id`: Format U0001-U9999
  - `dept`: Department (Finance, HR, Engineering, Sales, Legal, Data Science, Operations)
  - `role`: Position (analyst, manager, engineer, director, intern, admin)
  - `clearance`: Access level (public, internal, confidential, restricted)
  - `status`: active atau terminated
- Default: 95% active, 5% terminated
- Specific users (index 6, 22, 79) dipaksa terminated untuk attack simulation

**`event_stream(total=1000, seed=42)`**
- Generator yang menghasilkan security events stream
- Setiap event merepresentasikan aktivitas user (login, read, download, delete, dll)
- Menghitung `risk_score` berdasarkan:
  - User status (terminated = higher risk)
  - Action type (delete, permission_change = dangerous)
  - Clearance vs Asset sensitivity mismatch
  - Data volume accessed

#### Skenario Attack yang Disimulasikan:

**🔴 Exfiltration (20% progress)**
- User: Index 149 (compromised)
- Asset: Payroll database
- Action: Download massive data (5-15 MB)
- Source IP: Tor exit node (185.220.101.2)
- Risk Score: 95
- Label: `exfiltration_suspected`

**🟠 Compromised Account (55% progress)**
- User: Index 22 (terminated user)
- Asset: Customer database
- Actions: login, query, schema_discovery (reconnaissance)
- Source IP: Malicious proxy (45.77.21.13)
- Risk Score: 85
- Label: `compromised_account`

**🟡 Privilege Abuse (80% progress)**
- User: Index 79 (terminated admin)
- Asset: Git repository
- Action: permission_change (escalation)
- Source IP: VPN compromise (103.12.44.9)
- Risk Score: 90
- Label: `privilege_abuse`

#### Output Event Structure:
```json
{
  "event_id": "EVT0000001",
  "event_time": "2026-05-27T...",
  "user_id": "U0001",
  "dept": "Engineering",
  "role": "engineer",
  "clearance": "internal",
  "employee_status": "active",
  "device_type": "laptop",
  "source_ip": "10.10.15.42",
  "asset_id": "cust_db",
  "asset_type": "database",
  "data_classification": "restricted",
  "action": "download",
  "status": "success",
  "bytes_out": 150000,
  "records_accessed": 342,
  "latency_ms": 128,
  "risk_score": 68,
  "label": "normal"
}
```

#### Konfigurasi Event Distribution:
- **login** (22%): Akses login paling umum
- **read** (25%): Membaca data
- **query** (18%): Query database
- **download** (10%): Download files
- **upload** (6%): Upload files
- **logout** (8%): Logout
- **delete** (2%): Delete data (rare & risky)
- **permission_change** (1%): Change permissions (very rare)
- **schema_discovery** (5%): Explore data structure

---

### 2. **security_alert.py** (138 baris)
**Tujuan**: Evaluasi alert rules dan threat severity scoring

#### Fungsi Utama:

**`generate_security_alert(row)`**
- Mengevaluasi satu event dan mengembalikan severity level
- Menggunakan **hierarchical evaluation** (top-down checking)
- Menggabungkan rule-based logic + optional ML anomaly scoring

#### Severity Levels:
| Level | Score | Kondisi |
|-------|-------|---------|
| **CRITICAL** | 4 | Terminated user akses, besar data exfiltration (>1MB), ML score ≥0.90 |
| **HIGH** | 3 | Permission change/delete pada restricted data, ≥5 failed logins sebelumnya, ML score ≥0.75 |
| **MEDIUM** | 2 | Clearance violation, ≥3 failed login attempts, ML score ≥0.50 |
| **LOW** | 1 | Failed action attempts |
| **Normal** | 0 | Aktivitas normal tanpa red flag |

#### Alert Rules:

**TIER CRITICAL**
```python
1. Terminated employee accessing system → CRITICAL
2. Download restricted/confidential data >1MB → CRITICAL
3. ML anomaly score ≥0.90 → CRITICAL
```

**TIER HIGH**
```python
1. permission_change atau delete pada restricted data → HIGH
2. ≥5 failed login dalam 1 jam + successful login → HIGH
3. ML anomaly score ≥0.75 → HIGH
```

**TIER MEDIUM**
```python
1. User clearance < asset classification → MEDIUM
2. ≥3 failed logins dalam 1 jam → MEDIUM
3. ML anomaly score ≥0.50 → MEDIUM
```

**TIER LOW**
```python
1. Failed actions → LOW
```

#### Machine Learning Integration:

**`_extract_features_for_ml(row)`**
Mengekstrak 6 fitur untuk XGBoost:
1. Clearance violation (binary)
2. Terminated access (binary)
3. High-risk action (binary)
4. Rolling bytes in 1h
5. Rolling failed logins in 1h
6. Event count in 1h

Model files (jika ada):
- `model/xgb_anomaly_binary_model_production.json` - Binary classifier
- `model/xgb_anomaly_model_production.json` - Multi-class classifier

---

### 3. **stream_processor.py** (75 baris)
**Tujuan**: Monitoring alert real-time di terminal (CLI)

#### Fitur:
- Membaca event dari `event_stream()`
- Maintain rolling statistics per user (failed logins dalam 1 jam)
- Evaluasi setiap event dengan alert rules
- Print CRITICAL, HIGH, MEDIUM alerts ke stdout

#### Output Alert:
```json
{
  "alert_time": "2026-06-15T10:30:45.123456",
  "severity": "CRITICAL",
  "event_id": "EVT0000150",
  "user_id": "U0149",
  "action": "download",
  "asset_id": "payroll",
  "bytes_out": 8500000,
  "risk_score": 95,
  "label": "exfiltration_suspected"
}
```

#### Cara Pakai:
```bash
# Generate 1000 events dengan 0.05 detik delay per event
python stream_processor.py --events 1000 --speed 0.05
```

---

### 4. **app.py** (257 baris)
**Tujuan**: Interactive dashboard monitoring dengan Streamlit

#### Komponen Dashboard:

**Sidebar Controls**
- Total events: 10-20,000 (default 500)
- Event delay: 0.0-1.0 detik (default 0.05)
- Latest alerts preview: 1-500 (default 20)
- UI refresh rate: 1-60 Hz (default 10)

**Metrics Cards**
- Total events processed
- Alerts generated
- Critical alerts count
- High alerts count
- Medium alerts count
- Normal events count
- Unique users

**Visualizations**

1. **Alert Summary Table**
   - Top 200 alerts sorted by severity
   - Columns: alert_time, event_id, user_id, asset_id, action, severity, label, bytes_out

2. **Event Label Distribution (Pie Chart)**
   - Shows percentage split:
     - normal
     - policy_violation
     - exfiltration_suspected
     - compromised_account
     - privilege_abuse

3. **Latest Event Sample (100 rows)**
   - Raw event data sorted by time

4. **Alert Severity Distribution (Bar Chart)**
   - Count by severity (CRITICAL, HIGH, MEDIUM, LOW, Normal)

#### Optimisasi UI:
- **Throttled updates**: UI updates maksimal 1/`ui_update_interval` Hz
- **Bounded deque**: Hanya simpan N latest alerts (prevent memory bloat)
- **Non-blocking rendering**: Error di UI tidak crash processor

#### Cara Pakai:
```bash
streamlit run app.py
# Akses di http://localhost:8501
```

---

### 5. **requirements.txt**
**Dependencies & versi yang diperlukan**

```
streamlit==1.50.0          # Dashboard & UI framework
pandas==2.3.3              # Data manipulation & analysis
altair==5.5.0              # Interactive charting (Vega-Lite)
xgboost==3.2.0             # Machine learning (anomaly detection)
```

---

### 6. **data/** (folder)
**Storage untuk output files**

Menyimpan hasil generate events:
- `stream_events.jsonl` - Generated security events (1 event per baris)
- `sample_stream_events.csv` - Sample batch data untuk testing

---

### 7. **model/** (folder)
**Pre-trained ML Models (optional)**

Menyimpan trained XGBoost models:
- `xgb_anomaly_binary_model_production.json` - Binary classifier
- `xgb_anomaly_model_production.json` - Multi-class severity classifier

---

## 🚀 Instalasi & Setup

### Prasyarat
- **Python 3.13** atau lebih
- pip (Python package manager)

### Step-by-Step Installation

#### 1. Clone Repository
```bash
git clone https://github.com/Elvin-Aurelio/UAS-Perancangan-Big-Data.git
cd UAS-Perancangan-Big-Data
```

#### 2. Verifikasi Python Version
```bash
python --version
# Output harus: Python 3.13.x
```

Jika menggunakan pyenv atau conda untuk multiple Python versions:
```bash
# Menggunakan pyenv
pyenv install 3.13.0
pyenv local 3.13.0
python --version

# Atau menggunakan conda
conda create -n bigdata python=3.13
conda activate bigdata
```

#### 3. Setup Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

#### 4. Upgrade pip dan install dependencies
```bash
# Upgrade pip ke versi terbaru
pip install --upgrade pip

# Install dependencies dari requirements.txt
pip install -r requirements.txt
```

Verifikasi installation:
```bash
pip list
# Seharusnya menampilkan:
# streamlit         1.50.0
# pandas            2.3.3
# altair            5.5.0
# xgboost           3.2.0
```

#### 5. Verifikasi Dependencies untuk Python 3.13
```bash
python -c "import streamlit; import pandas; import altair; import xgboost; print('✅ All dependencies imported successfully!')"
```

#### 6. Create Data Directory (jika belum ada)
```bash
mkdir -p data
mkdir -p model
```

---

## 💻 Cara Penggunaan

### Opsi 1: Generate Event Stream & Simpan ke File

```bash
# Generate 100,000 events dengan kecepatan 0.05 detik per event
python stream_generator.py --events 100000 --speed 0.05 --out data/stream_events.jsonl

# Hanya generate cepat tanpa delay (untuk batch processing)
python stream_generator.py --events 50000 --out data/events.jsonl
```

**Output**: File `data/stream_events.jsonl` dengan format JSON Lines:
```jsonl
{"event_id": "EVT0000001", "event_time": "...", ...}
{"event_id": "EVT0000002", "event_time": "...", ...}
...
```

---

### Opsi 2: Real-time Alert Monitoring (CLI)

```bash
# Monitor 1000 events dengan real-time alert printing
python stream_processor.py --events 1000 --speed 0.05

# Fast monitoring (no delay)
python stream_processor.py --events 5000
```

**Output Alert di Terminal**:
```json
{"alert_time": "2026-06-15T10:30:45.123456", "severity": "CRITICAL", "event_id": "EVT0000150", ...}
{"alert_time": "2026-06-15T10:31:12.456789", "severity": "HIGH", "event_id": "EVT0000200", ...}
```

---

### Opsi 3: Interactive Dashboard (Recommended for Visualization)

```bash
# Launch Streamlit dashboard
streamlit run app.py

# Dashboard akan terbuka di browser: http://localhost:8501
```

**Di Dashboard**:
1. Atur parameter di sidebar (jumlah events, delay, refresh rate)
2. Klik tombol "Run simulation"
3. Lihat progress bar dan metrics secara real-time
4. Analisis alert distribution dengan charts

---

## ✨ Fitur Utama

### 1. **Synthetic Data Generation** 
✅ Realistic user behavior patterns  
✅ 3 skenario attack yang disimulasikan  
✅ Risk scoring berdasarkan multi-factor analysis  
✅ Reproducible dengan seed control  

### 2. **Real-time Alert Detection**
✅ Hierarchical rule evaluation  
✅ 5 severity levels (CRITICAL → Normal)  
✅ Rolling statistics per user (failed logins, bytes out)  
✅ Optional ML anomaly scoring (XGBoost)  

### 3. **Interactive Visualization**
✅ Live metrics dashboard  
✅ Alert severity distribution  
✅ Event label pie chart  
✅ Filterable alert summary table  

### 4. **Production-Ready Features**
✅ Bounded memory usage (deque for alert history)  
✅ Throttled UI updates (prevent performance degradation)  
✅ Error handling & graceful degradation  
✅ Configurable parameters  

---

## 🛠️ Teknologi & Dependencies

| Komponen | Versi | Fungsi |
|----------|-------|--------|
| Python | 3.13 | Runtime environment |
| Streamlit | 1.50.0 | Web dashboard framework |
| Pandas | 2.3.3 | Data manipulation & analysis |
| Altair | 5.5.0 | Interactive visualization |
| XGBoost | 3.2.0 | ML anomaly detection |

### Kompatibilitas

Platform ini dikembangkan dan ditest untuk:
- ✅ Python 3.13.0+
- ✅ Windows 10+, macOS 11+, Linux (Ubuntu 20.04+)
- ✅ pip 24.0+

---

## 📊 Contoh Workflow

### Scenario: Analisis Exfiltration Attack

```bash
# 1. Generate 5000 events dengan attack scenarios
python stream_generator.py --events 5000 --speed 0.02 --out data/exfil_test.jsonl

# 2. Monitoring alerts real-time di CLI
python stream_processor.py --events 5000 --speed 0.02

# Output: Terdeteksi CRITICAL alerts untuk exfiltration_suspected (20% progress point)

# 3. Visualisasi lengkap dengan dashboard
streamlit run app.py
# → Lihat event distribution, alert severity, specific attack patterns
```

---

## 📝 Notes & Best Practices

### For Development
- **Reproducible Results**: Gunakan `seed=42` untuk testing
- **Memory Usage**: Bounded deque mencegah memory bloat untuk stream besar
- **Testing**: Start dengan `--events 100` untuk quick testing

### For Production
- **Event Volume**: Scale hingga 100,000+ events dengan speed 0.0 (batch processing)
- **Model Training**: Train XGBoost models dengan historical data dan simpan ke `model/`
- **Monitoring**: Deploy `stream_processor.py` sebagai background service untuk real-time alerts

---

## 📞 Support & Questions

Untuk pertanyaan atau issues, silakan buka GitHub Issues di repository ini.

---

**Last Updated**: June 15, 2026  
**Python Version**: 3.13  
**Platform**: Cross-platform (Windows, macOS, Linux)
