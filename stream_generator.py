"""
Stream Event Generator untuk Data Security Analytics

Modul ini menghasilkan synthetic event stream yang mensimulasikan aktivitas pengguna
di dalam sebuah organisasi dengan berbagai skenario keamanan: normal activity, anomalies,
dan attack patterns. Data ini digunakan untuk training dan testing security analytics models.

Fitur utama:
- Generates realistic user behavior patterns
- Simulates multiple attack scenarios (exfiltration, account compromise, privilege abuse)
- Calculates risk scores berdasarkan user profile, action, dan asset sensitivity
- Outputs events sebagai JSON stream (1 event per baris)

Penggunaan:
    python stream_generator.py --events 100000 --speed 0.1 --out events.jsonl
"""

import argparse, csv, json, random, time
from datetime import datetime, timedelta
from pathlib import Path

# ========== STATIC DATA & CONFIGURATIONS ==========
# Daftar departemen yang ada di organisasi
DEPTS = ['Finance', 'HR', 'Engineering', 'Sales', 'Legal', 'Data Science', 'Operations']

# Daftar jabatan/peran pengguna
ROLES = ['analyst', 'manager', 'engineer', 'director', 'intern', 'admin']

# Tipe device yang digunakan untuk mengakses sistem
DEVICES = ['laptop', 'mobile', 'workstation', 'server', 'vpn_gateway']

# Daftar aset/resources yang ada di sistem
# Format: (asset_id, asset_type, data_classification)
# - asset_type: jenis aset (database, storage, code, dashboard, web, saas)
# - data_classification: tingkat sensitifitas data (public, internal, confidential, restricted)
ASSETS = [
    ('cust_db', 'database', 'restricted'),        # Database pelanggan - sensitif tinggi
    ('payroll', 'database', 'confidential'),      # Database gaji - konfidensial
    ('crm', 'saas', 'confidential'),              # CRM system - konfidensial
    ('data_lake', 'storage', 'restricted'),       # Data lake - sensitif tinggi
    ('git_repo', 'code', 'internal'),             # Repository kode sumber
    ('bi_dashboard', 'dashboard', 'internal'),    # Dashboard business intelligence
    ('public_web', 'web', 'public'),              # Website publik
    ('ticketing', 'saas', 'internal')             # Sistem ticketing internal
]

def build_users(n=150, seed=42):
    """
    Membuat daftar user dengan profil acak.
    
    Fungsi ini menghasilkan synthetic user data dengan atribut: user_id, department,
    role, clearance level, dan status. Clearance level menunjukkan tingkat akses
    yang diizinkan user terhadap data yang berbeda klasifikasi.
    
    Args:
        n (int): Jumlah user yang akan dibuat. Default 150.
        seed (int): Random seed untuk reproducibility. Default 42.
    
    Returns:
        list: List of dict dengan structure:
            {
                'user_id': str (format: U0001-U9999),
                'dept': str (salah satu dari DEPTS),
                'role': str (salah satu dari ROLES),
                'clearance': str (public, internal, confidential, restricted),
                'status': str (active atau terminated)
            }
    
    Note:
        - Secara default 95% user adalah active, 5% terminated
        - Beberapa user tertentu (index 6, 22, 79) dipaksa jadi terminated
          untuk mensimulasikan specific attack scenarios
    """
    random.seed(seed)
    users = []
    
    # Generate random user profiles
    for i in range(1, n+1):
        users.append({
            'user_id': f'U{i:04d}',
            'dept': random.choice(DEPTS),
            'role': random.choice(ROLES),
            'clearance': random.choice(['public', 'internal', 'confidential', 'restricted']),
            'status': random.choices(['active', 'terminated'], [95, 5])[0]  # 95% active, 5% terminated
        })
    
    # Force specific users ke status "terminated" untuk attack simulation scenarios
    # - Index 6: akan digunakan untuk exfiltration attack
    # - Index 22: akan digunakan untuk compromised account scenario
    # - Index 79: akan digunakan untuk privilege abuse scenario
    for idx in [6, 22, 79]:
        users[idx]['status'] = 'terminated'
    
    return users


def event_stream(total=1000, seed=42):
    """
    Generator untuk menghasilkan security event stream.
    
    Fungsi ini adalah core logic yang menghasilkan realistic security events dengan
    beberapa skenario attack yang disimulasikan. Setiap event merepresentasikan
    aktivitas user (login, read, download, delete, etc.) terhadap suatu asset.
    
    Risk score dihitung berdasarkan multiple factors:
    - User status (terminated users = higher risk)
    - Action type (dangerous actions seperti delete, permission_change)
    - Asset sensitivity vs user clearance level mismatch
    - Data volume accessed
    
    Skenario Attack yang Disimulasikan:
    1. EXFILTRATION (20% progress area):
       - User mencuri large volume data dari sensitive asset (payroll database)
       - Indikator: large bytes_out (5-15 MB), terminated user status
    
    2. COMPROMISED ACCOUNT (55% progress area):
       - Attacker menggunakan akun user yang sudah di-compromise
       - Indikator: akses dari suspicious IP, multiple failed login attempts
    
    3. PRIVILEGE ABUSE (80% progress area):
       - User dengan privilege berubah permissions untuk unauthorized access
       - Indikator: permission_change action dari terminated user, suspicious IP
    
    Args:
        total (int): Total jumlah event yang akan di-generate. Default 1000.
        seed (int): Random seed untuk reproducibility. Default 42.
    
    Yields:
        dict: Event object dengan struktur:
            {
                'event_id': str (EVT0000001 format),
                'event_time': str (ISO format timestamp),
                'user_id': str,
                'dept': str,
                'role': str,
                'device_type': str,
                'source_ip': str (IP address),
                'asset_id': str,
                'asset_type': str,
                'data_classification': str,
                'action': str (login, logout, read, query, download, upload, delete, etc.),
                'status': str (success atau failed),
                'bytes_out': int (data volume in bytes),
                'records_accessed': int (estimated record count),
                'latency_ms': int (network latency),
                'risk_score': int (0-100 score),
                'label': str (normal, policy_violation, exfiltration_suspected, etc.)
            }
    """
    random.seed()  # Reset seed agar setiap run menghasilkan data berbeda
    users = build_users(seed=seed)
    start = datetime.now().replace(microsecond=0)

    for n in range(1, total + 1):
        # ========== BASELINE EVENT GENERATION ==========
        # Generate random event dengan user, asset, dan action random
        u = random.choice(users)
        asset = random.choice(ASSETS)

        # Action distribution (realistic distribution):
        # - login (22%): akses login adalah paling sering
        # - read (25%): membaca data
        # - query (18%): query database
        # - download (10%): download files
        # - upload (6%): upload files
        # - logout (8%): logout
        # - delete (2%): delete data (rare & risky)
        # - permission_change (1%): change permissions (very rare & risky)
        # - schema_discovery (5%): explore data structure
        action = random.choices(
            ['login','logout','read','query','download','upload','delete','permission_change','schema_discovery'],
            [22,8,25,18,10,6,2,1,5]
        )[0]

        # Data volume: normally distributed dengan mean 80KB dan std 50KB
        # Ini merepresentasikan typical data transfer volume
        bytes_out = max(0, int(random.gauss(80000, 50000)))
        
        # Source IP: internal network (10.10.x.x range)
        # Format: 10.10.{random 1-20}.{random 2-254} untuk avoid network & broadcast addresses
        src = f"10.10.{random.randint(1,20)}.{random.randint(2,254)}"
        
        # Status: 90% success, 10% failed (realistic failure rate)
        status = random.choices(['success', 'failed'], [90,10])[0]

        # ========== RISK CALCULATION ==========
        # Risk score adalah akumulasi dari berbagai risk factors
        risk = 0

        # Factor 1: User Status (terminated users sangat berisiko)
        # Terminated user yang masih access = potential security breach
        if u['status'] == 'terminated':
            risk += 45

        # Factor 2: Action Type (certain actions lebih dangerous)
        # - delete: merusak data integrity
        # - permission_change: escalate privileges
        if action in ['delete', 'permission_change']:
            risk += 25

        # Factor 3: Clearance Level Mismatch
        # Jika user clearance < asset classification = unauthorized access attempt
        # Misal: public-clearance user akses restricted data = high risk
        if asset[2] in ['restricted','confidential'] and u['clearance'] in ['public','internal']:
            risk += 25

        # Factor 4: Unusual Data Volume
        # Download > 200KB bisa jadi suspicious (potential data exfiltration)
        if bytes_out > 200000:
            risk += 10

        # ========== DEFAULT LABEL ==========
        label = 'normal'

        # ========== ATTACK SCENARIO 1: DATA EXFILTRATION ==========
        # Skenario ini mensimulasikan unauthorized massive data download
        # Terjadi di 20% progress point, spanning 20 events
        # - User: index 149 (specific "compromised" user)
        # - Asset: payroll (highly sensitive)
        # - Action: download (exfiltration method)
        # - Volume: massive 5-15 MB (obvious indicator)
        # - Source IP: Tor exit node (185.220.101.2 - known malicious)
        # - Risk: 95 (very high - anomaly detection trigger)
        if n in range(int(total * 0.20), int(total * 0.20) + 20):
            u = users[min(len(users)-1, 149)]  # Fixed user untuk konsistency
            asset = ('payroll', 'database', 'confidential')
            action = 'download'
            bytes_out = random.randint(5_000_000,15_000_000)  # 5-15 MB
            src = '185.220.101.2'  # Known Tor exit node
            status = 'success'
            risk = 95
            label = 'exfiltration_suspected'

        # ========== ATTACK SCENARIO 2: COMPROMISED ACCOUNT ==========
        # Skenario ini mensimulasikan akun user yang sudah di-compromise oleh attacker
        # Terjadi di 55% progress point, spanning 20 events
        # - User: index 22 (terminated user - reused from build_users)
        # - Asset: cust_db (customer database - restricted)
        # - Actions: login, query, schema_discovery (reconnaissance activities)
        # - Source IP: compromised proxy (45.77.21.13)
        # - Risk: 85 (high - unauthorized user account access)
        elif n in range(int(total * 0.55), int(total * 0.55) + 20):
            u = users[22]  # Specific terminated user
            asset = ('cust_db', 'database', 'restricted', 'extra')
            action = random.choice(['login', 'query', 'schema_discovery'])  # Attacker reconnaissance
            bytes_out = random.randint(100_000, 500_000)
            src = '45.77.21.13'  # Known malicious proxy
            status = random.choice(['failed','success'])
            risk = 0 + 85
            label = 'compromised_account'

        # ========== ATTACK SCENARIO 3: PRIVILEGE ABUSE ==========
        # Skenario ini mensimulasikan privilege escalation attack
        # Attacker menggunakan compromised admin account untuk change permissions
        # Terjadi di 80% progress point, spanning 15 events
        # - User: index 79 (terminated admin - reused from build_users)
        # - Asset: git_repo (source code repository)
        # - Action: permission_change (changing access control)
        # - Source IP: VPN compromise (103.12.44.9)
        # - Risk: 90 (very high - privilege escalation)
        elif n in range(int(total * 0.80), int(total * 0.80) + 15):
            u = users[79]  # Specific terminated user (likely admin)
            asset = ('git_repo','code','internal')
            action = 'permission_change'  # Escalating privileges
            bytes_out = 0
            src = '103.12.44.9'  # VPN compromise IP
            status = 'success'
            risk = 90
            label = 'privilege_abuse'

        # ========== POLICY VIOLATION DETECTION ==========
        # Jika baseline risk score >= 60, classify sebagai policy violation
        # Ini adalah normal activity tapi dengan high risk factors
        elif risk >= 60:
            label = 'policy_violation'

        # ========== FINAL EVENT OBJECT ==========
        # Yield complete event dengan semua field yang diperlukan untuk analysis
        yield {
            'event_id': f'EVT{n:07d}',  # Sequential event ID
            'event_time': (start + timedelta(seconds=n*10)).isoformat(),  # Timestamp (10sec interval)
            'user_id': u['user_id'],
            'dept': u['dept'],
            'role': u['role'],
            'device_type': random.choice(DEVICES),
            'source_ip': src,
            'asset_id': asset[0],
            'asset_type': asset[1],
            'data_classification': asset[2],
            'action': action,
            'status': status,
            'bytes_out': bytes_out,
            'records_accessed': max(0, int(bytes_out / random.randint(1, 500))),  # Estimate records from bytes
            'latency_ms': max(1, int(random.gauss(120,30))),  # Network latency normally distributed
            'risk_score': min(100, risk + random.randint(0, 8)),  # Add slight randomness (0-8) to risk
            'label': label,
        }

def main():
    """
    Main entry point untuk script ini.
    
    Memproses command-line arguments dan menjalankan event stream generation.
    Output ditulis ke file dalam format JSON Lines (1 event per baris).
    
    Command-line Arguments:
        --events (int): Jumlah events yang akan di-generate. Default: 1000
        --speed (float): Delay per event dalam detik (untuk real-time simulation).
                        0.0 = no delay (generate secepatnya). Default: 0.0
        --out (str): Path file output untuk menyimpan events. Default: 'event_stream.json'
    
    Contoh penggunaan:
        python stream_generator.py --events 5000 --speed 0.1 --out events.json
        # Generates 5000 events dengan 0.1 detik delay per event, simpan ke events.json
    
    Output Format:
        JSON Lines format (1 event per baris):
        {"event_id": "EVT0000001", "event_time": "2026-05-27T...", ...}
        {"event_id": "EVT0000002", "event_time": "2026-05-27T...", ...}
        ...
    """
    # ========== ARGUMENT PARSING ==========
    p = argparse.ArgumentParser()
    p.add_argument('--events', type=int, default=1000, help='Number of events to generate')
    p.add_argument('--speed', type=float, default=0.0, help='Delay per event in seconds (0 = no delay)')
    p.add_argument('--out', default='event_stream.jsonl', help='Output file path')

    args = p.parse_args()

    # ========== EVENT GENERATION & OUTPUT ==========
    # Buka file output untuk writing JSON Lines
    with open(args.out, 'w', encoding='utf8') as f:
        # Iterate melalui event stream generator
        for e in event_stream(args.events):
            # Convert event dict ke JSON string
            line = json.dumps(e, ensure_ascii=False)
            
            # Output ke console (untuk monitoring progress)
            print(line)
            
            # Write ke file output
            f.write(line)
            f.write('\n')  # Newline untuk JSON Lines format
            
            # Optional: Sleep untuk rate limiting/real-time simulation
            # Berguna untuk testing streaming pipelines atau simulating real-time scenarios
            if args.speed > 0:
                time.sleep(args.speed)

if __name__ == '__main__':
    main()