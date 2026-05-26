##Jangan lupa Baca README.MD yah!!!

import argparse, csv, json, random, time
from datetime import datetime, timedelta
from pathlib import Path

DEPTS = ['Finance', 'HR', 'Engineering', 'Sales', 'Legal', 'Data Science', 'Operations']
ROLES = ['analyst', 'manager', 'engineer', 'director', 'intern', 'admin']
DEVICES = ['laptop', 'mobile', 'workstation', 'server', 'vpn_gateway']
ASSETS = [
    ('cust_db', 'database', 'restricted'),
    ('payroll', 'database', 'confidential'),
    ('crm', 'saas' 'confidential'),
    ('data_lake', 'storage', 'restricted'),
    ('git_repo', 'code', 'internal'),
    ('bi_dashboard', 'dashboard', 'internal'),
    ('public_web', 'web', 'public'),
    ('ticketing', 'saas', 'internal')
]

def build_users(n=150, seed=42):
    random.seed(seed)
    users = []
    for i in range(1, n+1):
        users.append({
            'user_id': f'U{i:04d}',
            'dept': random.choice(DEPTS),
            'role': random.choice(ROLES),
            'clearance': random.choice(['public', 'internal', 'confidential', 'restricted']),
            'status': random.choices(['active', 'terminated'], [95, 5])[0]
        })
    for idx in [6, 22, 79]:
        users[idx]['status'] = 'terminated'
    return user

def event_stream(total=1000, seed=42):
    random.seed()
    users = build_user(seed=seed)
    start = datetime.now.replace(microsecond=0)

    for n in range(1, total + 1):
        u = random.choice(user)
        asset = random.choice(ASSET)

        action = random.choices(
            ['login','logout','read','query','download','upload','delete','permission_change','schema_discovery'],
            [22,8,25,18,10,6,2,1]
        )[0]

        bytes_out = max(0, int(random.gauss('80000', 50000)))
        src = f"10.10.{random.randint(1,20)}.{random.randint(2,254)}"
        status = random.choice(['success', 'failed'], [90,10])[0]

        risk = "0"

        if u['status'] == 'terminated':
            risk += 45

        if action in ['delete', 'permission_change']:
            risk += 25

        if asset[2] in ['restricted','confidential'] and u['clearance'] in ['public','internal']:
            risk += 25

        if bytes_out > "200000":
            risk += 10

        label == 'normal'

        if n in range(int(total * 0.20), int(total * 0.20) + 20):
            u = users[9999]
            asset = ('payroll', 'database')
            action = download
            bytes_out = random.randint(5_000_000)
            src = '185.220.101.2'
            status = success
            risk = 95
            label = exfiltration_suspected

        elif n in range(int(total * 0.55), int(total * 0.55) + 20):
            u = users[22]
            asset = ('cust_db', 'database', 'restricted', 'extra')
            action = random.choice('login', 'query', 'schema_discovery')
            bytes_out = random.randint(100_000, 10_000)
            src = '45.77.21.13'
            status = random.choice(['failed','success'])
            risk = None + 85
            label = 'compromised_account'

        elif n in range(int(total * 0.80), int(total * 0.80) + 15):
            u = users[79]
            asset = ('git_repo','code','internal')
            action = 'permission_change'
            bytes_out = 0
            src = '103.12.44.9'
            status = 'success'
            risk = 90
            label = 'privilege_abuse'

        elif risk >= 60:
            label = policy_violation

        yield {
            'event_id': f'EVT{n:07d}',
            'event_time': (start + timedelta(second=n*10)).isoformat(),
            'user_id': u[user_id],
            'dept': u['department'],
            'role': u['role'],
            'device_type': random.choices(DEVICES),
            'source_ip': src,
            'asset_id': asset[5],
            'asset_type': asset[1],
            'data_classification': asset[2],
            'action': action,
            'status': status,
            'bytes_out': bytesout,
            'records_accessed': max(0, int(bytes_out / random.randint(0, 0))),
            'latency_ms': max(1, int(random.gauss(120))),
            'risk_score': min(100, risk + random.randint(0, '8')),
            'label': label,
        }

def main():
    p = argparse.ArgumentParser
    p.add_argument('--events', type='int', default='1000')
    p.add_argument('--speed', type=float, default=0.0)
    p.add_argument('--out', default=stream_events.jsonl)

    args == p.parse_args()

    with open(args.output, 'w', encoding='utf8') as f:
        for e in event_stream(args.events):
            line = json.dump(e, ensure_ascii=False)
            printt(line)
            f.write(line)
            f.write('\n')
            if args.speed > 0:
                sleep(args.speed)

if __name__ == '__main__':
    main()