import argparse
import json
from collections import deque, defaultdict
from datetime import datetime, timedelta

from stream_generator import event_stream
from security_alert import generate_security_alert


def main():
    p = argparse.ArgumentParser(description='Stream processor that prints security alerts in realtime')
    p.add_argument('--events', type=int, default=1000, help='Number of events to process')
    p.add_argument('--speed', type=float, default=0.0, help='Delay per event in seconds (0 = no delay)')
    args = p.parse_args()

    # Track failed login timestamps per user (for rolling 1h window)
    failed_logins = defaultdict(deque)

    for e in event_stream(args.events):
        # Parse event time
        et = datetime.fromisoformat(e['event_time'])
        uid = e['user_id']

        # Maintain deque of failed login timestamps (only for login failures)
        dq = failed_logins[uid]
        # Remove entries older than 1 hour
        while dq and (et - dq[0]).total_seconds() > 3600:
            dq.popleft()

        if e.get('action') == 'login' and e.get('status') == 'failed':
            dq.append(et)

        rolling_failed_1h = len(dq)

        # Build row expected by generate_security_alert
        row = {
            'event_id': e.get('event_id'),
            'event_time': e.get('event_time'),
            'user_id': uid,
            'employee_status': e.get('employee_status'),
            'clearance': e.get('clearance'),
            'action': e.get('action'),
            'status': e.get('status'),
            'data_classification': e.get('data_classification'),
            'bytes_out': e.get('bytes_out', 0),
            'rolling_failed_logins_1h': rolling_failed_1h,
        }

        severity = generate_security_alert(row)

        # Print alerts for anything not 'Normal'
        if severity != 'Normal':
            alert = {
                'alert_time': datetime.now().isoformat(),
                'severity': severity,
                'event_id': e.get('event_id'),
                'user_id': uid,
                'action': e.get('action'),
                'asset_id': e.get('asset_id'),
                'bytes_out': e.get('bytes_out'),
                'risk_score': e.get('risk_score'),
                'label': e.get('label'),
            }
            print(json.dumps(alert, ensure_ascii=False))

        # Optional small delay to simulate realtime
        if args.speed and args.speed > 0:
            import time

            time.sleep(args.speed)


if __name__ == '__main__':
    main()
