"""Streamlit dashboard for realtime security alert monitoring.

This module generates a synthetic security event stream, evaluates each event
with the shared alert rules in `security_alert.py`, and visualizes both event
labels and alert severity in an interactive Streamlit dashboard.

The dashboard is designed for collaboration: it explains how simulated events
are processed, which rules are applied, and how alerts are surfaced to users.
"""

import time
from collections import deque, defaultdict
from datetime import datetime

import pandas as pd
import altair as alt
import streamlit as st

from security_alert import generate_security_alert
from stream_generator import event_stream


def process_stream(total, speed, seed, progress_placeholder, status_placeholder, alert_preview_placeholder,
                   latest_alert_limit=20, ui_update_interval=0.1):
    """Simulate a stream of events and classify alerts in realtime.

    This function separates data processing from UI rendering. To avoid
    excessive DOM updates and UI repainting, it collects alerts in a fixed
    size `deque` and only updates the Streamlit placeholder at most once per
    `ui_update_interval` seconds (i.e. throttling UI updates). This allows the
    backend to process events at full speed while the frontend refreshes at a
    bounded rate (for production use keep this <= 10 Hz).

    Args:
        total (int): Total number of synthetic events to generate.
        speed (float): Delay in seconds between events to simulate realtime.
        seed (int): Random seed for reproducible user profiles.
        progress_placeholder: Streamlit placeholder for progress bar.
        status_placeholder: Streamlit placeholder for status text.
        alert_preview_placeholder: Streamlit placeholder for alert preview table.
        latest_alert_limit (int): How many most-recent alerts to keep/show.
        ui_update_interval (float): Minimum seconds between UI updates (throttle).

    Returns:
        tuple[pd.DataFrame, pd.DataFrame]: DataFrames for all events and generated alerts.

    The function keeps a rolling failed-login counter per user, evaluates every
    event using `generate_security_alert`, and appends non-normal events to a
    bounded alert deque for display. UI updates are throttled to avoid
    repainting faster than `1 / ui_update_interval` Hz.
    """
    failed_logins = defaultdict(deque)
    events = []
    # Use a bounded deque to prevent the DOM from growing unboundedly. The
    # deque holds the N most recent alerts; the placeholder will render this
    # deque as a small DataFrame. This prevents continuous `st.write` calls
    # that append new DOM nodes and cause layout growth.
    alerts = deque(maxlen=latest_alert_limit)

    progress_bar = progress_placeholder.progress(0)
    status = status_placeholder.text('Preparing stream...')

    last_ui_update = time.time() - ui_update_interval
    for index, event in enumerate(event_stream(total, seed=42), start=1):
        event_time = datetime.fromisoformat(event['event_time'])
        user_id = event['user_id']

        dq = failed_logins[user_id]
        while dq and (event_time - dq[0]).total_seconds() > 3600:
            dq.popleft()

        if event['action'] == 'login' and event['status'] == 'failed':
            dq.append(event_time)

        rolling_failed_1h = len(dq)

        row = {
            'event_id': event['event_id'],
            'event_time': event['event_time'],
            'user_id': user_id,
            'dept': event.get('dept'),
            'role': event.get('role'),
            'clearance': event.get('clearance'),
            'employee_status': event.get('employee_status'),
            'action': event['action'],
            'status': event['status'],
            'data_classification': event.get('data_classification'),
            'bytes_out': event.get('bytes_out', 0),
            'risk_score': event.get('risk_score'),
            'label': event.get('label'),
            'asset_id': event.get('asset_id'),
            'severity': None,
            'rolling_failed_logins_1h': rolling_failed_1h,
        }

        row['severity'] = generate_security_alert(row)
        events.append(row)

        if row['severity'] != 'Normal':
            alerts.append({
                'alert_time': datetime.now().isoformat(),
                'event_id': row['event_id'],
                'user_id': user_id,
                'asset_id': row['asset_id'],
                'action': row['action'],
                'severity': row['severity'],
                'label': row['label'],
                'bytes_out': row['bytes_out'],
                'risk_score': row['risk_score'],
                'rolling_failed_logins_1h': rolling_failed_1h,
            })

        if total:
            progress_bar.progress(index / total)
            status.text(f'Processing event {index}/{total}...')

        # Throttle UI updates to at most once per `ui_update_interval`.
        now = time.time()
        if now - last_ui_update >= ui_update_interval:
            try:
                # Convert the bounded deque to a DataFrame for rendering.
                alert_preview_placeholder.dataframe(pd.DataFrame(list(alerts)))
            except Exception:
                # Rendering should not crash the processor loop; ignore UI errors
                # and continue processing events.
                pass
            last_ui_update = now

        if speed > 0:
            time.sleep(speed)

    status.text('Stream simulation complete.')
    # Final render: ensure UI shows the most recent alerts at the end.
    try:
        alert_preview_placeholder.dataframe(pd.DataFrame(list(alerts)))
    except Exception:
        pass

    # Convert deque to a list for the return value to preserve shape.
    return pd.DataFrame(events), pd.DataFrame(list(alerts))


def main():
    """Render the Streamlit dashboard and allow users to run the simulation.

    The sidebar exposes simulation controls. When the user clicks the button,
    `process_stream` is invoked and the dashboard renders summaries, alert
    details, and visualizations.
    """
    st.set_page_config(page_title='Security Alert Dashboard', layout='wide')
    st.title('🔔 Security Alert Stream Monitoring')
    st.markdown(
        'Monitor generated security events and realtime alert severity using the synthetic stream.'
    )

    with st.sidebar:
        st.header('Simulation Settings')
        total_events = st.number_input('Total events', min_value=10, max_value=20000, value=500, step=10)
        speed = st.slider('Event delay (seconds)', min_value=0.0, max_value=1.0, value=0.05, step=0.05)
        # seed = st.number_input('User seed', min_value=1, max_value=9999, value=42, step=1)
        st.markdown('---')
        st.subheader('UI Throttling & Preview')
        latest_alerts = st.number_input('Latest alerts to show (N)', min_value=1, max_value=500, value=20, step=1,
                                       help='Number of most-recent alerts to keep in the preview table (bounded deque).')
        ui_refresh_hz = st.number_input('UI refresh rate (Hz)', min_value=1, max_value=60, value=10, step=1,
                                       help='Maximum UI updates per second. Internally converted to a throttling interval.')
        ui_update_interval = 1.0 / max(1, ui_refresh_hz)
        st.markdown('---')
        st.write('Click **Run simulation** to generate a stream and display alerts.')

    run_simulation = st.button('Run simulation')

    if run_simulation:
        progress_placeholder = st.empty()
        status_placeholder = st.empty()
        alert_preview_placeholder = st.empty()

        with st.spinner('Running stream processor...'):
            events_df, alerts_df = process_stream(
                total=total_events,
                speed=speed,
                seed=42,
                progress_placeholder=progress_placeholder,
                status_placeholder=status_placeholder,
                alert_preview_placeholder=alert_preview_placeholder,
                latest_alert_limit=latest_alerts,
                ui_update_interval=ui_update_interval,
            )

        st.success('Simulation finished successfully.')

        alert_counts = alerts_df['severity'].value_counts().to_dict() if not alerts_df.empty else {}
        label_counts = events_df['label'].value_counts().to_dict() if not events_df.empty else {}

        col1, col2, col3, col4 = st.columns(4)
        col1.metric('Total events', len(events_df))
        col2.metric('Alerts generated', len(alerts_df))
        col3.metric('Critical alerts', alert_counts.get('CRITICAL', 0))
        col4.metric('High alerts', alert_counts.get('HIGH', 0))

        col5, col6, col7 = st.columns(3)
        col5.metric('Medium alerts', alert_counts.get('MEDIUM', 0))
        col6.metric('Normal events', len(events_df) - len(alerts_df))
        col7.metric('Unique users', events_df['user_id'].nunique())

        st.markdown('### Alert summary')
        if not alerts_df.empty:
            st.dataframe(alerts_df.sort_values(by='severity', ascending=False).head(200))
        else:
            st.info('No alert rules triggered for this simulation.')

        st.markdown('### Event label distribution')
        if label_counts:
            label_df = pd.DataFrame(
                list(label_counts.items()), columns=['label', 'count']
            )
            # Use joinaggregate to compute the total across the whole dataset
            # before calculating per-row percentages. Using transform_window
            # here can accidentally compute per-row totals (partitioned windows)
            # which makes each slice compute percentage = count / count = 1.0.
            pie_chart = (
                alt.Chart(label_df)
                .transform_joinaggregate(
                    total='sum(count)'
                )
                .transform_calculate(
                    percentage='datum.count / datum.total'
                )
                .mark_arc(innerRadius=50)
                .encode(
                    theta=alt.Theta(field='count', type='quantitative'),
                    color=alt.Color(field='label', type='nominal', legend=alt.Legend(title='Label')),
                    tooltip=[
                        'label',
                        alt.Tooltip('count:Q', title='Count'),
                        alt.Tooltip('percentage:Q', title='Share', format='.1%'),
                    ],
                )
            )
            # pie_labels = pie_chart.mark_text(radius=110, size=12).encode(
            #     text=alt.Text('percentage:Q', format='.1%')
            # )
            st.altair_chart(pie_chart, use_container_width=True)
        else:
            st.info('No event labels available yet.')

        st.markdown('### Latest event sample')
        st.dataframe(events_df.sort_values(by='event_time', ascending=False).head(100))

        st.markdown('### Alert severity distribution')
        if not alerts_df.empty:
            st.bar_chart(alerts_df['severity'].value_counts())


if __name__ == '__main__':
    main()
