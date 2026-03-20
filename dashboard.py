import os
from flask import Flask, render_template, jsonify
from datetime import datetime

live_state = {
    'devices'   : [],
    'down_mbps' : 0.0,
    'up_mbps'   : 0.0,
    'updated'   : None,
}

history_state = {}
MAX_HISTORY_POINTS = 120

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

# Tolerance for enforcement  match check
MATCH_TOLERANCE = 0.10


def _to_mbps(bytes_per_sec):
    return round((bytes_per_sec * 8) / 1_000_000, 2)


def update_history(devices, updated_at):
    """Track per-device time series for demand/allocated/enforced bandwidth."""
    if not devices:
        history_state.clear()
        return

    active_ips = set()
    time_label = updated_at.strftime('%H:%M:%S') if isinstance(updated_at, datetime) else str(updated_at)

    for device in devices:
        ip = device.get('ip', '')
        if not ip:
            continue

        active_ips.add(ip)
        series = history_state.setdefault(ip, {
            'time': [],
            'demand': [],
            'allocated': [],
            'enforced': [],
        })

        demand_bps = device.get('down_bytes_per_sec', 0) + device.get('up_bytes_per_sec', 0)
        allocated_bps = device.get('allocated_bytes_download', 0) + device.get('allocated_bytes_upload', 0)
        enforced_bps = device.get('enforced_down_bps', 0) + device.get('enforced_up_bps', 0)

        series['time'].append(time_label)
        series['demand'].append(_to_mbps(demand_bps))
        series['allocated'].append(_to_mbps(allocated_bps))
        series['enforced'].append(_to_mbps(enforced_bps))

        if len(series['time']) > MAX_HISTORY_POINTS:
            series['time'] = series['time'][-MAX_HISTORY_POINTS:]
            series['demand'] = series['demand'][-MAX_HISTORY_POINTS:]
            series['allocated'] = series['allocated'][-MAX_HISTORY_POINTS:]
            series['enforced'] = series['enforced'][-MAX_HISTORY_POINTS:]

    stale_ips = [ip for ip in history_state if ip not in active_ips]
    for ip in stale_ips:
        del history_state[ip]


def build_history():
    return {
        ip: {
            'time': list(series['time']),
            'demand': list(series['demand']),
            'allocated': list(series['allocated']),
            'enforced': list(series['enforced']),
        }
        for ip, series in history_state.items()
    }


def build_devices():
    """Convert raw live_state devices into dashboard-ready dicts."""
    devices = []

    for device in live_state['devices']:
        allocated_down_bps  = device.get('allocated_bytes_download', 0)
        allocated_up_bps    = device.get('allocated_bytes_upload', 0)
        demand_bps          = device.get('down_bytes_per_sec', 0) + device.get('up_bytes_per_sec', 0)

        # enforced values written by enforce.py
        enforced_down_bps = device.get('enforced_down_bps', 0)
        enforced_up_bps   = device.get('enforced_up_bps', 0)

        allocated_total = allocated_down_bps + allocated_up_bps
        enforced_total  = enforced_down_bps + enforced_up_bps

        # check if enforcement matches allocation within tolerance
        if allocated_total > 0:
            deviation   = abs(enforced_total - allocated_total) / allocated_total
            is_match    = deviation <= MATCH_TOLERANCE
        else:
            is_match = True  # if no allocation, nothing to match

        devices.append({
            'ip'                : device.get('ip', ''),
            'protocol'          : device.get('protocol', 'UNKNOWN'),
            'priority'          : device.get('priority', 1),
            'demand'            : round((demand_bps * 8) / 1_000_000, 2),  # convert to Mbps
            'allocated'         : round(allocated_total * 8) / 1_000_000,
            'down_allocated'    : round(allocated_down_bps * 8) / 1_000_000,
            'up_allocated'      : round(allocated_up_bps * 8) / 1_000_000,
            'enforced'          : round(enforced_total * 8) / 1_000_000,
            'enforced_down'     : round(enforced_down_bps * 8) / 1_000_000,
            'enforced_up'       : round(enforced_up_bps * 8) / 1_000_000,
            'is_match'          : is_match,
            'status'            : 'active' if demand_bps > 0 else 'idle',
        })

    return devices


def build_totals(devices):
    """Compute summary totals from processed device list."""
    updated = live_state['updated']
    return {
        'devices'       : len(devices),
        'demand'        : round(sum(d['demand'] for d in devices), 2),
        'allocated'     : round(sum(d['allocated'] for d in devices), 2),
        'enforced'      : round(sum(d['enforced'] for d in devices), 2),
        'down_pool'     : round(live_state['down_mbps'], 2),
        'up_pool'       : round(live_state['up_mbps'], 2),
        'time'          : updated.strftime('%Y-%m-%d %H:%M:%S') if updated else "-",
        'date'          : updated.strftime('%Y-%m-%d') if updated else "-",
    }


@app.route('/')
def dashboard():
    devices = build_devices()
    totals  = build_totals(devices)
    history = build_history()
    return render_template('dashboard.html', devices=devices, totals=totals, history=history)


@app.route('/api/data')
def api_data():
    devices = build_devices()
    totals  = build_totals(devices)
    history = build_history()
    return jsonify({
        'devices': devices,
        'totals' : totals,
        'history': history,
    })


@app.route('/api/status')
def api_status():
    updated = live_state['updated']
    return jsonify({
        'status'    : 'running',
        'devices'   : len(live_state['devices']),
        'timestamp' : updated.isoformat() if updated else None,
    })