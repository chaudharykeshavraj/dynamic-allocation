import time
import subprocess

INITIAL_MBPS = 10
MIN_MBPS = 2
MAX_MBPS = 20
TC_HEADROOM = 0.9
PROBE_SECS = 3

MIN_BPS = (MIN_MBPS * 1_000_000) / 8
MAX_BPS = (MAX_MBPS * 1_000_000) / 8

_current_down_bps = None
_current_up_bps = None
low_util_counter = 0
high_util_counter = 0
up_low_counter = 0
up_high_counter = 0


def _read_interface_bytes(interface):
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if interface in line:
                    parts = line.split()
                    return int(parts[1]), int(parts[9])
    except:
        pass
    return 0, 0


def measure_total_bandwidth(interface='wlp3s0'):
    global _current_down_bps, _current_up_bps

    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    # Measure both directions for 10 seconds
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(10)
    rx2, tx2 = _read_interface_bytes(interface)

    observed_down = (rx2 - rx1) / 10
    observed_up = (tx2 - tx1) / 10

    # Set pools based on actual observation - NO 0.4 ASSUMPTION
    _current_down_bps = max(observed_down * TC_HEADROOM, MIN_BPS)
    _current_up_bps = max(observed_up * TC_HEADROOM, MIN_BPS * 0.5)

    print(f"Initial capacity: Down={_current_down_bps*8/1e6:.2f} Mbps, Up={_current_up_bps*8/1e6:.2f} Mbps")
    return _current_down_bps, _current_up_bps


def probe_real_capacity(interface='wlp3s0'):
    global _current_down_bps, _current_up_bps

    print("  [PROBE] Measuring real capacity...")

    # Remove tc temporarily
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'ingress'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', 'ifb0', 'root'],
                   capture_output=True)

    time.sleep(0.5)

    # Measure BOTH directions
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(PROBE_SECS)
    rx2, tx2 = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / PROBE_SECS
    real_up = (tx2 - tx1) / PROBE_SECS

    print(f"  [PROBE] Observed: Down={real_down*8/1e6:.2f} Mbps, Up={real_up*8/1e6:.2f} Mbps")

    # Update if meaningful traffic
    MIN_TRAFFIC = 100 * 1024  # 100 KB/s
    if real_down > MIN_TRAFFIC:
        _current_down_bps = 0.7 * _current_down_bps + 0.3 * (real_down * TC_HEADROOM)
    if real_up > MIN_TRAFFIC:
        _current_up_bps = 0.7 * _current_up_bps + 0.3 * (real_up * TC_HEADROOM)

    # Clamp
    _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
    _current_up_bps = max(MIN_BPS * 0.3, min(MAX_BPS, _current_up_bps))

    print(f"  [PROBE] New: Down={_current_down_bps*8/1e6:.2f} Mbps, Up={_current_up_bps*8/1e6:.2f} Mbps")
    return _current_down_bps, _current_up_bps


def update_bandwidth_estimate(interface='wlp3s0'):
    global _current_down_bps, _current_up_bps, low_util_counter, high_util_counter
    global up_low_counter, up_high_counter

    if _current_down_bps is None:
        return measure_total_bandwidth(interface)

    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, tx2 = _read_interface_bytes(interface)

    observed_down = rx2 - rx1
    observed_up = tx2 - tx1

    down_util = observed_down / (_current_down_bps + 1e-9)
    up_util = observed_up / (_current_up_bps + 1e-9)

    print(f"  Util: Down={down_util:.2%}, Up={up_util:.2%}")

    # Update download
    if down_util > 0.85:
        high_util_counter += 1
        if high_util_counter >= 3:
            _current_down_bps = min(MAX_BPS, _current_down_bps * 1.15)
            high_util_counter = 0
    elif down_util < 0.3:
        low_util_counter += 1
        if low_util_counter >= 5:
            _current_down_bps = max(MIN_BPS, _current_down_bps * 0.95)
            low_util_counter = 0
    else:
        low_util_counter = 0
        high_util_counter = 0

    # Update upload (separate logic)
    if up_util > 0.85:
        up_high_counter += 1
        if up_high_counter >= 3:
            _current_up_bps = min(MAX_BPS, _current_up_bps * 1.15)
            up_high_counter = 0
    elif up_util < 0.3:
        up_low_counter += 1
        if up_low_counter >= 5:
            _current_up_bps = max(MIN_BPS * 0.3, _current_up_bps * 0.95)
            up_low_counter = 0
    else:
        up_low_counter = 0
        up_high_counter = 0

    _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
    _current_up_bps = max(MIN_BPS * 0.3, min(MAX_BPS, _current_up_bps))

    return _current_down_bps, _current_up_bps