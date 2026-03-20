import time
import subprocess

INITIAL_MBPS = 10
MIN_MBPS     = 2
MAX_MBPS     = 20
TC_HEADROOM  = 0.9
PROBE_SECS   = 3

MIN_BPS = (MIN_MBPS * 1_000_000) / 8
MAX_BPS = (MAX_MBPS * 1_000_000) / 8

_current_down_bps = None
_current_up_bps   = None
low_util_counter = 0
high_util_counter = 0


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

    base = (INITIAL_MBPS * 1_000_000) / 8
    _current_down_bps = base * TC_HEADROOM
    _current_up_bps   = _current_down_bps * 0.4

    print(f"Initial capacity: {INITIAL_MBPS} Mbps")
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

    # Measure
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(PROBE_SECS)
    rx2, tx2 = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / PROBE_SECS
    real_up = (tx2 - tx1) / PROBE_SECS
    real_mbps = (real_down * 8) / 1_000_000

    print(f"  [PROBE] Observed: {real_mbps:.2f} Mbps")

    # Update estimate if meaningful traffic detected
    if real_down > 100 * 1024:  # 100 KB/s
        target_down = real_down * TC_HEADROOM
        _current_down_bps = 0.7 * _current_down_bps + 0.3 * target_down
        _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
        _current_up_bps = real_up * TC_HEADROOM
        _current_up_bps = max(MIN_BPS * 0.3, min(MAX_BPS * 0.5, _current_up_bps))
        print(f"  [PROBE] New estimate: {(_current_down_bps*8)/1e6:.2f} Mbps")
    else:
        print(f"  [PROBE] Low traffic, keeping: {(_current_down_bps*8)/1e6:.2f} Mbps")

    # tc rules are deleted - enforce() will detect and recreate them
    return _current_down_bps, _current_up_bps


def update_bandwidth_estimate(interface='wlp3s0'):
    global _current_down_bps, _current_up_bps, low_util_counter, high_util_counter

    if _current_down_bps is None:
        return measure_total_bandwidth(interface)

    rx1, _ = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, _ = _read_interface_bytes(interface)

    observed_down = rx2 - rx1
    utilization = observed_down / (_current_down_bps + 1e-9)

    print(f"  Utilization: {utilization:.2%} (observed: {(observed_down*8)/1e6:.2f} Mbps, limit: {(_current_down_bps*8)/1e6:.2f} Mbps)")

    if utilization > 0.85:
        high_util_counter += 1
        low_util_counter = 0
        if high_util_counter >= 3:
            increase = _current_down_bps * 0.15
            _current_down_bps = min(MAX_BPS, _current_down_bps + increase)
            high_util_counter = 0
            print(f"  [UP] Increased to {(_current_down_bps*8)/1e6:.2f} Mbps")

    elif 0.3 <= utilization <= 0.85:
        low_util_counter = 0
        high_util_counter = 0

    else:
        low_util_counter += 1
        high_util_counter = 0
        if low_util_counter >= 5:
            _current_down_bps *= 0.95
            low_util_counter = 0
            print(f"  [DOWN] Decreased to {(_current_down_bps*8)/1e6:.2f} Mbps")

    _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
    _current_up_bps = _current_down_bps * 0.4

    return _current_down_bps, _current_up_bps