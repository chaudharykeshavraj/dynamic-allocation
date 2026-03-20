import time
import subprocess

# -------------------------------
# CONFIG
# -------------------------------
INITIAL_MBPS = 10
MIN_MBPS     = 2
MAX_MBPS     = 20

TC_HEADROOM  = 0.9
INTERFACE    = "wlp3s0"

MIN_BPS = (MIN_MBPS * 1_000_000) / 8
MAX_BPS = (MAX_MBPS * 1_000_000) / 8

_current_down_bps = None
_current_up_bps   = None

# 🔥 NEW: stability tracking
low_util_counter = 0


# -------------------------------
# READ INTERFACE
# -------------------------------
def _read_interface_bytes(interface):
    with open('/proc/net/dev') as f:
        for line in f:
            if interface in line:
                parts = line.split()
                return int(parts[1]), int(parts[9])
    return 0, 0


# -------------------------------
# INITIAL
# -------------------------------
def measure_total_bandwidth(interface=INTERFACE):
    global _current_down_bps, _current_up_bps

    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    base = (INITIAL_MBPS * 1_000_000) / 8

    _current_down_bps = base * TC_HEADROOM
    _current_up_bps   = _current_down_bps * 0.4

    print(f"Start capacity: {INITIAL_MBPS} Mbps")

    return _current_down_bps, _current_up_bps


# -------------------------------
# PROBE (SAFE)
# -------------------------------
def probe_real_capacity(interface):
    global _current_down_bps, _current_up_bps

    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    time.sleep(1)

    rx1, _ = _read_interface_bytes(interface)
    time.sleep(3)
    rx2, _ = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / 3
    real_mbps = (real_down * 8) / 1_000_000

    print(f"[PROBE] {real_mbps:.2f} Mbps")

    if real_mbps < 1:
        print("Probe ignored (idle)")
        return _current_down_bps, _current_up_bps

    probe_down = real_down * TC_HEADROOM

    # 🔥 asymmetric update
    if probe_down > _current_down_bps:
        _current_down_bps = 0.6 * _current_down_bps + 0.4 * probe_down
    else:
        _current_down_bps = 0.9 * _current_down_bps + 0.1 * probe_down

    _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
    _current_up_bps   = _current_down_bps * 0.4

    return _current_down_bps, _current_up_bps


# -------------------------------
# UPDATE (FINAL FIX)
# -------------------------------
def update_bandwidth_estimate(interface=INTERFACE):
    global _current_down_bps, _current_up_bps, low_util_counter

    if _current_down_bps is None:
        return measure_total_bandwidth(interface)

    rx1, _ = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, _ = _read_interface_bytes(interface)

    observed_down = rx2 - rx1
    utilization = observed_down / (_current_down_bps + 1e-9)

    # -------------------------------
    # 🔼 INCREASE (fast)
    # -------------------------------
    if utilization > 0.85:
        boost = observed_down * TC_HEADROOM
        _current_down_bps = 0.7 * _current_down_bps + 0.3 * boost
        low_util_counter = 0
        print(f"[UP] {(_current_down_bps*8)/1e6:.2f} Mbps")

    # -------------------------------
    # ⏸ STABLE REGION
    # -------------------------------
    elif 0.3 < utilization <= 0.85:
        low_util_counter = 0
        # DO NOTHING → no decay

    # -------------------------------
    # 🔽 POSSIBLE DECREASE
    # -------------------------------
    else:
        low_util_counter += 1

        # only decrease after sustained low usage
        if low_util_counter >= 5:
            _current_down_bps *= 0.95
            low_util_counter = 0
            print(f"[DOWN] {(_current_down_bps*8)/1e6:.2f} Mbps")

    # clamp
    _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
    _current_up_bps   = _current_down_bps * 0.4

    return _current_down_bps, _current_up_bps