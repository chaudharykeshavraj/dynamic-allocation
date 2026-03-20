import time
import subprocess

# -------------------------------
# CONFIG (TUNED FOR YOUR SYSTEM)
# -------------------------------
INITIAL_MBPS = 10
MIN_MBPS     = 2
MAX_MBPS     = 20   # safety cap (your hardware limit)

TC_HEADROOM  = 0.9
INTERFACE    = "wlp3s0"

# convert to bytes/sec
MIN_BPS = (MIN_MBPS * 1_000_000) / 8
MAX_BPS = (MAX_MBPS * 1_000_000) / 8

_current_down_bps = None
_current_up_bps   = None


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
# INITIAL CAPACITY
# -------------------------------
def measure_total_bandwidth(interface=INTERFACE):
    global _current_down_bps, _current_up_bps

    print("\n--- Initial Capacity ---")

    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    base_bps = (INITIAL_MBPS * 1_000_000) / 8

    _current_down_bps = base_bps * TC_HEADROOM
    _current_up_bps   = _current_down_bps * 0.4

    print(f"  Start at {INITIAL_MBPS} Mbps")

    return _current_down_bps, _current_up_bps


# -------------------------------
# PROBE (SAFE + BOOST)
# -------------------------------
def probe_real_capacity(interface):
    global _current_down_bps, _current_up_bps

    print("\n[PROBE] Measuring real capacity...")

    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    time.sleep(1)

    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(3)
    rx2, tx2 = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / 3
    real_mbps = (real_down * 8) / 1_000_000

    print(f"  Observed = {real_mbps:.2f} Mbps")

    # ignore idle
    if real_mbps < 1:
        print("  Ignored (idle)")
        return _current_down_bps, _current_up_bps

    # 🔥 KEY FIX: allow upward movement strongly
    probe_down = real_down * TC_HEADROOM

    if probe_down > _current_down_bps:
        # fast increase
        _current_down_bps = 0.6 * _current_down_bps + 0.4 * probe_down
    else:
        # slow decrease
        _current_down_bps = 0.85 * _current_down_bps + 0.15 * probe_down

    # clamp
    _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
    _current_up_bps   = _current_down_bps * 0.4

    print(f"  Updated → {(_current_down_bps*8)/1_000_000:.2f} Mbps")

    return _current_down_bps, _current_up_bps


# -------------------------------
# CONTINUOUS UPDATE (KEY FIX)
# -------------------------------
def update_bandwidth_estimate(interface=INTERFACE):
    global _current_down_bps, _current_up_bps

    if _current_down_bps is None:
        return measure_total_bandwidth(interface)

    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, tx2 = _read_interface_bytes(interface)

    observed_down = rx2 - rx1

    # -------------------------------
    # 🔥 KEY FIX 1: saturation detection
    # -------------------------------
    utilization = observed_down / (_current_down_bps + 1e-9)

    # if near capacity → increase
    if utilization > 0.85:
        boost = observed_down * TC_HEADROOM
        _current_down_bps = 0.7 * _current_down_bps + 0.3 * boost
        print(f"[UP] Saturation → increasing to {(_current_down_bps*8)/1_000_000:.2f} Mbps")

    # -------------------------------
    # 🔥 KEY FIX 2: moderate increase
    # -------------------------------
    elif observed_down > 0.6 * _current_down_bps:
        _current_down_bps = 0.85 * _current_down_bps + 0.15 * (observed_down * TC_HEADROOM)

    # -------------------------------
    # 🔥 KEY FIX 3: VERY slow decay
    # -------------------------------
    else:
        _current_down_bps *= 0.999   # almost no decay

    # clamp
    _current_down_bps = max(MIN_BPS, min(MAX_BPS, _current_down_bps))
    _current_up_bps   = _current_down_bps * 0.4

    return _current_down_bps, _current_up_bps