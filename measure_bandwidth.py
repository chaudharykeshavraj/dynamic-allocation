import time
import subprocess

# -------------------------------
# CONFIG (TUNED FOR YOUR LAPTOP)
# -------------------------------
INITIAL_MBPS = 10        # your observed starting point
MIN_MBPS     = 2         # never go below this
TC_HEADROOM  = 0.9
INTERFACE    = "wlp3s0"

_current_down_bps = None
_current_up_bps   = None


# -------------------------------
# READ INTERFACE BYTES
# -------------------------------
def _read_interface_bytes(interface):
    with open('/proc/net/dev') as f:
        for line in f:
            if interface in line:
                parts = line.split()
                return int(parts[1]), int(parts[9])
    return 0, 0


# -------------------------------
# INITIAL CAPACITY (FIXED BASE)
# -------------------------------
def measure_total_bandwidth(interface=INTERFACE):
    global _current_down_bps, _current_up_bps

    print("\n--- Initial Capacity Setup ---")

    # remove tc just in case
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    # use REALISTIC fixed start
    base_bps = (INITIAL_MBPS * 1_000_000) / 8

    _current_down_bps = base_bps * TC_HEADROOM
    _current_up_bps   = _current_down_bps * 0.4

    print(f"  Start Download = {INITIAL_MBPS} Mbps")
    print(f"  Start Upload   ≈ {INITIAL_MBPS*0.4:.2f} Mbps")

    return _current_down_bps, _current_up_bps


# -------------------------------
# SAFE PROBE (NO COLLAPSE)
# -------------------------------
def probe_real_capacity(interface):
    global _current_down_bps, _current_up_bps

    print("\n[PROBE] Checking real capacity...")

    # remove tc
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    time.sleep(1)

    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(3)
    rx2, tx2 = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / 3
    real_mbps = (real_down * 8) / 1_000_000

    print(f"  Observed = {real_mbps:.2f} Mbps")

    # ignore very low values (idle case)
    if real_mbps < 1:
        print("  Ignored (too low, likely idle)")
        return _current_down_bps, _current_up_bps

    # smooth update (NO sharp drop)
    new_down = 0.7 * _current_down_bps + 0.3 * (real_down * TC_HEADROOM)

    # enforce minimum floor
    min_bps = (MIN_MBPS * 1_000_000) / 8
    new_down = max(new_down, min_bps)

    _current_down_bps = new_down
    _current_up_bps   = new_down * 0.4

    print(f"  Updated → {(new_down*8)/1_000_000:.2f} Mbps")

    return _current_down_bps, _current_up_bps


# -------------------------------
# CONTINUOUS UPDATE
# -------------------------------
def update_bandwidth_estimate(interface=INTERFACE):
    global _current_down_bps, _current_up_bps

    if _current_down_bps is None:
        return measure_total_bandwidth(interface)

    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, tx2 = _read_interface_bytes(interface)

    observed_down = rx2 - rx1

    # upward adjustment only if clearly higher
    if observed_down > _current_down_bps * 1.1:
        _current_down_bps = (
            0.8 * _current_down_bps +
            0.2 * observed_down * TC_HEADROOM
        )
        print(f"[UPDATE] Increased → {(_current_down_bps*8)/1_000_000:.2f} Mbps")

    # slow decay (prevents overestimation)
    _current_down_bps *= 0.995

    # enforce minimum floor
    min_bps = (MIN_MBPS * 1_000_000) / 8
    if _current_down_bps < min_bps:
        _current_down_bps = min_bps

    _current_up_bps = _current_down_bps * 0.4

    return _current_down_bps, _current_up_bps