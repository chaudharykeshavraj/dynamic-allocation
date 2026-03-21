import time
import subprocess

MIN_MBPS    = 2
MAX_MBPS    = 15    # reduced from 20 — realistic WiFi hotspot ceiling
TC_HEADROOM = 0.9
PROBE_SECS  = 3

MIN_BPS = (MIN_MBPS * 1_000_000) / 8
MAX_BPS = (MAX_MBPS * 1_000_000) / 8

_current_down_bps = None
_current_up_bps   = None
low_util_counter  = 0
high_util_counter = 0
up_low_counter    = 0
up_high_counter   = 0

def _read_interface_bytes(interface):
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if interface in line:
                    parts = line.split()
                    return int(parts[1]), int(parts[9])
    except Exception:
        pass
    return 0, 0

def measure_total_bandwidth(interface='wlp3s0'):
    global _current_down_bps, _current_up_bps

    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)

    print(f"  Observing {interface} for 10 seconds (no tc limits)...")
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(10)
    rx2, tx2 = _read_interface_bytes(interface)

    observed_down = (rx2 - rx1) / 10
    observed_up   = (tx2 - tx1) / 10

    _current_down_bps = max(observed_down * TC_HEADROOM, MIN_BPS)

    # FIX: upload pool = 50% of download pool MAX
    # ifb0 mirrors all traffic so raw observed_up may be inflated
    # cap upload at half of download to prevent 11 Mbps inflation
    _current_up_bps = max(
        min(observed_up * TC_HEADROOM, _current_down_bps * 0.5),
        MIN_BPS * 0.3
    )

    # clamp both to MAX
    _current_down_bps = min(_current_down_bps, MAX_BPS)
    _current_up_bps   = min(_current_up_bps,   MAX_BPS * 0.5)

    print(f"  Pool set: down={_current_down_bps*8/1e6:.2f} Mbps  up={_current_up_bps*8/1e6:.2f} Mbps")
    return _current_down_bps, _current_up_bps

def probe_real_capacity(interface='wlp3s0'):
    """
    BUG FIX: Now restores tc rules after probe!
    Previous version deleted tc and never restored → devices ran unlimited.
    """
    global _current_down_bps, _current_up_bps

    print("  [PROBE] Removing tc for 3 seconds...")

    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'ingress'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', 'ifb0', 'root'],
                   capture_output=True)

    time.sleep(0.5)

    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(PROBE_SECS)
    rx2, tx2 = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / PROBE_SECS
    real_up   = (tx2 - tx1) / PROBE_SECS

    print(f"  [PROBE] Observed: down={real_down*8/1e6:.2f} Mbps  up={real_up*8/1e6:.2f} Mbps")

    MIN_TRAFFIC = 50 * 1024   # 50 KB/s

    if real_down > MIN_TRAFFIC:
        new_down          = real_down * TC_HEADROOM
        _current_down_bps = 0.7 * _current_down_bps + 0.3 * new_down

    # FIX: cap upload at 50% of download — prevents inflation
    if real_up > MIN_TRAFFIC:
        new_up          = min(real_up * TC_HEADROOM, _current_down_bps * 0.5)
        _current_up_bps = 0.7 * _current_up_bps + 0.3 * new_up

    _current_down_bps = max(MIN_BPS,       min(MAX_BPS,       _current_down_bps))
    _current_up_bps   = max(MIN_BPS * 0.3, min(MAX_BPS * 0.5, _current_up_bps))

    print(f"  [PROBE] New pool: down={_current_down_bps*8/1e6:.2f} Mbps  up={_current_up_bps*8/1e6:.2f} Mbps")

    # FIX: restore tc rules after probe
    try:
        from enforce import setup_tc, reapply_all_devices
        setup_tc(interface, _current_down_bps, _current_up_bps)
        reapply_all_devices()
        print("  [PROBE] tc rules restored")
    except Exception as e:
        print(f"  [PROBE] tc restore error: {e}")

    return _current_down_bps, _current_up_bps

def update_bandwidth_estimate(interface='wlp3s0'):
    """
    FIX: measures actual elapsed time not fixed 1 second.
    FIX: upload never exceeds 50% of download pool.
    """
    global _current_down_bps, _current_up_bps
    global low_util_counter, high_util_counter
    global up_low_counter, up_high_counter

    if _current_down_bps is None:
        return measure_total_bandwidth(interface)

    # FIX: measure actual elapsed time
    t1       = time.time()
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, tx2 = _read_interface_bytes(interface)
    t2       = time.time()

    elapsed = max(t2 - t1, 0.01)

    observed_down = (rx2 - rx1) / elapsed
    observed_up   = (tx2 - tx1) / elapsed

    down_util = observed_down / (_current_down_bps + 1e-9)
    up_util   = observed_up   / (_current_up_bps   + 1e-9)

    print(f"  Util: down={down_util:.1%}  up={up_util:.1%}  elapsed={elapsed:.3f}s")

    # download
    if down_util > 0.85:
        high_util_counter += 1
        low_util_counter   = 0
        if high_util_counter >= 3:
            _current_down_bps = min(MAX_BPS, _current_down_bps * 1.15)
            high_util_counter = 0
    elif down_util < 0.3:
        low_util_counter  += 1
        high_util_counter  = 0
        if low_util_counter >= 5:
            _current_down_bps = max(MIN_BPS, _current_down_bps * 0.95)
            low_util_counter  = 0
    else:
        low_util_counter = high_util_counter = 0

    # upload — FIX: hard cap at 50% of current download pool
    MAX_UP = _current_down_bps * 0.5

    if up_util > 0.85:
        up_high_counter += 1
        up_low_counter   = 0
        if up_high_counter >= 3:
            _current_up_bps = min(MAX_UP, _current_up_bps * 1.15)
            up_high_counter = 0
    elif up_util < 0.3:
        up_low_counter  += 1
        up_high_counter  = 0
        if up_low_counter >= 5:
            _current_up_bps = max(MIN_BPS * 0.3, _current_up_bps * 0.95)
            up_low_counter  = 0
    else:
        up_low_counter = up_high_counter = 0

    _current_down_bps = max(MIN_BPS,       min(MAX_BPS, _current_down_bps))
    _current_up_bps   = max(MIN_BPS * 0.3, min(MAX_UP,  _current_up_bps))

    return _current_down_bps, _current_up_bps
