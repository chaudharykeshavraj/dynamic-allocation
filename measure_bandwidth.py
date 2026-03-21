import time
import subprocess
 
# ── CONFIGURE THESE ONCE ─────────────────────────────────────
# Run speedtest on a connected device and set these values.
# These are the real WiFi hotspot throughput limits.
# Your measured values: ~6 Mbps down, ~2 Mbps up
WIFI_DOWN_MBPS = 11.0
WIFI_UP_MBPS   = 5.0
 
# tc headroom — set pool slightly below real capacity
# so tc drops packets BEFORE WiFi hardware does
# this makes tc drop counters show true unsatisfied demand
TC_HEADROOM = 0.90
 
# ── Derived constants ─────────────────────────────────────────
DOWN_BPS = (WIFI_DOWN_MBPS * 1_000_000 / 8) * TC_HEADROOM
UP_BPS   = (WIFI_UP_MBPS   * 1_000_000 / 8) * TC_HEADROOM
 
# internal state
_current_down_bps = None
_current_up_bps   = None
 
 
def _read_interface_bytes(interface):
    """Read cumulative rx/tx bytes from kernel. Zero cost."""
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
    """
    Called ONCE at startup.
    Uses hardcoded values — no measurement needed.
    Simple, reliable, no shrinking, no drift.
    """
    global _current_down_bps, _current_up_bps
 
    # clear any leftover tc rules before setup
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', interface, 'root'],
        capture_output=True
    )
 
    _current_down_bps = DOWN_BPS
    _current_up_bps   = UP_BPS
 
    print(f"\n  WiFi pool set:")
    print(f"  Download = {_current_down_bps*8/1e6:.2f} Mbps")
    print(f"  Upload   = {_current_up_bps*8/1e6:.2f} Mbps")
    print(f"  (Edit WIFI_DOWN_MBPS/WIFI_UP_MBPS in measure_bandwidth.py to change)")
 
    return _current_down_bps, _current_up_bps
 
 
def probe_real_capacity(interface='wlp3s0'):
    """
    Called at interval 1 and every 60 seconds.
    Removes tc briefly to observe real free-run speed.
    Only updates pool if observed is HIGHER than current
    (proves real capacity is higher than configured).
    Never shrinks below configured value.
    """
    global _current_down_bps, _current_up_bps
 
    print("  [PROBE] Observing real capacity for 3 seconds...")
 
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'ingress'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', 'ifb0', 'root'],
                   capture_output=True)
 
    time.sleep(0.5)
 
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(3)
    rx2, tx2 = _read_interface_bytes(interface)
 
    real_down = (rx2 - rx1) / 3
    real_up   = (tx2 - tx1) / 3
 
    print(f"  [PROBE] Observed: down={real_down*8/1e6:.2f} Mbps  "
          f"up={real_up*8/1e6:.2f} Mbps")
    print(f"  [PROBE] Configured: down={_current_down_bps*8/1e6:.2f} Mbps")
 
    # only update if observed is meaningfully higher than configured
    # this means real capacity is more than we thought → raise pool
    # never lower below configured value — pool shrinking was the bug
    SIGNIFICANT_THRESHOLD = 50 * 1024   # 50 KB/s
 
    if real_down > SIGNIFICANT_THRESHOLD:
        probed = real_down * TC_HEADROOM
        if probed > _current_down_bps * 1.1:
            # real capacity meaningfully higher → raise pool
            _current_down_bps = probed
            print(f"  [PROBE] Pool raised → {_current_down_bps*8/1e6:.2f} Mbps")
        else:
            # observed close to or below configured → keep configured
            print(f"  [PROBE] Pool kept at {_current_down_bps*8/1e6:.2f} Mbps")
 
    if real_up > SIGNIFICANT_THRESHOLD:
        probed_up = min(real_up * TC_HEADROOM, _current_down_bps * 0.5)
        if probed_up > _current_up_bps * 1.1:
            _current_up_bps = probed_up
 
    # restore tc rules
    try:
        from enforce import setup_tc, reapply_all_devices
        setup_tc(interface, _current_down_bps, _current_up_bps)
        reapply_all_devices()
        print("  [PROBE] tc restored")
    except Exception as e:
        print(f"  [PROBE] tc restore error: {e}")
 
    return _current_down_bps, _current_up_bps
 
 
def update_bandwidth_estimate(interface='wlp3s0'):
    """
    Called every interval. Zero cost — reads /proc/net/dev.
    ONLY adjusts upward — never shrinks pool.
    Low utilization ≠ low capacity, just idle devices.
    """
    global _current_down_bps, _current_up_bps
 
    if _current_down_bps is None:
        return measure_total_bandwidth(interface)
 
    t1       = time.time()
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, tx2 = _read_interface_bytes(interface)
    t2       = time.time()
 
    elapsed       = max(t2 - t1, 0.01)
    observed_down = (rx2 - rx1) / elapsed
    observed_up   = (tx2 - tx1) / elapsed
 
    print(f"  Pool: {_current_down_bps*8/1e6:.2f} Mbps  "
          f"Observed: {observed_down*8/1e6:.2f} Mbps  "
          f"Util: {observed_down/_current_down_bps:.1%}")
 
    # only adjust upward — never shrink
    if observed_down > _current_down_bps:
        _current_down_bps = 0.7 * _current_down_bps + \
                            0.3 * (observed_down * TC_HEADROOM)
        print(f"  Pool raised → {_current_down_bps*8/1e6:.2f} Mbps")
 
    if observed_up > _current_up_bps:
        max_up          = _current_down_bps * 0.5
        _current_up_bps = min(max_up,
            0.7 * _current_up_bps + 0.3 * (observed_up * TC_HEADROOM))
 
    return _current_down_bps, _current_up_bps
 