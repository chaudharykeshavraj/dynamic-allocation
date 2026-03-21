import time
import subprocess
 
# ── SET THESE ONCE ────────────────────────────────────────────
# Measure using speedtest on a connected device
# Your WiFi hotspot capacity from testing = ~10 Mbps down, ~4 Mbps up
WIFI_DOWN_MBPS = 14.0
WIFI_UP_MBPS   = 4.0
 
# tc gets 90% of real capacity
# ensures tc drops packets BEFORE WiFi hardware
# makes tc drop counters show true unsatisfied demand
TC_HEADROOM = 0.90
 
# ── Constants ─────────────────────────────────────────────────
DOWN_BPS = (WIFI_DOWN_MBPS * 1_000_000 / 8) * TC_HEADROOM
UP_BPS   = (WIFI_UP_MBPS   * 1_000_000 / 8) * TC_HEADROOM
 
_current_down_bps = None
_current_up_bps   = None
 
 
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
    """
    Called ONCE at startup. Returns fixed configured pool.
    No measurement, no waiting — instant and reliable.
    Pool never drifts or shrinks.
    """
    global _current_down_bps, _current_up_bps
 
    # clear any leftover tc rules
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', interface, 'root'],
        capture_output=True
    )
 
    _current_down_bps = DOWN_BPS
    _current_up_bps   = UP_BPS
 
    print(f"\n  WiFi pool (fixed):")
    print(f"  Download = {_current_down_bps*8/1e6:.2f} Mbps")
    print(f"  Upload   = {_current_up_bps*8/1e6:.2f} Mbps")
 
    return _current_down_bps, _current_up_bps
 
 
def probe_real_capacity(interface='wlp3s0'):
    """
    REMOVED: probe was causing 3 second interruptions
    every 60 seconds with no benefit because observed traffic
    never exceeds configured pool (tc prevents it).
 
    This function now does nothing except return current pool.
    Kept for compatibility with main.py imports.
    """
    global _current_down_bps, _current_up_bps
 
    if _current_down_bps is None:
        return measure_total_bandwidth(interface)
 
    print(f"  [PROBE] Skipped — pool fixed at "
          f"{_current_down_bps*8/1e6:.2f} Mbps")
 
    return _current_down_bps, _current_up_bps
 
 
def update_bandwidth_estimate(interface='wlp3s0'):
    """
    Called every interval. Returns fixed pool.
    No shrinking, no growing, no utilization logic.
 
    Why removed dynamic adjustment:
      Low utilization = devices idle, NOT low capacity
      Dynamic downward adjustment caused pool to shrink
      from 18 Mbps → 2 Mbps over time incorrectly
      Pool is a physical WiFi property — set it once correctly
    """
    global _current_down_bps, _current_up_bps
 
    if _current_down_bps is None:
        return measure_total_bandwidth(interface)
 
    # just print current utilization for info
    t1       = time.time()
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, tx2 = _read_interface_bytes(interface)
    t2       = time.time()
 
    elapsed       = max(t2 - t1, 0.01)
    observed_down = (rx2 - rx1) / elapsed
 
    util = observed_down / (_current_down_bps + 1e-9)
    print(f"  Pool={_current_down_bps*8/1e6:.2f}Mbps  "
          f"Observed={observed_down*8/1e6:.2f}Mbps  "
          f"Util={util:.1%}")
 
    return _current_down_bps, _current_up_bps