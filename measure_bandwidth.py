import time
import subprocess
import re
 
BAND_2_4GHZ_BPS = (20 * 1_000_000) / 8   # 20 Mbps practical 2.4GHz
BAND_5GHZ_BPS   = (50 * 1_000_000) / 8   # 50 Mbps practical 5GHz
 
MIN_MBPS    = 2
MAX_MBPS    = 50
TC_HEADROOM = 0.9
PROBE_SECS  = 3
 
MIN_BPS = (MIN_MBPS * 1_000_000) / 8
MAX_BPS = (MAX_MBPS * 1_000_000) / 8
 
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
 
 
def _detect_wifi_band(interface):
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            capture_output=True, text=True
        )
        m = re.search(r'Frequency[:\s]+([\d.]+)\s*GHz', result.stdout)
        if m:
            freq = float(m.group(1))
            if freq >= 5.0:
                print(f"  WiFi = 5 GHz → starting pool = 50 Mbps")
                return BAND_5GHZ_BPS
            else:
                print(f"  WiFi = 2.4 GHz → starting pool = 20 Mbps")
                return BAND_2_4GHZ_BPS
    except Exception:
        pass
    print("  WiFi band unknown → default 20 Mbps")
    return BAND_2_4GHZ_BPS
 
 
def measure_total_bandwidth(interface='wlp3s0'):
    """
    Called ONCE at startup BEFORE tc rules.
    Uses WiFi band detection as starting pool.
    Probe at interval 1 adjusts to real observed value.
    """
    global _current_down_bps, _current_up_bps
 
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', interface, 'root'],
        capture_output=True
    )
 
    print(f"  Detecting WiFi band...")
    band_bps = _detect_wifi_band(interface)
 
    # observe 5 seconds of actual traffic
    print(f"  Observing {interface} for 5 seconds...")
    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(5)
    rx2, tx2 = _read_interface_bytes(interface)
 
    observed_down = (rx2 - rx1) / 5
    observed_up   = (tx2 - tx1) / 5
 
    print(f"  Observed: down={observed_down*8/1e6:.2f} Mbps  up={observed_up*8/1e6:.2f} Mbps")
 
    # use band capacity as floor — never start lower than band estimate
    _current_down_bps = max(observed_down * TC_HEADROOM, band_bps * TC_HEADROOM)
    _current_up_bps   = max(observed_up   * TC_HEADROOM, MIN_BPS * 0.3)
 
    _current_down_bps = max(MIN_BPS, min(MAX_BPS,       _current_down_bps))
    _current_up_bps   = max(MIN_BPS * 0.3, min(MAX_BPS * 0.5, _current_up_bps))
 
    print(f"  Initial pool: down={_current_down_bps*8/1e6:.2f} Mbps  up={_current_up_bps*8/1e6:.2f} Mbps")
    print(f"  (Probe at interval 1 will adjust to real WiFi speed)")
 
    return _current_down_bps, _current_up_bps
 
 
def probe_real_capacity(interface='wlp3s0'):
    """
    Remove tc for 3 seconds → observe real free-run capacity.
    This is the ONLY reliable way to measure WiFi capacity.
    Updates pool based on what devices actually get when unlimited.
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
        # blend 50/50 — prevents single noisy probe drastically changing pool
        _current_down_bps = 0.5 * _current_down_bps + 0.5 * new_down
 
    if real_up > MIN_TRAFFIC:
        new_up          = min(real_up * TC_HEADROOM, _current_down_bps * 0.5)
        _current_up_bps = 0.5 * _current_up_bps + 0.5 * new_up
 
    _current_down_bps = max(MIN_BPS,       min(MAX_BPS,       _current_down_bps))
    _current_up_bps   = max(MIN_BPS * 0.3, min(MAX_BPS * 0.5, _current_up_bps))
 
    print(f"  [PROBE] New pool: down={_current_down_bps*8/1e6:.2f} Mbps  up={_current_up_bps*8/1e6:.2f} Mbps")
 
    # restore tc rules
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
    Called every interval. Zero network cost.
 
    FIX: ONLY adjusts upward — never downward.
 
    Why no downward adjustment:
      Low utilization = devices not downloading much RIGHT NOW
      This does NOT mean WiFi capacity dropped
      WiFi capacity is a physical property of hardware
      Only probe_real_capacity() can reliably measure real capacity
      because it removes tc and observes free-run traffic
 
    If we adjust downward on low utilization:
      pool shrinks from 18 Mbps → 2 Mbps over time
      even though WiFi can still do 6 Mbps
      tc caps everyone at 2 Mbps → nobody can get more
      probe tries to fix it but shrinks again between probes
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
 
    down_util = observed_down / (_current_down_bps + 1e-9)
    up_util   = observed_up   / (_current_up_bps   + 1e-9)
 
    print(f"  Util: down={down_util:.1%}  up={up_util:.1%}  "
          f"pool={_current_down_bps*8/1e6:.2f}Mbps")
 
    # ONLY adjust upward
    # if observed exceeds current pool → proves real capacity is higher
    # tc prevents observing above current limit so this is reliable
    if observed_down > _current_down_bps:
        _current_down_bps = min(MAX_BPS,
            0.7 * _current_down_bps + 0.3 * (observed_down * TC_HEADROOM))
        print(f"  Pool raised → {_current_down_bps*8/1e6:.2f} Mbps")
 
    MAX_UP = _current_down_bps * 0.5
    if observed_up > _current_up_bps:
        _current_up_bps = min(MAX_UP,
            0.7 * _current_up_bps + 0.3 * (observed_up * TC_HEADROOM))
 
    # clamp — never go below MIN_BPS
    _current_down_bps = max(MIN_BPS, _current_down_bps)
    _current_up_bps   = max(MIN_BPS * 0.3, _current_up_bps)
 
    return _current_down_bps, _current_up_bps
 