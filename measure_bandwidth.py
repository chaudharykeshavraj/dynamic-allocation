import time
import subprocess
import re

# ── Internal State ────────────────────────────────────────────
_current_down_bps = None
_current_up_bps   = None
TC_HEADROOM       = 0.9

def _read_interface_bytes(interface):
    """Read cumulative rx/tx bytes from kernel. Zero cost."""
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if interface in line:
                    parts = line.split()
                    return int(parts[1]), int(parts[9])
    except Exception as e:
        print(f"  Interface read error: {e}")
    return 0, 0

def _detect_wifi_band(interface):
    """
    Detect if interface is 2.4GHz or 5GHz.
    Returns practical max throughput in bytes/sec.
    2.4GHz real max ≈ 20 Mbps shared
    5GHz   real max ≈ 50 Mbps shared
    """
    try:
        result = subprocess.run(
            ['iwconfig', interface],
            capture_output=True, text=True
        )
        output = result.stdout + result.stderr

        # check frequency
        freq_match = re.search(r'Frequency[:\s]+([\d.]+)\s*GHz', output)
        if freq_match:
            freq = float(freq_match.group(1))
            if freq >= 5.0:
                print(f"  WiFi band = 5 GHz → practical max ~50 Mbps")
                return 50 * 1_000_000 / 8   # 50 Mbps in bytes/sec
            else:
                print(f"  WiFi band = 2.4 GHz → practical max ~20 Mbps")
                return 20 * 1_000_000 / 8   # 20 Mbps in bytes/sec

        # check channel — 5GHz channels are above 14
        chan_match = re.search(r'Access Point.*Channel[:\s]+(\d+)', output)
        if not chan_match:
            chan_match = re.search(r'Channel[:\s]+(\d+)', output)
        if chan_match:
            channel = int(chan_match.group(1))
            if channel > 14:
                print(f"  WiFi channel={channel} → 5 GHz → practical max ~50 Mbps")
                return 50 * 1_000_000 / 8
            else:
                print(f"  WiFi channel={channel} → 2.4 GHz → practical max ~20 Mbps")
                return 20 * 1_000_000 / 8

    except Exception as e:
        print(f"  Band detection failed: {e}")

    # fallback — assume 2.4GHz conservative
    print(f"  Band unknown → assuming 2.4 GHz default")
    return 20 * 1_000_000 / 8

def measure_total_bandwidth(interface='wlp3s0'):
    """
    Called ONCE at startup BEFORE tc rules are set up.

    Strategy:
      1. Detect WiFi band → get theoretical max
      2. Observe actual traffic for 5 seconds
      3. Use MAX of (observed, band-based estimate) as starting point
      4. Apply 90% TC_HEADROOM so tc becomes first bottleneck
      5. probe_real_capacity() at interval 1 will fine-tune

    Why not use observed traffic only:
      At startup devices are idle → observed = near zero
      Cannot infer WiFi capacity from idle traffic
      Must use band knowledge as floor
    """
    global _current_down_bps, _current_up_bps

    print(f"\n--- Measuring WiFi Capacity on {interface} ---")

    # clear any leftover tc rules
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', interface, 'root'],
        capture_output=True
    )
    print("  Cleared old tc rules")

    # step 1 — detect WiFi band for theoretical max
    band_max_bps = _detect_wifi_band(interface)
    band_mbps    = (band_max_bps * 8) / 1_000_000
    print(f"  Band-based max = {band_mbps:.1f} Mbps")

    # step 2 — observe actual traffic for 5 seconds
    print(f"  Observing {interface} for 5 seconds...")
    OBSERVE_SECS = 5
    rx1, tx1     = _read_interface_bytes(interface)
    time.sleep(OBSERVE_SECS)
    rx2, tx2     = _read_interface_bytes(interface)

    observed_down = (rx2 - rx1) / OBSERVE_SECS
    observed_up   = (tx2 - tx1) / OBSERVE_SECS
    obs_mbps      = (observed_down * 8) / 1_000_000
    print(f"  Observed traffic  = {obs_mbps:.2f} Mbps")

    # step 3 — use band-based estimate as starting point
    # observed traffic at startup is NOT capacity
    # it is just current usage which is usually near zero
    # band-based estimate is much more realistic
    # probe at interval 1 will correct it to real value
    _current_down_bps = band_max_bps * TC_HEADROOM
    _current_up_bps   = _current_down_bps * 0.5

    # if observed is HIGHER than band estimate (unlikely but possible)
    # use observed as it proves capacity is at least that high
    if observed_down > _current_down_bps:
        _current_down_bps = observed_down * TC_HEADROOM
        _current_up_bps   = max(observed_up * TC_HEADROOM,
                                _current_down_bps * 0.3)
        print(f"  Observed > band estimate → using observed")

    down_mbps = (_current_down_bps * 8) / 1_000_000
    up_mbps   = (_current_up_bps   * 8) / 1_000_000

    print(f"\n  Initial Download pool = {down_mbps:.2f} Mbps")
    print(f"  Initial Upload pool   = {up_mbps:.2f} Mbps")
    print(f"  (Probe at interval 1 will correct to real value)")
    print("----------------------------------------------\n")

    return _current_down_bps, _current_up_bps

def probe_real_capacity(interface, setup_tc_func, reapply_devices_func):
    """
    Called at interval 1 and every 60 seconds.
    Removes tc for 3 seconds → observes true free-run capacity.
    This is the ONLY reliable way to measure WiFi capacity.
    tc removed → devices run freely → real throughput visible.
    """
    global _current_down_bps, _current_up_bps

    print("\n  [PROBE] Removing tc rules for 3 seconds...")

    # remove all tc rules
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'root'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', interface, 'ingress'],
                   capture_output=True)
    subprocess.run(['tc', 'qdisc', 'del', 'dev', 'ifb0', 'root'],
                   capture_output=True)

    # observe free run for 3 seconds
    PROBE_SECS  = 3
    MIN_TRAFFIC = 10 * 1024   # 10 KB/s

    rx1, tx1    = _read_interface_bytes(interface)
    time.sleep(PROBE_SECS)
    rx2, tx2    = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / PROBE_SECS
    real_up   = (tx2 - tx1) / PROBE_SECS

    real_mbps = (real_down * 8) / 1_000_000
    print(f"  [PROBE] Free-run observed = {real_mbps:.2f} Mbps")

    if real_down > MIN_TRAFFIC:
        # blend 50/50 with current estimate
        # prevents single noisy probe from drastically changing pool
        probe_down        = real_down * TC_HEADROOM
        probe_up          = max(real_up * TC_HEADROOM, probe_down * 0.3)

        _current_down_bps = 0.5 * _current_down_bps + 0.5 * probe_down
        _current_up_bps   = 0.5 * _current_up_bps   + 0.5 * probe_up

        print(f"  [PROBE] Updated pool → "
              f"{(_current_down_bps*8)/1_000_000:.2f} Mbps down  "
              f"{(_current_up_bps*8)/1_000_000:.2f} Mbps up")
    else:
        print(f"  [PROBE] Very low traffic → keeping current estimate")
        print(f"  [PROBE] Try downloading something on a device during probe")

    # restore tc immediately
    print("  [PROBE] Restoring tc rules...")
    setup_tc_func(interface, _current_down_bps, _current_up_bps)
    reapply_devices_func()
    print("  [PROBE] Done")

    return _current_down_bps, _current_up_bps

def update_bandwidth_estimate(interface='wlp3s0'):
    """
    Called every interval inside main loop.
    Reads /proc/net/dev — zero network cost.
    Only adjusts UPWARD — tc ceiling prevents seeing real capacity.
    probe_real_capacity() handles downward corrections.
    """
    global _current_down_bps, _current_up_bps

    if _current_down_bps is None:
        return measure_total_bandwidth(interface)

    rx1, tx1 = _read_interface_bytes(interface)
    time.sleep(1)
    rx2, tx2 = _read_interface_bytes(interface)

    observed_down = rx2 - rx1
    observed_up   = tx2 - tx1

    # only adjust upward
    if observed_down > _current_down_bps:
        new_down          = 0.7 * _current_down_bps + 0.3 * observed_down
        _current_down_bps = new_down * TC_HEADROOM
        print(f"  Capacity updated UP → "
              f"{(_current_down_bps*8)/1_000_000:.2f} Mbps")

    if observed_up > _current_up_bps:
        new_up          = 0.7 * _current_up_bps + 0.3 * observed_up
        _current_up_bps = new_up * TC_HEADROOM

    return _current_down_bps, _current_up_bps
