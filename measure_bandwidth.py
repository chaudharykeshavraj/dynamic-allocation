import time
import subprocess

# ── Internal State ────────────────────────────────────────────
_current_down_bps = None
_current_up_bps   = None

# set tc slightly BELOW real WiFi capacity
# ensures tc is bottleneck BEFORE WiFi hardware
# this makes tc drop counters show true unsatisfied demand
# value: 0.9 = 90% of observed capacity
TC_HEADROOM = 0.9

def _read_interface_bytes(interface):
    """
    Read cumulative byte counters from Linux kernel.
    /proc/net/dev updated by kernel in real time.
    rx = bytes received on interface
    tx = bytes transmitted on interface
    Zero network cost — just a kernel file read.
    """
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if interface in line:
                    parts = line.split()
                    rx    = int(parts[1])   # received bytes
                    tx    = int(parts[9])   # transmitted bytes
                    return rx, tx
    except Exception as e:
        print(f"  Interface read error: {e}")
    return 0, 0

def measure_total_bandwidth(interface='wlp3s0'):
    """
    Called ONCE at startup BEFORE tc rules are set up.

    Why before tc:
      tc creates ceiling on traffic
      measuring before tc = real free-run capacity visible
      no chicken-and-egg problem

    Why 90% of observed (TC_HEADROOM = 0.9):
      tc must become bottleneck BEFORE WiFi hardware
      if tc limit > WiFi capacity:
        WiFi hardware saturates first
        random hardware packet drops
        TCP reduces demand before tc sees it
        tc drop counters stay at 0
        true demand invisible to system (mirroring!)

      if tc limit < WiFi capacity:
        tc drops packets first
        WiFi hardware never saturates
        tc drop counters show true unsatisfied demand
        get_tc_demand_boost() works correctly
        true demand visible to system!

    Returns (down_bytes_per_sec, up_bytes_per_sec)
    """
    global _current_down_bps, _current_up_bps

    print(f"\n--- Measuring WiFi Capacity on {interface} ---")

    # clear any leftover tc rules from previous run
    # so observation is unaffected by old limits
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', interface, 'root'],
        capture_output=True
    )
    print("  Cleared old tc rules")
    print(f"  Observing {interface} for 5 seconds (no tc limits)...")

    # observe free-run traffic for 5 seconds
    OBSERVE_SECS = 5
    rx1, tx1     = _read_interface_bytes(interface)
    time.sleep(OBSERVE_SECS)
    rx2, tx2     = _read_interface_bytes(interface)

    # bytes per second flowing through interface
    observed_down = (rx2 - rx1) / OBSERVE_SECS
    observed_up   = (tx2 - tx1) / OBSERVE_SECS

    observed_down_mbps = (observed_down * 8) / 1_000_000
    observed_up_mbps   = (observed_up   * 8) / 1_000_000
    print(f"  Observed download = {observed_down_mbps:.2f} Mbps")
    print(f"  Observed upload   = {observed_up_mbps:.2f} Mbps")

    # minimum meaningful traffic threshold
    MIN_TRAFFIC = 100 * 1024   # 100 KB/s

    if observed_down > MIN_TRAFFIC:
        # set tc pool to 90% of observed capacity
        # tc becomes bottleneck BEFORE WiFi hardware
        # ensures tc drops reveal true unsatisfied demand
        _current_down_bps = observed_down * TC_HEADROOM
        _current_up_bps   = max(
            observed_up * TC_HEADROOM,
            _current_down_bps * 0.3
        )
        print(f"  Setting pool to {TC_HEADROOM*100:.0f}% of observed")
        print(f"  → tc will be bottleneck before WiFi hardware")
        print(f"  → tc drop counters will show true demand")

    else:
        # no devices active yet
        # use safe conservative default
        # probe will correct after 60 seconds
        _current_down_bps = 5 * 1_000_000 / 8    # 5 Mbps
        _current_up_bps   = 2 * 1_000_000 / 8    # 2 Mbps
        print(f"  No traffic detected → safe default 5 Mbps")
        print(f"  Will auto-correct after first probe (60 seconds)")

    down_mbps = (_current_down_bps * 8) / 1_000_000
    up_mbps   = (_current_up_bps   * 8) / 1_000_000

    print(f"\n  Download pool = {down_mbps:.2f} Mbps")
    print(f"  Upload pool   = {up_mbps:.2f} Mbps")
    print("----------------------------------------------\n")

    return _current_down_bps, _current_up_bps

def probe_real_capacity(interface, setup_tc_func, reapply_devices_func):
    """
    Called every 60 seconds from main loop.
    Removes tc for 3 seconds → observes true capacity.
    Sets pool to 90% of observed → tc remains bottleneck.
    Restores tc immediately after.
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

    # observe free-run for 3 seconds
    PROBE_SECS = 3
    rx1, tx1   = _read_interface_bytes(interface)
    time.sleep(PROBE_SECS)
    rx2, tx2   = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / PROBE_SECS
    real_up   = (tx2 - tx1) / PROBE_SECS

    real_down_mbps = (real_down * 8) / 1_000_000
    print(f"  [PROBE] Observed = {real_down_mbps:.2f} Mbps")

    MIN_TRAFFIC = 100 * 1024

    if real_down > MIN_TRAFFIC:
        # set to 90% of probe observation
        # same logic as startup — tc must be first bottleneck
        probe_down = real_down * TC_HEADROOM
        probe_up   = max(real_up * TC_HEADROOM, probe_down * 0.3)

        # blend with current estimate 50/50
        # prevents single noisy probe from drastically changing pool
        _current_down_bps = 0.5 * _current_down_bps + 0.5 * probe_down
        _current_up_bps   = 0.5 * _current_up_bps   + 0.5 * probe_up

        print(f"  [PROBE] Updated pool → {(_current_down_bps*8)/1_000_000:.2f} Mbps")
    else:
        print(f"  [PROBE] Low traffic → keeping current estimate")

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

    Only adjusts upward because:
      tc limits traffic to current pool
      observed traffic never exceeds pool
      cannot detect real capacity from below
      probe_real_capacity() handles downward corrections
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
    # if observed exceeds current → real capacity higher than thought
    # apply 90% headroom to keep tc as bottleneck
    if observed_down > _current_down_bps:
        new_down          = 0.7 * _current_down_bps + 0.3 * observed_down
        _current_down_bps = new_down * TC_HEADROOM
        print(f"  Capacity updated → {(_current_down_bps*8)/1_000_000:.2f} Mbps")

    if observed_up > _current_up_bps:
        new_up          = 0.7 * _current_up_bps + 0.3 * observed_up
        _current_up_bps = new_up * TC_HEADROOM

    return _current_down_bps, _current_up_bps
