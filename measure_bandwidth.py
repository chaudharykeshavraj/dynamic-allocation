import time
import subprocess

# ── Internal State ────────────────────────────────────────────
_current_down_bps = None
_current_up_bps   = None

# tc must be below real WiFi capacity
# ensures tc drops packets BEFORE WiFi hardware does
# makes tc drop counters show true unsatisfied demand
TC_HEADROOM = 0.9

def _read_interface_bytes(interface):
    """
    Read cumulative byte counters from Linux kernel.
    /proc/net/dev is updated by kernel in real time.
    rx = bytes received on interface (devices downloading)
    tx = bytes transmitted on interface (devices uploading)
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

    Observes wlp3s0 for 10 seconds to detect real traffic.
    If traffic detected → use 90% as pool (tc becomes bottleneck)
    If no traffic yet  → use safe 5 Mbps default
                         probe_real_capacity() will correct at interval 1

    Why 10 seconds:
      gives devices time to send background traffic
      more accurate than 5 seconds

    Why MIN_TRAFFIC = 10 KB/s:
      even idle phones send background traffic (DNS, push)
      10 KB/s catches this reliably
      old 100 KB/s threshold was too high → always fell to default
    """
    global _current_down_bps, _current_up_bps

    print(f"\n--- Measuring WiFi Capacity on {interface} ---")

    # clear any leftover tc rules from previous run
    subprocess.run(
        ['tc', 'qdisc', 'del', 'dev', interface, 'root'],
        capture_output=True
    )
    print("  Cleared old tc rules")
    print(f"  Observing {interface} for 10 seconds (no tc limits)...")

    # observe free-run traffic for 10 seconds
    OBSERVE_SECS = 10
    MIN_TRAFFIC  = 10 * 1024   # 10 KB/s — catches background traffic

    rx1, tx1     = _read_interface_bytes(interface)
    time.sleep(OBSERVE_SECS)
    rx2, tx2     = _read_interface_bytes(interface)

    observed_down = (rx2 - rx1) / OBSERVE_SECS
    observed_up   = (tx2 - tx1) / OBSERVE_SECS

    down_mbps = (observed_down * 8) / 1_000_000
    up_mbps   = (observed_up   * 8) / 1_000_000
    print(f"  Observed download = {down_mbps:.2f} Mbps")
    print(f"  Observed upload   = {up_mbps:.2f} Mbps")

    if observed_down > MIN_TRAFFIC:
        # real traffic detected
        # set pool to 90% so tc becomes first bottleneck
        _current_down_bps = observed_down * TC_HEADROOM
        _current_up_bps   = max(observed_up * TC_HEADROOM,
                                _current_down_bps * 0.3)
        print(f"  Traffic detected → using observed × {TC_HEADROOM}")

    else:
        # no traffic yet — devices idle at startup
        # use safe 5 Mbps default
        # probe at interval 1 will correct this immediately
        _current_down_bps = 5 * 1_000_000 / 8    # 5 Mbps
        _current_up_bps   = 2 * 1_000_000 / 8    # 2 Mbps
        print(f"  No traffic detected → safe default 5 Mbps")
        print(f"  Probe will correct at interval 1 automatically")

    print(f"\n  Download pool = {(_current_down_bps*8)/1_000_000:.2f} Mbps")
    print(f"  Upload pool   = {(_current_up_bps*8)/1_000_000:.2f} Mbps")
    print("----------------------------------------------\n")

    return _current_down_bps, _current_up_bps

def probe_real_capacity(interface, setup_tc_func, reapply_devices_func):
    """
    Removes tc rules for 3 seconds to observe real free-run capacity.
    Restores tc rules immediately after.

    Called:
      at interval 1 always (corrects startup default immediately)
      every 60 seconds after that (corrects any drift)

    Why needed:
      tc creates ceiling — /proc/net/dev never shows above limit
      removing tc briefly reveals true WiFi capacity
      3 seconds unfairness every 60 seconds is acceptable
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
    PROBE_SECS   = 3
    MIN_TRAFFIC  = 10 * 1024

    rx1, tx1     = _read_interface_bytes(interface)
    time.sleep(PROBE_SECS)
    rx2, tx2     = _read_interface_bytes(interface)

    real_down = (rx2 - rx1) / PROBE_SECS
    real_up   = (tx2 - tx1) / PROBE_SECS

    real_mbps = (real_down * 8) / 1_000_000
    print(f"  [PROBE] Observed = {real_mbps:.2f} Mbps")

    if real_down > MIN_TRAFFIC:
        # blend probe result with current estimate 50/50
        # prevents single noisy probe from drastically changing pool
        probe_down        = real_down * TC_HEADROOM
        probe_up          = max(real_up * TC_HEADROOM, probe_down * 0.3)

        _current_down_bps = 0.5 * _current_down_bps + 0.5 * probe_down
        _current_up_bps   = 0.5 * _current_up_bps   + 0.5 * probe_up

        print(f"  [PROBE] Updated → {(_current_down_bps*8)/1_000_000:.2f} Mbps")
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
    Only adjusts upward — tc ceiling prevents seeing real capacity.
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
    # tc prevents observing above current limit
    # so only trust observations that exceed current estimate
    if observed_down > _current_down_bps:
        new_down          = 0.7 * _current_down_bps + 0.3 * observed_down
        _current_down_bps = new_down * TC_HEADROOM
        print(f"  Capacity updated UP → {(_current_down_bps*8)/1_000_000:.2f} Mbps")

    if observed_up > _current_up_bps:
        new_up          = 0.7 * _current_up_bps + 0.3 * observed_up
        _current_up_bps = new_up * TC_HEADROOM

    return _current_down_bps, _current_up_bps