import subprocess
import time
import re

known_devices           = {}    # ip → class_id
is_setup_done           = False
next_class_id           = 10    # global counter, never reuses ids
last_interface          = None
last_device_allocations = {}    # ip → latest allocated rates, used for tc reapply

# ── tc byte counter state ──────────────────────────────────────
# _prev_tc  : snapshot taken at END of each cycle
# _curr_tc  : snapshot taken at START of each cycle
# diff = curr - prev over elapsed = post-shaping bytes/sec
# tc Sent counter increments AFTER HTB delivers packet to wire
# → physically bounded by rate ceiling → no spikes possible
_prev_tc = {}   # class_id → { down_bytes, up_bytes, time }


def run_cmd(cmd):
    subprocess.run(cmd, shell=True)

def _run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


# ── tc byte counter parser ─────────────────────────────────────

def _parse_tc_bytes(tc_output):
    """
    Parse 'tc -s class show' output.
    Returns dict: class_id (int) → cumulative bytes sent by HTB class.

    Real output format (confirmed from tc -s class show dev wlp3s0):
      class htb 1:13 parent 1:1 leaf 13: prio 0 rate 609Kbit ...
       Sent 383440 bytes 446 pkt (dropped 0, overlimits 345 requeues 0)
       backlog 0b 0p requeues 0
       lended: 444 borrowed: 0 giants: 0
       tokens: ...

    Key facts:
      - 'Sent N bytes' is always the line immediately after 'class htb 1:N'
      - fq_codel classes also appear (class fq_codel X:Y) — ignored by htb regex
      - class_id is the minor number after '1:' in the class htb header
      - Only HTB classes have the 'Sent N bytes' line we care about
    """
    counters   = {}
    current_id = None

    for line in tc_output.splitlines():
        # match HTB class header only — ignore fq_codel classes
        m = re.search(r'class htb 1:(\d+)', line)
        if m:
            current_id = int(m.group(1))
            continue    # move to next line immediately

        # match Sent bytes on the line following the class header
        # current_id stays set until we find Sent, so intermediate
        # lines between header and Sent are tolerated safely
        if current_id is not None:
            m = re.search(r'Sent (\d+) bytes', line)
            if m:
                counters[current_id] = int(m.group(1))
                current_id = None   # reset — one Sent per class

    return counters


def _read_tc_bytes_now(interface):
    """
    Read current cumulative tc Sent byte counters for both interfaces.
    Returns (down_counters, up_counters): dict class_id → bytes.
    wlp3s0 egress = download path, ifb0 egress = upload path.
    """
    down_raw = _run(f"tc -s class show dev {interface}")
    up_raw   = _run("tc -s class show dev ifb0")

    down = _parse_tc_bytes(down_raw)
    up   = _parse_tc_bytes(up_raw)

    return down, up


def _snapshot_tc_counters(interface):
    """
    Store current tc byte counters into _prev_tc.
    Called at END of each enforce() cycle.
    Next cycle's read_stats_tc() diffs against these values.
    Only snapshots class_ids actively tracked in known_devices.
    """
    down_counters, up_counters = _read_tc_bytes_now(interface)
    now = time.time()

    for ip, class_id in known_devices.items():
        _prev_tc[class_id] = {
            'down_bytes': down_counters.get(class_id, 0),
            'up_bytes'  : up_counters.get(class_id,   0),
            'time'      : now,
        }

    # ── debug — uncomment to diagnose zero enforced ──
    # print(f"[snapshot] known_devices = {known_devices}")
    # print(f"[snapshot] _prev_tc      = {_prev_tc}")
    # print(f"[snapshot] down_counters = {down_counters}")
    # print(f"[snapshot] up_counters   = {up_counters}")
    # ─────────────────────────────────────────────────


def read_stats_tc(interface):
    """
    Compute per-device actual throughput by diffing tc Sent byte counters.

    Why tc counters give spike-free values:
      iptables FORWARD fires BEFORE tc shapes the packet.
      tc 'Sent bytes' increments AFTER HTB delivers the packet to wire.

      During a burst: many packets arrive at FORWARD in 1 second.
        iptables: counts all burst packets → spike above pool
        tc Sent:  counts only what HTB actually dripped out → bounded by rate

      So tc counters are physically bounded by the configured ceiling.
      Total enforced across all devices can never exceed the pool.

    Timing:
      _prev_tc was written at END of previous cycle (5 seconds ago).
      We read current counters now → elapsed ≈ 5 seconds of shaped traffic.

    Returns dict: ip → { down_bps, up_bps }
    First cycle per device returns 0 (no prev snapshot yet).
    """
    down_current, up_current = _read_tc_bytes_now(interface)
    now    = time.time()
    result = {}

    for ip, class_id in known_devices.items():
        d_now = down_current.get(class_id, 0)
        u_now = up_current.get(class_id,   0)

        if class_id in _prev_tc:
            prev    = _prev_tc[class_id]
            elapsed = now - prev['time']

            if elapsed > 0:
                # max(0,...) guards against counter reset after tc flush/probe
                down_bps = max(0, (d_now - prev['down_bytes']) / elapsed)
                up_bps   = max(0, (u_now - prev['up_bytes'])   / elapsed)
            else:
                down_bps = up_bps = 0.0
        else:
            # no prev snapshot for this class yet — first cycle, return 0
            down_bps = up_bps = 0.0

        # ── debug — uncomment to diagnose zero enforced ──
        # print(f"[stats] {ip} class={class_id} d_now={d_now} "
        #       f"prev={_prev_tc.get(class_id)} down_bps={down_bps:.0f}")
        # ─────────────────────────────────────────────────

        result[ip] = {
            'down_bps': down_bps,
            'up_bps'  : up_bps,
        }

    return result


# ── tc setup ──────────────────────────────────────────────────

def setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec):
    global last_interface

    last_interface = interface

    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)

    run_cmd(f"tc qdisc del dev {interface} root 2>/dev/null")
    run_cmd(f"tc qdisc add dev {interface} root handle 1: htb default 999 r2q 1")

    down_burst = max(15, total_down_kbits // 8)    # ≥15KB — HTB rejects burst below ~2KB
    run_cmd(f"tc class add dev {interface} parent 1: classid 1:1 htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class add dev {interface} parent 1: classid 1:999 htb rate 100mbit burst 12kb")
    run_cmd(f"tc qdisc add dev {interface} parent 1:999 handle 999: fq_codel")

    run_cmd(f"tc qdisc del dev {interface} ingress 2>/dev/null")
    run_cmd(f"tc qdisc del dev ifb0 root 2>/dev/null")
    run_cmd("modprobe ifb")
    run_cmd("ip link add ifb0 type ifb 2>/dev/null")
    run_cmd("ip link set ifb0 up")
    run_cmd(f"tc qdisc add dev {interface} ingress")
    run_cmd(f"tc filter add dev {interface} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0")

    run_cmd(f"tc qdisc add dev ifb0 root handle 1: htb default 999 r2q 1")

    up_burst = max(15, total_up_kbits // 8)
    run_cmd(f"tc class add dev ifb0 parent 1: classid 1:1 htb rate {total_up_kbits}kbit burst {up_burst}kb")
    run_cmd(f"tc class add dev ifb0 parent 1: classid 1:999 htb rate 100mbit burst 12kb")
    run_cmd(f"tc qdisc add dev ifb0 parent 1:999 handle 999: fq_codel")

    print("tc setup done")


def add_device(device, class_id, interface):

    ip         = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)

    run_cmd(f"tc class add dev {interface} parent 1:1 classid 1:{class_id} htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}: fq_codel target 5ms interval 100ms quantum 1514")
    run_cmd(f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{class_id}")

    run_cmd(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
    run_cmd(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}: fq_codel target 5ms interval 100ms quantum 1514")
    run_cmd(f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 flowid 1:{class_id}")

    print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [new]")


def update_device(device, class_id, interface):

    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)

    run_cmd(f"tc class change dev {interface} parent 1:1 classid 1:{class_id} htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")

    print(f"{device['ip']} → down={down_kbits} Kbps | up={up_kbits} Kbps  [updated]")


def remove_device(ip, class_id, interface):

    run_cmd(f"tc qdisc del dev {interface} handle {class_id}: 2>/dev/null")
    run_cmd(f"tc qdisc del dev ifb0 handle {class_id}: 2>/dev/null")

    run_cmd(f"tc filter del dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 2>/dev/null")
    run_cmd(f"tc filter del dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 2>/dev/null")

    run_cmd(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null")
    run_cmd(f"tc class del dev ifb0 classid 1:{class_id} 2>/dev/null")

    _prev_tc.pop(class_id, None)

    print(f"{ip} → removed from tc  [disconnected]")


def reapply_all_devices():
    """Recreate per-device tc classes/filters after a full tc reset (post-probe)."""
    global _prev_tc

    if not last_interface:
        print("No interface available for tc reapply")
        return

    if len(known_devices) == 0:
        print("No devices to reapply")
        return

    # tc counters reset to zero on tc flush — clear stale prev snapshot
    # otherwise next diff = (new_small - old_large) → negative → clamped to 0
    _prev_tc.clear()

    reapplied = 0
    for ip, class_id in known_devices.items():
        device = last_device_allocations.get(ip)
        if not device:
            continue
        add_device(device, class_id, last_interface)
        reapplied += 1

    print(f"Reapplied {reapplied} device classes after probe")


def enforce(all_devices, interface, download_bytes_per_sec, upload_bytes_per_sec):
    global known_devices, is_setup_done, next_class_id, last_interface

    last_interface = interface

    if not is_setup_done:
        setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec)
        is_setup_done = True

    # update parent class ceiling every cycle in case bandwidth was remeasured
    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)
    down_burst       = max(15, total_down_kbits // 8)
    up_burst         = max(15, total_up_kbits   // 8)

    run_cmd(f"tc class change dev {interface} parent 1: classid 1:1 htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1: classid 1:1 htb rate {total_up_kbits}kbit burst {up_burst}kb")

    # ── Step 1: diff tc counters against END-of-last-cycle snapshot ───────
    # elapsed ≈ 5 seconds of post-shaping bytes — bounded by tc rate ceiling
    # first cycle per device returns 0 — real values from second cycle onward
    actual_stats = read_stats_tc(interface)

    # ── Step 2: remove disconnected devices ───────────────────────────────
    current_ips      = [d['ip'] for d in all_devices]
    disconnected_ips = [ip for ip in known_devices if ip not in current_ips]

    for ip in disconnected_ips:
        class_id = known_devices[ip]
        remove_device(ip, class_id, interface)
        del known_devices[ip]
        last_device_allocations.pop(ip, None)

    # ── Step 3: add new devices / update existing ─────────────────────────
    for device in all_devices:
        ip = device['ip']

        last_device_allocations[ip] = {
            'ip'                       : ip,
            'allocated_bytes_download' : device.get('allocated_bytes_download', 0),
            'allocated_bytes_upload'   : device.get('allocated_bytes_upload', 0),
        }

        if ip not in known_devices:
            known_devices[ip] = next_class_id
            next_class_id     = next_class_id + 1
            add_device(device, known_devices[ip], interface)
        else:
            update_device(device, known_devices[ip], interface)

    # ── Step 4: write enforced throughput onto each device dict ───────────
    for device in all_devices:
        ip    = device['ip']
        stats = actual_stats.get(ip)

        if stats:
            device['enforced_down_bps'] = stats['down_bps']
            device['enforced_up_bps']   = stats['up_bps']
        else:
            device['enforced_down_bps'] = 0.0
            device['enforced_up_bps']   = 0.0

    # ── Step 5: snapshot tc counters at END of this cycle ─────────────────
    # written into _prev_tc — next cycle's read_stats_tc() diffs against this
    # must be LAST so snapshot captures counters after add/update ran
    _snapshot_tc_counters(interface)