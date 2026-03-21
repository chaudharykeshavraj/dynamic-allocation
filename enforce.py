import subprocess
import time
import re

known_devices           = {}
is_setup_done           = False
next_class_id           = 10
last_interface          = None
last_device_allocations = {}
_prev_tc                = {}

# track which class_ids have filters already added
# KEY FIX: never add duplicate filters
_filters_added = set()   # set of class_ids that already have filters


def run_cmd(cmd):
    subprocess.run(cmd, shell=True, capture_output=True)


def _run(cmd):
    return subprocess.run(cmd, shell=True,
                          capture_output=True, text=True).stdout


def _run_tc(cmd, retries=3):
    for attempt in range(retries):
        result = subprocess.run(cmd, shell=True,
                                capture_output=True, text=True)
        if result.returncode == 0:
            return True
        if attempt < retries - 1:
            time.sleep(0.05)
    print(f"  [TC WARN] Failed: {cmd.strip()}")
    if result.stderr:
        print(f"  [TC WARN] {result.stderr.strip()}")
    return False


def _tc_rules_exist(interface):
    result = subprocess.run(
        ['tc', 'qdisc', 'show', 'dev', interface],
        capture_output=True, text=True
    )
    return 'htb' in result.stdout


def _ip_to_hex(ip):
    """Convert dotted IP to hex for tc filter matching."""
    parts = ip.split('.')
    return ''.join(f'{int(p):02x}' for p in parts)


def _parse_tc_bytes(tc_output):
    counters   = {}
    current_id = None
    SKIP_IDS   = {1, 999}

    for line in tc_output.splitlines():
        m = re.search(r'class htb 1:(\d+)', line)
        if m:
            cid = int(m.group(1))
            if cid in SKIP_IDS:
                current_id = None
                continue
            current_id = cid
            continue

        if 'class fq_codel' in line:
            current_id = None
            continue

        if current_id is not None:
            m = re.search(r'Sent (\d+) bytes', line)
            if m:
                counters[current_id] = int(m.group(1))
                current_id = None

    return counters


def _read_tc_bytes_now(interface):
    down_raw = _run(f"tc -s class show dev {interface}")
    up_raw   = _run("tc -s class show dev ifb0")
    return _parse_tc_bytes(down_raw), _parse_tc_bytes(up_raw)


def _snapshot_tc_counters(interface):
    down_counters, up_counters = _read_tc_bytes_now(interface)
    now = time.time()
    for ip, class_id in known_devices.items():
        _prev_tc[class_id] = {
            'down_bytes': down_counters.get(class_id, 0),
            'up_bytes'  : up_counters.get(class_id,   0),
            'time'      : now,
        }


def read_stats_tc(interface):
    down_current, up_current = _read_tc_bytes_now(interface)
    now    = time.time()
    result = {}

    for ip, class_id in known_devices.items():
        d_now = down_current.get(class_id, 0)
        u_now = up_current.get(class_id,   0)

        if class_id in _prev_tc:
            prev    = _prev_tc[class_id]
            elapsed = now - prev['time']
            if elapsed > 0.1:
                down_bps = max(0, (d_now - prev['down_bytes']) / elapsed)
                up_bps   = max(0, (u_now - prev['up_bytes'])   / elapsed)
            else:
                down_bps = up_bps = 0.0
        else:
            down_bps = up_bps = 0.0

        result[ip] = {'down_bps': down_bps, 'up_bps': up_bps}

    return result


def setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec):
    global last_interface, _filters_added

    last_interface = interface

    # clear filter tracking — fresh setup means all filters gone
    _filters_added.clear()

    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)

    run_cmd(f"tc qdisc del dev {interface} root 2>/dev/null")
    run_cmd(f"tc qdisc add dev {interface} root handle 1: htb default 999 r2q 1")

    down_burst = max(15, total_down_kbits // 8)
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
    """
    Add HTB class + fq_codel + filter for one device.
    FIX: track _filters_added set to NEVER add duplicate filters.
    Duplicate filters were accumulating every cycle causing hundreds
    of redundant rules and unpredictable packet matching.
    """
    global _filters_added

    ip         = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)

    # download class + qdisc
    _run_tc(f"tc class add dev {interface} parent 1:1 classid 1:{class_id} "
            f"htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    _run_tc(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}0: "
            f"fq_codel target 5ms interval 100ms quantum 1514")

    # upload class + qdisc
    _run_tc(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} "
            f"htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
    _run_tc(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}0: "
            f"fq_codel target 5ms interval 100ms quantum 1514")

    # KEY FIX: only add filter ONCE per class_id
    # tc stores IP as hex in kernel — dotted decimal grep never matches
    # so old check always returned empty → added filter every cycle
    # now we use Python set to track — reliable and instant
    if class_id not in _filters_added:
        ok_down = _run_tc(
            f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 "
            f"u32 match ip dst {ip}/32 flowid 1:{class_id}"
        )
        ok_up = _run_tc(
            f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 "
            f"u32 match ip src {ip}/32 flowid 1:{class_id}"
        )
        if ok_down and ok_up:
            _filters_added.add(class_id)
            print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [new + filter]")
        else:
            print(f"{ip} → [WARN] filter failed! device may be unlimited")
    else:
        print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [new]")


def update_device(device, class_id, interface):
    """
    Update HTB rate only — never touch filters.
    FIX: removed the broken filter-check-and-readd logic.
    That logic grepped dotted IP against hex tc output → always false
    → added duplicate filter every single cycle.
    Filters are managed only by add_device() and reapply_all_devices().
    """
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)

    _run_tc(f"tc class change dev {interface} parent 1:1 classid 1:{class_id} "
            f"htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    _run_tc(f"tc class change dev ifb0 parent 1:1 classid 1:{class_id} "
            f"htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")

    print(f"{device['ip']} → down={down_kbits} Kbps | up={up_kbits} Kbps  [updated]")


def remove_device(ip, class_id, interface):
    global _filters_added

    run_cmd(f"tc qdisc del dev {interface} handle {class_id}0: 2>/dev/null")
    run_cmd(f"tc qdisc del dev ifb0 handle {class_id}0: 2>/dev/null")
    run_cmd(f"tc filter del dev {interface} protocol ip parent 1:0 prio 1 "
            f"u32 match ip dst {ip}/32 2>/dev/null")
    run_cmd(f"tc filter del dev ifb0 protocol ip parent 1:0 prio 1 "
            f"u32 match ip src {ip}/32 2>/dev/null")
    run_cmd(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null")
    run_cmd(f"tc class del dev ifb0 classid 1:{class_id} 2>/dev/null")

    _prev_tc.pop(class_id, None)
    _filters_added.discard(class_id)
    print(f"{ip} → removed  [disconnected]")


def reapply_all_devices():
    """Called after probe to restore all tc rules."""
    global _prev_tc, _filters_added

    if not last_interface:
        return

    # tc counters reset on flush
    _prev_tc.clear()
    # filters also gone after tc flush — reset tracking
    _filters_added.clear()

    reapplied = 0
    for ip, class_id in known_devices.items():
        device = last_device_allocations.get(ip)
        if device:
            add_device(device, class_id, last_interface)
            reapplied += 1

    print(f"Reapplied {reapplied} device classes after probe")


def enforce(all_devices, interface, download_bytes_per_sec, upload_bytes_per_sec):
    global known_devices, is_setup_done, next_class_id, last_interface

    last_interface = interface
    rules_exist    = _tc_rules_exist(interface)

    if not is_setup_done or not rules_exist:
        print("  [ENFORCE] Setting up tc rules...")
        setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec)
        is_setup_done = True

        for ip, class_id in known_devices.items():
            device = last_device_allocations.get(ip)
            if device:
                add_device(device, class_id, interface)

        _snapshot_tc_counters(interface)

    # update parent ceiling
    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)
    down_burst        = max(15, total_down_kbits // 8)
    up_burst          = max(15, total_up_kbits   // 8)

    run_cmd(f"tc class change dev {interface} parent 1: classid 1:1 "
            f"htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1: classid 1:1 "
            f"htb rate {total_up_kbits}kbit burst {up_burst}kb")

    actual_stats = read_stats_tc(interface)

    # remove disconnected
    current_ips      = [d['ip'] for d in all_devices]
    disconnected_ips = [ip for ip in list(known_devices.keys())
                        if ip not in current_ips]
    for ip in disconnected_ips:
        class_id = known_devices[ip]
        remove_device(ip, class_id, interface)
        del known_devices[ip]
        last_device_allocations.pop(ip, None)

    # add new / update existing
    for device in all_devices:
        ip = device['ip']
        last_device_allocations[ip] = {
            'ip'                       : ip,
            'allocated_bytes_download' : device.get('allocated_bytes_download', 0),
            'allocated_bytes_upload'   : device.get('allocated_bytes_upload',   0),
        }
        if ip not in known_devices:
            known_devices[ip] = next_class_id
            next_class_id    += 1
            add_device(device, known_devices[ip], interface)
        else:
            update_device(device, known_devices[ip], interface)

    # write enforced stats
    for device in all_devices:
        stats = actual_stats.get(device['ip'])
        if stats:
            device['enforced_down_bps'] = stats['down_bps']
            device['enforced_up_bps']   = stats['up_bps']
        else:
            device['enforced_down_bps'] = 0.0
            device['enforced_up_bps']   = 0.0

    _snapshot_tc_counters(interface)