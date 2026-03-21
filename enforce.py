import subprocess
import time
import re
 
known_devices           = {}
is_setup_done           = False
next_class_id           = 10
last_interface          = None
last_device_allocations = {}
_prev_tc                = {}
 
 
def run_cmd(cmd):
    """Silent run — used for cleanup commands where failure is expected."""
    subprocess.run(cmd, shell=True, capture_output=True)
 
 
def _run(cmd):
    return subprocess.run(cmd, shell=True,
                          capture_output=True, text=True).stdout
 
 
def _run_tc(cmd, retries=3):
    """
    Run a tc command with retries and error reporting.
    FIX: old run_cmd silently ignored errors causing missing filters.
    Filters that fail silently → device goes to default 1:999 = unlimited!
    Now retries up to 3 times with small delay between attempts.
    """
    for attempt in range(retries):
        result = subprocess.run(cmd, shell=True,
                                capture_output=True, text=True)
        if result.returncode == 0:
            return True
        if attempt < retries - 1:
            time.sleep(0.05)   # 50ms before retry
    print(f"  [TC WARN] Failed after {retries} attempts: {cmd.strip()}")
    if result.stderr:
        print(f"  [TC WARN] {result.stderr.strip()}")
    return False
 
 
def _tc_rules_exist(interface):
    result = subprocess.run(
        ['tc', 'qdisc', 'show', 'dev', interface],
        capture_output=True, text=True
    )
    return 'htb' in result.stdout
 
 
def _filter_exists(interface, ip, class_id):
    """
    Check if a filter already exists for this IP.
    Prevents duplicate filter errors on reapply.
    """
    result = subprocess.run(
        f"tc filter show dev {interface} | grep -c '{ip}'",
        shell=True, capture_output=True, text=True
    )
    try:
        return int(result.stdout.strip()) > 0
    except Exception:
        return False
 
 
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
    global last_interface
    last_interface = interface
 
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
    FIX: Use _run_tc() with retries for all tc commands.
    Especially critical for filter commands — if filter is missing,
    device goes to default class 1:999 = 100 Mbit = unlimited!
    Also verify filter was actually added after each attempt.
    """
    ip         = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)
 
    # ── download — wlp3s0 egress ─────────────────────────────
    _run_tc(f"tc class add dev {interface} parent 1:1 classid 1:{class_id} "
            f"htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
 
    _run_tc(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}0: "
            f"fq_codel target 5ms interval 100ms quantum 1514")
 
    # FIX: filter add with retry — this is the critical command
    # without this filter, all packets go to default 1:999 = unlimited!
    filter_ok = _run_tc(
        f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 "
        f"u32 match ip dst {ip}/32 flowid 1:{class_id}"
    )
    if not filter_ok:
        print(f"  [CRITICAL] Download filter failed for {ip}! Device will be unlimited!")
 
    # ── upload — ifb0 egress ──────────────────────────────────
    _run_tc(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} "
            f"htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
 
    _run_tc(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}0: "
            f"fq_codel target 5ms interval 100ms quantum 1514")
 
    # FIX: upload filter with retry
    filter_up_ok = _run_tc(
        f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 "
        f"u32 match ip src {ip}/32 flowid 1:{class_id}"
    )
    if not filter_up_ok:
        print(f"  [CRITICAL] Upload filter failed for {ip}!")
 
    print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [new]")
 
 
def update_device(device, class_id, interface):
    """
    FIX: Use _run_tc() for class change.
    Also verify filter still exists — re-add if missing.
    This handles cases where tc rules were partially reset.
    """
    ip         = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)
 
    _run_tc(f"tc class change dev {interface} parent 1:1 classid 1:{class_id} "
            f"htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
 
    _run_tc(f"tc class change dev ifb0 parent 1:1 classid 1:{class_id} "
            f"htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
 
    # FIX: verify filter still exists — re-add if gone
    # This can happen after probe or partial tc reset
    down_filter = _run(
        f"tc filter show dev {interface} | grep '{ip}'"
    ).strip()
    if not down_filter:
        print(f"  [WARN] Download filter missing for {ip}, re-adding...")
        _run_tc(
            f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 "
            f"u32 match ip dst {ip}/32 flowid 1:{class_id}"
        )
 
    up_filter = _run(
        f"tc filter show dev ifb0 | grep '{ip}'"
    ).strip()
    if not up_filter:
        print(f"  [WARN] Upload filter missing for {ip}, re-adding...")
        _run_tc(
            f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 "
            f"u32 match ip src {ip}/32 flowid 1:{class_id}"
        )
 
    print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [updated]")
 
 
def remove_device(ip, class_id, interface):
    run_cmd(f"tc qdisc del dev {interface} handle {class_id}0: 2>/dev/null")
    run_cmd(f"tc qdisc del dev ifb0 handle {class_id}0: 2>/dev/null")
    run_cmd(f"tc filter del dev {interface} protocol ip parent 1:0 prio 1 "
            f"u32 match ip dst {ip}/32 2>/dev/null")
    run_cmd(f"tc filter del dev ifb0 protocol ip parent 1:0 prio 1 "
            f"u32 match ip src {ip}/32 2>/dev/null")
    run_cmd(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null")
    run_cmd(f"tc class del dev ifb0 classid 1:{class_id} 2>/dev/null")
    _prev_tc.pop(class_id, None)
    print(f"{ip} → removed  [disconnected]")
 
 
def reapply_all_devices():
    global _prev_tc
 
    if not last_interface:
        return
 
    # tc counters reset on flush — clear stale snapshots
    _prev_tc.clear()
 
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
 
    rules_exist = _tc_rules_exist(interface)
 
    if not is_setup_done or not rules_exist:
        print("  [ENFORCE] Setting up tc rules...")
        setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec)
        is_setup_done = True
 
        for ip, class_id in known_devices.items():
            device = last_device_allocations.get(ip)
            if device:
                add_device(device, class_id, interface)
 
        _snapshot_tc_counters(interface)
 
    # update parent class ceiling every cycle
    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)
    down_burst        = max(15, total_down_kbits // 8)
    up_burst          = max(15, total_up_kbits   // 8)
 
    run_cmd(f"tc class change dev {interface} parent 1: classid 1:1 "
            f"htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1: classid 1:1 "
            f"htb rate {total_up_kbits}kbit burst {up_burst}kb")
 
    actual_stats = read_stats_tc(interface)
 
    # remove disconnected devices
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
 
    # write enforced throughput onto device dicts
    for device in all_devices:
        stats = actual_stats.get(device['ip'])
        if stats:
            device['enforced_down_bps'] = stats['down_bps']
            device['enforced_up_bps']   = stats['up_bps']
        else:
            device['enforced_down_bps'] = 0.0
            device['enforced_up_bps']   = 0.0
 
    _snapshot_tc_counters(interface)
 