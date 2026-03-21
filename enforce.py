import subprocess
import time
import re
import os
import csv
from datetime import datetime

known_devices           = {}
is_setup_done           = False
next_class_id           = 10
last_interface          = None
last_device_allocations = {}

# track which class_ids have filters already added
# KEY FIX: never add duplicate filters
_filters_added = set()   # set of class_ids that already have filters

# ── iptables measurement state ────────────────────────────────
# replaces tc byte counters — iptables is independent of tc HTB
# tc Sent bytes only count traffic that hits the leaf class
# iptables FORWARD counts every packet regardless of tc class matching
_CHAIN_DOWN    = 'BW_MONITOR_DOWN'
_CHAIN_UP      = 'BW_MONITOR_UP'
_prev_iptables = {}   # ip → { down_bytes, up_bytes, time }
_WAN_IFACE     = None
_LAN_IFACE     = None


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
    parts = ip.split('.')
    return ''.join(f'{int(p):02x}' for p in parts)


# ── iptables measurement functions ────────────────────────────

def _detect_wan_iface():
    """Detect WAN interface from default route."""
    for line in _run("ip route show default").splitlines():
        parts = line.split()
        if 'dev' in parts:
            idx = parts.index('dev')
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return 'enp0s25'


def _setup_iptables_chains(lan_iface, wan_iface):
    """
    Create counting-only iptables chains.
    Rules end in RETURN — traffic never blocked or modified.
    FORWARD jump scoped by direction:
      DOWN: wan→lan  (internet → device = download)
      UP:   lan→wan  (device → internet = upload)
    """
    for chain in (_CHAIN_DOWN, _CHAIN_UP):
        run_cmd(f"iptables -F {chain} 2>/dev/null")
        run_cmd(f"iptables -X {chain} 2>/dev/null")
        run_cmd(f"iptables -N {chain}")

    fwd = _run("iptables -L FORWARD --line-numbers -n")
    if _CHAIN_DOWN not in fwd:
        run_cmd(f"iptables -I FORWARD 1 -i {wan_iface} -o {lan_iface} -j {_CHAIN_DOWN}")
    if _CHAIN_UP not in fwd:
        run_cmd(f"iptables -I FORWARD 2 -i {lan_iface} -o {wan_iface} -j {_CHAIN_UP}")

    print(f"  iptables chains ready (WAN={wan_iface} LAN={lan_iface})")


def _add_iptables_device(ip):
    """Add per-IP counting rules. RETURN — never blocks."""
    existing = _run(f"iptables -L {_CHAIN_DOWN} -n")
    if ip not in existing:
        run_cmd(f"iptables -A {_CHAIN_DOWN} -d {ip} -j RETURN")
        run_cmd(f"iptables -A {_CHAIN_UP}   -s {ip} -j RETURN")


def _remove_iptables_device(ip):
    """Remove per-IP counting rules on disconnect."""
    run_cmd(f"iptables -D {_CHAIN_DOWN} -d {ip} -j RETURN 2>/dev/null")
    run_cmd(f"iptables -D {_CHAIN_UP}   -s {ip} -j RETURN 2>/dev/null")
    _prev_iptables.pop(ip, None)


def _parse_iptables_bytes(chain):
    """
    Parse iptables -L <chain> -n -v -x output.
    -x gives exact integers — without it values show as 186M causing ValueError.
    Returns dict: ip → cumulative_bytes.
    """
    raw    = _run(f"iptables -L {chain} -n -v -x")
    result = {}
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        try:
            byte_count = int(parts[1])
        except ValueError:
            continue
        ip_field = parts[8] if chain == _CHAIN_DOWN else parts[7]
        if ip_field == '0.0.0.0/0' or '/' in ip_field:
            continue
        if ip_field.startswith('192.168.'):
            result[ip_field] = byte_count
    return result


def _seed_iptables_counters():
    """
    Seed baseline counters right after chain setup.
    So cycle 1 already has a real diff window instead of returning 0.
    """
    now          = time.time()
    down_current = _parse_iptables_bytes(_CHAIN_DOWN)
    up_current   = _parse_iptables_bytes(_CHAIN_UP)
    for ip in set(down_current) | set(up_current):
        _prev_iptables[ip] = {
            'down_bytes': down_current.get(ip, 0),
            'up_bytes'  : up_current.get(ip,   0),
            'time'      : now,
        }


def _read_proc_net_dev(iface):
    """
    Read cumulative TX bytes for an interface from /proc/net/dev.
    From AP perspective: wlp3s0 TX = bytes sent TO devices = download.
                         wlp3s0 RX = bytes received FROM devices = upload.
    Returns (download_bytes, upload_bytes).
    """
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                if iface + ':' in line:
                    parts    = line.split()
                    rx_bytes = int(parts[1])   # from devices = upload
                    tx_bytes = int(parts[9])   # to devices   = download
                    return tx_bytes, rx_bytes  # (download, upload)
    except Exception:
        pass
    return 0, 0


def read_stats_iptables():
    """
    Measure real per-device throughput using iptables ratios anchored to
    /proc/net/dev interface ground truth.

    Why anchoring is needed:
      iptables FORWARD can double-count when ifb0 redirect causes packets
      to traverse FORWARD twice — once on wlp3s0→enp0s25 and once via ifb0.
      This causes enforced > pool.

    Fix:
      Step 1 — diff iptables counters per IP → gives correct per-device RATIOS
               even if absolute values are inflated by double-counting.
      Step 2 — read /proc/net/dev TX bytes → true total bytes that left the
               interface this interval (kernel hardware counter, never double-counts).
      Step 3 — scale each device's raw delta by (proc_total / iptables_total)
               so per-device values sum to the real interface throughput.
    """
    now          = time.time()
    down_current = _parse_iptables_bytes(_CHAIN_DOWN)
    up_current   = _parse_iptables_bytes(_CHAIN_UP)

    # Step 1: raw byte deltas per IP from iptables
    raw_down = {}
    raw_up   = {}
    all_ips  = set(down_current) | set(up_current)

    for ip in all_ips:
        d_now = down_current.get(ip, 0)
        u_now = up_current.get(ip,   0)

        if ip in _prev_iptables:
            prev    = _prev_iptables[ip]
            elapsed = now - prev['time']
            if elapsed > 0:
                raw_down[ip] = max(0, d_now - prev['down_bytes'])
                raw_up[ip]   = max(0, u_now - prev['up_bytes'])
            else:
                raw_down[ip] = raw_up[ip] = 0
        else:
            raw_down[ip] = raw_up[ip] = 0

        _prev_iptables[ip] = {
            'down_bytes': d_now,
            'up_bytes'  : u_now,
            'time'      : now,
        }

    # Step 2: true interface totals from proc (ground truth, no double-counting)
    proc_down_bytes, proc_up_bytes = _read_proc_net_dev(_LAN_IFACE or 'wlp3s0')

    # compute elapsed from prev proc reading
    if not hasattr(read_stats_iptables, '_prev_proc'):
        read_stats_iptables._prev_proc = {
            'down': proc_down_bytes, 'up': proc_up_bytes, 'time': now
        }
        elapsed_proc = 5.0
        true_down_bytes = sum(raw_down.values())
        true_up_bytes   = sum(raw_up.values())
    else:
        p       = read_stats_iptables._prev_proc
        elapsed_proc    = max(now - p['time'], 0.1)
        true_down_bytes = max(0, proc_down_bytes - p['down'])
        true_up_bytes   = max(0, proc_up_bytes   - p['up'])
        read_stats_iptables._prev_proc = {
            'down': proc_down_bytes, 'up': proc_up_bytes, 'time': now
        }

    # Step 3: scale iptables raw deltas to match proc ground truth
    raw_total_down = sum(raw_down.values())
    raw_total_up   = sum(raw_up.values())

    result = {}
    for ip in all_ips:
        if raw_total_down > 0 and true_down_bytes > 0:
            scaled_down = raw_down.get(ip, 0) * (true_down_bytes / raw_total_down)
        else:
            scaled_down = raw_down.get(ip, 0)

        if raw_total_up > 0 and true_up_bytes > 0:
            scaled_up = raw_up.get(ip, 0) * (true_up_bytes / raw_total_up)
        else:
            scaled_up = raw_up.get(ip, 0)

        result[ip] = {
            'down_bps': scaled_down / elapsed_proc,
            'up_bps'  : scaled_up   / elapsed_proc,
        }

    return result


# ── tc setup — UNCHANGED ──────────────────────────────────────

def setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec):
    global last_interface, _filters_added

    last_interface = interface
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
    global _filters_added

    ip         = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)

    _run_tc(f"tc class add dev {interface} parent 1:1 classid 1:{class_id} "
            f"htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    _run_tc(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}0: "
            f"fq_codel target 5ms interval 100ms quantum 1514")

    _run_tc(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} "
            f"htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
    _run_tc(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}0: "
            f"fq_codel target 5ms interval 100ms quantum 1514")

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

    # add iptables counting rule for this device
    _add_iptables_device(ip)


def update_device(device, class_id, interface):
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

    _filters_added.discard(class_id)
    _remove_iptables_device(ip)   # removes iptables rule + clears _prev_iptables
    print(f"{ip} → removed  [disconnected]")


def reapply_all_devices():
    """Called after probe to restore all tc rules."""
    global _filters_added

    if not last_interface:
        return

    _filters_added.clear()
    # iptables counters survive tc reset — do NOT clear _prev_iptables

    reapplied = 0
    for ip, class_id in known_devices.items():
        device = last_device_allocations.get(ip)
        if device:
            add_device(device, class_id, last_interface)
            reapplied += 1

    print(f"Reapplied {reapplied} device classes after probe")


def enforce(all_devices, interface, download_bytes_per_sec, upload_bytes_per_sec):
    global known_devices, is_setup_done, next_class_id, last_interface
    global _WAN_IFACE, _LAN_IFACE

    last_interface = interface
    rules_exist    = _tc_rules_exist(interface)

    if not is_setup_done or not rules_exist:
        print("  [ENFORCE] Setting up tc rules...")

        _LAN_IFACE = interface
        _WAN_IFACE = _detect_wan_iface()

        setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec)
        _setup_iptables_chains(_LAN_IFACE, _WAN_IFACE)
        _seed_iptables_counters()   # seed baseline so cycle 1 gives real values

        is_setup_done = True

        for ip, class_id in known_devices.items():
            device = last_device_allocations.get(ip)
            if device:
                add_device(device, class_id, interface)

    # update parent ceiling
    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)
    down_burst        = max(15, total_down_kbits // 8)
    up_burst          = max(15, total_up_kbits   // 8)

    run_cmd(f"tc class change dev {interface} parent 1: classid 1:1 "
            f"htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1: classid 1:1 "
            f"htb rate {total_up_kbits}kbit burst {up_burst}kb")

    # read actual throughput BEFORE add/update so elapsed = full interval
    actual_stats = read_stats_iptables()

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

    # write enforced stats onto each device dict
    for device in all_devices:
        ip    = device['ip']
        stats = actual_stats.get(ip)
        if stats:
            device['enforced_down_bps'] = stats['down_bps']
            device['enforced_up_bps']   = stats['up_bps']
        else:
            device['enforced_down_bps'] = 0.0
            device['enforced_up_bps']   = 0.0

    # save CSV
    file_path   = "result/allocate_vs_demand_vs_enforced.csv"
    file_exists = os.path.isfile(file_path)
    fieldnames  = ["timestamp","ip","up_bytes_per_sec","down_bytes_per_sec",
                   "protocol","priority","allocated_bytes_download","allocated_bytes_upload", "enforced_down_bps","enforced_up_bps"]
    os.makedirs("result", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(file_path, mode="a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        for d in all_devices:
            row = d.copy()
            row["timestamp"] = timestamp
            writer.writerow(row)