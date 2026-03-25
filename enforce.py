import subprocess
import time
import re
import os
import csv
from datetime import datetime

# State management
known_devices = {}           # ip → class_id
is_setup_done = False
next_class_id = 10
last_interface = None
last_device_allocations = {}

# Track filters to avoid duplicates
_filters_added = set()

# tc stats tracking
_prev_tc_down = {}
_prev_tc_up = {}

# iptables measurement
_CHAIN_DOWN = 'BW_MONITOR_DOWN'
_CHAIN_UP = 'BW_MONITOR_UP'
_prev_iptables = {}
_WAN_IFACE = None
_LAN_IFACE = None


def run_cmd(cmd):
    subprocess.run(cmd, shell=True, capture_output=True)


def _run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def _run_tc(cmd, retries=3):
    for attempt in range(retries):
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True
        if attempt < retries - 1:
            time.sleep(0.05)
    return False


def _tc_rules_exist(interface):
    result = subprocess.run(['tc', 'qdisc', 'show', 'dev', interface], capture_output=True, text=True)
    return 'htb' in result.stdout


def _detect_wan_iface():
    for line in _run("ip route show default").splitlines():
        parts = line.split()
        if 'dev' in parts:
            idx = parts.index('dev')
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return 'enp0s25'


def _setup_iptables_chains(lan_iface, wan_iface):
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
    existing = _run(f"iptables -L {_CHAIN_DOWN} -n")
    if ip not in existing:
        run_cmd(f"iptables -A {_CHAIN_DOWN} -d {ip} -j RETURN")
        run_cmd(f"iptables -A {_CHAIN_UP} -s {ip} -j RETURN")


def _remove_iptables_device(ip):
    run_cmd(f"iptables -D {_CHAIN_DOWN} -d {ip} -j RETURN 2>/dev/null")
    run_cmd(f"iptables -D {_CHAIN_UP} -s {ip} -j RETURN 2>/dev/null")
    _prev_iptables.pop(ip, None)


def _parse_iptables_bytes(chain):
    raw = _run(f"iptables -L {chain} -n -v -x")
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
    now = time.time()
    down_current = _parse_iptables_bytes(_CHAIN_DOWN)
    up_current = _parse_iptables_bytes(_CHAIN_UP)
    for ip in set(down_current) | set(up_current):
        _prev_iptables[ip] = {
            'down_bytes': down_current.get(ip, 0),
            'up_bytes': up_current.get(ip, 0),
            'time': now,
        }


def read_demand_iptables():
    now = time.time()
    down_current = _parse_iptables_bytes(_CHAIN_DOWN)
    up_current = _parse_iptables_bytes(_CHAIN_UP)

    raw_down = {}
    raw_up = {}
    all_ips = set(down_current) | set(up_current)

    if not hasattr(read_demand_iptables, '_prev_time'):
        read_demand_iptables._prev_time = now
        elapsed = 5.0
    else:
        elapsed = max(now - read_demand_iptables._prev_time, 0.1)
        read_demand_iptables._prev_time = now

    for ip in all_ips:
        d_now = down_current.get(ip, 0)
        u_now = up_current.get(ip, 0)

        if ip in _prev_iptables:
            prev = _prev_iptables[ip]
            raw_down[ip] = max(0, d_now - prev['down_bytes'])
            raw_up[ip] = max(0, u_now - prev['up_bytes'])
        else:
            raw_down[ip] = raw_up[ip] = 0

        _prev_iptables[ip] = {
            'down_bytes': d_now,
            'up_bytes': u_now,
            'time': now,
        }

    result = {}
    for ip in all_ips:
        result[ip] = {
            'down_bps': raw_down.get(ip, 0) / elapsed,
            'up_bps': raw_up.get(ip, 0) / elapsed,
        }
    return result


def read_enforced_tc_stats():
    global _prev_tc_down, _prev_tc_up, last_interface, known_devices
    
    if not last_interface or not known_devices:
        return {}
    
    # Get class stats
    down_raw = subprocess.run(
        ['tc', '-s', 'class', 'show', 'dev', last_interface],
        capture_output=True, text=True
    ).stdout
    
    up_raw = subprocess.run(
        ['tc', '-s', 'class', 'show', 'dev', 'ifb0'],
        capture_output=True, text=True
    ).stdout
    
    # Parse download bytes
    down_bytes = {}
    current_class = None
    
    for line in down_raw.splitlines():
        m = re.search(r'class htb 1:(\d+)', line)
        if m:
            current_class = int(m.group(1))
            continue
        
        if current_class is not None and 'Sent' in line:
            m = re.search(r'Sent\s+(\d+)\s+bytes', line)
            if m:
                down_bytes[current_class] = int(m.group(1))
                current_class = None
    
    # Parse upload bytes
    up_bytes = {}
    current_class = None
    
    for line in up_raw.splitlines():
        m = re.search(r'class htb 1:(\d+)', line)
        if m:
            current_class = int(m.group(1))
            continue
        
        if current_class is not None and 'Sent' in line:
            m = re.search(r'Sent\s+(\d+)\s+bytes', line)
            if m:
                up_bytes[current_class] = int(m.group(1))
                current_class = None
    
    # Map class_id to IP
    class_to_ip = {v: k for k, v in known_devices.items()}
    now = time.time()
    result = {}
    
    for class_id, ip in class_to_ip.items():
        result[ip] = {'down_bps': 0, 'up_bps': 0}
        
        # Download rate
        if class_id in down_bytes:
            current = down_bytes[class_id]
            if class_id in _prev_tc_down:
                prev_bytes, prev_time = _prev_tc_down[class_id]
                elapsed = max(now - prev_time, 0.1)
                result[ip]['down_bps'] = max(0, current - prev_bytes) / elapsed
            _prev_tc_down[class_id] = (current, now)
        
        # Upload rate
        if class_id in up_bytes:
            current = up_bytes[class_id]
            if class_id in _prev_tc_up:
                prev_bytes, prev_time = _prev_tc_up[class_id]
                elapsed = max(now - prev_time, 0.1)
                result[ip]['up_bps'] = max(0, current - prev_bytes) / elapsed
            _prev_tc_up[class_id] = (current, now)
    
    return result


def setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec):
    global last_interface, _filters_added, _prev_tc_down, _prev_tc_up, known_devices, next_class_id

    last_interface = interface
    _filters_added.clear()
    _prev_tc_down.clear()
    _prev_tc_up.clear()
    known_devices.clear()
    next_class_id = 10

    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits = int((upload_bytes_per_sec * 8) / 1000)

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


def ensure_device_tc_rules(device, class_id, interface):
    """Ensure tc classes and filters exist - ONLY create if missing, never delete"""
    ip = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits = max(1, int((device['allocated_bytes_upload'] * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst = max(15, up_kbits // 8)

    # Check if class exists
    down_check = subprocess.run(f"tc class show dev {interface} | grep -q '1:{class_id}'", shell=True, capture_output=True)
    up_check = subprocess.run(f"tc class show dev ifb0 | grep -q '1:{class_id}'", shell=True, capture_output=True)
    
    # Create class if missing (first time only)
    if down_check.returncode != 0:
        subprocess.run(f"tc class add dev {interface} parent 1:1 classid 1:{class_id} "
                       f"htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb", shell=True)
        subprocess.run(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}0: "
                       f"fq_codel target 5ms interval 100ms quantum 1514", shell=True)
        print(f"  {ip}: Created download class 1:{class_id}")

    if up_check.returncode != 0:
        subprocess.run(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} "
                       f"htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb", shell=True)
        subprocess.run(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}0: "
                       f"fq_codel target 5ms interval 100ms quantum 1514", shell=True)
        print(f"  {ip}: Created upload class 1:{class_id}")

    # Check if filter exists - if not, add it (ONCE, never delete)
    filter_check = subprocess.run(f"tc filter show dev {interface} | grep -q '{ip}/32'", shell=True, capture_output=True)
    
    if filter_check.returncode != 0:
        # Filter doesn't exist, add it
        subprocess.run(f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{class_id}", shell=True)
        subprocess.run(f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 flowid 1:{class_id}", shell=True)
        print(f"  {ip}: Added filter for class 1:{class_id}")
    else:
        print(f"  {ip}: Filter already exists for class 1:{class_id}")

    return True


def update_device_rate(device, class_id, interface):
    """Update ONLY the rate - NEVER touch filters"""
    ip = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits = max(1, int((device['allocated_bytes_upload'] * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst = max(15, up_kbits // 8)

    # Update rates ONLY - NO filter deletion
    subprocess.run(f"tc class change dev {interface} parent 1:1 classid 1:{class_id} "
                   f"htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb 2>/dev/null", shell=True)
    subprocess.run(f"tc class change dev ifb0 parent 1:1 classid 1:{class_id} "
                   f"htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb 2>/dev/null", shell=True)

    print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [rate updated]")


def remove_device(ip, class_id, interface):
    """Remove everything when device disconnects"""
    global _filters_added, _prev_tc_down, _prev_tc_up

    # Delete filter (only when device leaves)
    subprocess.run(f"tc filter del dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 2>/dev/null", shell=True)
    subprocess.run(f"tc filter del dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 2>/dev/null", shell=True)
    
    # Delete qdisc and class
    subprocess.run(f"tc qdisc del dev {interface} handle {class_id}0: 2>/dev/null", shell=True)
    subprocess.run(f"tc qdisc del dev ifb0 handle {class_id}0: 2>/dev/null", shell=True)
    subprocess.run(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null", shell=True)
    subprocess.run(f"tc class del dev ifb0 classid 1:{class_id} 2>/dev/null", shell=True)

    _filters_added.discard(class_id)
    _prev_tc_down.pop(class_id, None)
    _prev_tc_up.pop(class_id, None)
    _remove_iptables_device(ip)
    print(f"{ip} → removed  [disconnected]")


def reapply_all_devices():
    """Called after probe to restore all tc rules."""
    global _filters_added, last_interface, known_devices, last_device_allocations

    if not last_interface:
        return

    _filters_added.clear()

    reapplied = 0
    for ip, class_id in known_devices.items():
        device = last_device_allocations.get(ip)
        if device:
            ensure_device_tc_rules(device, class_id, last_interface)
            reapplied += 1

    print(f"Reapplied {reapplied} device classes after probe")


def enforce(all_devices, interface, download_bytes_per_sec, upload_bytes_per_sec):
    global known_devices, is_setup_done, next_class_id, last_interface
    global _WAN_IFACE, _LAN_IFACE

    last_interface = interface
    rules_exist = _tc_rules_exist(interface)

    if not is_setup_done or not rules_exist:
        print("  [ENFORCE] Setting up tc rules...")
        _LAN_IFACE = interface
        _WAN_IFACE = _detect_wan_iface()

        setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec)
        _setup_iptables_chains(_LAN_IFACE, _WAN_IFACE)
        _seed_iptables_counters()

        is_setup_done = True

    # Update parent ceiling
    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits = int((upload_bytes_per_sec * 8) / 1000)
    down_burst = max(15, total_down_kbits // 8)
    up_burst = max(15, total_up_kbits // 8)

    run_cmd(f"tc class change dev {interface} parent 1: classid 1:1 "
            f"htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1: classid 1:1 "
            f"htb rate {total_up_kbits}kbit burst {up_burst}kb")

    # Read demand and enforced
    demand_stats = read_demand_iptables()
    enforced_stats = read_enforced_tc_stats()

    # Get current IPs from all_devices
    current_ips = set(d['ip'] for d in all_devices)

    # Remove devices that are no longer connected
    for ip in list(known_devices.keys()):
        if ip not in current_ips:
            class_id = known_devices[ip]
            remove_device(ip, class_id, interface)
            del known_devices[ip]
            last_device_allocations.pop(ip, None)

    # Add or update devices
    for device in all_devices:
        ip = device['ip']
        last_device_allocations[ip] = {
            'ip': ip,
            'allocated_bytes_download': device.get('allocated_bytes_download', 0),
            'allocated_bytes_upload': device.get('allocated_bytes_upload', 0),
        }

        if ip not in known_devices:
            # New device - assign unique class_id
            class_id = next_class_id
            known_devices[ip] = class_id
            next_class_id += 1
            print(f"{ip} → NEW DEVICE, assigning class 1:{class_id}")
            ensure_device_tc_rules(device, class_id, interface)
            _add_iptables_device(ip)
        else:
            class_id = known_devices[ip]
            ensure_device_tc_rules(device, class_id, interface)
            update_device_rate(device, class_id, interface)

    # Write stats onto each device dict
    for device in all_devices:
        ip = device['ip']
        
        demand = demand_stats.get(ip)
        if demand:
            device['demand_down_bps'] = demand['down_bps']
            device['demand_up_bps'] = demand['up_bps']
        else:
            device['demand_down_bps'] = 0.0
            device['demand_up_bps'] = 0.0

        enforced = enforced_stats.get(ip)
        if enforced:
            device['enforced_down_bps'] = enforced['down_bps']
            device['enforced_up_bps'] = enforced['up_bps']
        else:
            device['enforced_down_bps'] = 0.0
            device['enforced_up_bps'] = 0.0

    # Save CSV
    file_path = "result/allocate_vs_demand_vs_enforced.csv"
    file_exists = os.path.isfile(file_path)
    fieldnames = ["timestamp", "ip", "up_bytes_per_sec", "down_bytes_per_sec",
                  "protocol", "priority", "demand_down_bps", "demand_up_bps",
                  "allocated_bytes_download", "allocated_bytes_upload",
                  "enforced_down_bps", "enforced_up_bps"]
    os.makedirs("result", exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(file_path, mode="a" if file_exists else "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        for d in all_devices:
            row = {
                "timestamp": timestamp,
                "ip": d.get("ip", ""),
                "up_bytes_per_sec": d.get("up_bytes_per_sec", 0),
                "down_bytes_per_sec": d.get("down_bytes_per_sec", 0),
                "protocol": d.get("protocol", "UNKNOWN"),
                "priority": d.get("priority", 1),
                "demand_down_bps": d.get("demand_down_bps", 0),
                "demand_up_bps": d.get("demand_up_bps", 0),
                "allocated_bytes_download": d.get("allocated_bytes_download", 0),
                "allocated_bytes_upload": d.get("allocated_bytes_upload", 0),
                "enforced_down_bps": d.get("enforced_down_bps", 0),
                "enforced_up_bps": d.get("enforced_up_bps", 0),
            }
            writer.writerow(row)

    # Print summary
    total_demand_down = sum(d.get('demand_down_bps', 0) for d in all_devices)
    total_demand_up = sum(d.get('demand_up_bps', 0) for d in all_devices)
    total_enforced_down = sum(d.get('enforced_down_bps', 0) for d in all_devices)
    total_enforced_up = sum(d.get('enforced_up_bps', 0) for d in all_devices)

    print(f"\n  Demand (iptables): {total_demand_down * 8 / 1e6:.2f} Mbps down, "
          f"{total_demand_up * 8 / 1e6:.2f} Mbps up")
    print(f"  Enforced (tc): {total_enforced_down * 8 / 1e6:.2f} Mbps down, "
          f"{total_enforced_up * 8 / 1e6:.2f} Mbps up")