import subprocess
import time
import re

known_devices  = {}     # ip → class_id
is_setup_done  = False
next_class_id  = 10     # global counter, never reuses ids

# prev_counters stores last tc byte reading per class_id
# so we can difference to readings to get bytes/sec
prev_counters = {}     # ip → (down_bytes, up_bytes)

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)

def setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec):

    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)

    run_cmd(f"tc qdisc del dev {interface} root 2>/dev/null")
    run_cmd(f"tc qdisc add dev {interface} root handle 1: htb default 999 r2q 1")

    down_burst = max(15, total_down_kbits // 8)     # burst should be at least 1 packet (15KB) to avoid excessive packet drops, HTB rejects burst below ~2KB
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
    run_cmd(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}: fq_codel target 5ms interval 100ms quantum 1514")    # changed  handle {class_id}0: to handle {class_id}:
    run_cmd(f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{class_id}")

    run_cmd(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
    run_cmd(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}: fq_codel target 5ms interval 100ms quantum 1514")    # changed  handle {class_id}0: to handle {class_id}:
    run_cmd(f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 flowid 1:{class_id}")

    print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [new]")

def update_device(device, class_id, interface):

    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(15, down_kbits // 8)
    up_burst   = max(15, up_kbits   // 8)

    # class change → smooth update, no traffic interruption
    run_cmd(f"tc class change dev {interface} parent 1:1 classid 1:{class_id} htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")

    print(f"{device['ip']} → down={down_kbits} Kbps | up={up_kbits} Kbps  [updated]")

def remove_device(ip, class_id, interface):
    # delete this device's class from both interfaces
    # filters attached to class are automatically removed too

    # delete leaf qdisc — handle matches class_id: (fix 1 applied here too)
    run_cmd(f"tc qdisc del dev {interface} handle {class_id}: 2>/dev/null")
    run_cmd(f"tc qdisc del dev ifb0 handle {class_id}: 2>/dev/null")

    # delete filter matched to this ip
    run_cmd(f"tc filter del dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 2>/dev/null")
    run_cmd(f"tc filter del dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 2>/dev/null")

    # now safely deleting the class
    run_cmd(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null")
    run_cmd(f"tc class del dev ifb0 classid 1:{class_id} 2>/dev/null")

    print(f"{ip} → removed from tc  [disconnected]")


# read_stats() reads tc -s class show output and returns actual bytes/sec flowing per device based on kernel counters
def read_stats(interface):
    global prev_counters

    now = time.time()
    
    def parse_bytes(tc_output):
        # parse tc -s output and return { class_id_int: cumulative_bytes }
        counters    = {}
        current_id  = None

        for line in tc_output.splitlines():
            # match class header — extract minor id after 1:
            # e.g. 'class htb 1:10' → class_id = 10
            class_match = re.search(r'class htb 1:(\d+)', line)
            if class_match:
                current_id = int(class_match.group(1))

            # match Sent bytes line under current class
            if current_id is not None:
                sent_match = re.search(r'Sent (\d+) bytes', line)
                if sent_match:
                    counters[current_id] = int(sent_match.group(1))
                    current_id = None   # reset after reading — one Sent line per class

        return counters

    # run tc -s on both interfaces — wlp3s0 = download, ifb0 = upload
    down_raw = subprocess.run(
        f"tc -s class show dev {interface}",
        shell=True, capture_output=True, text=True
    ).stdout

    up_raw = subprocess.run(
        "tc -s class show dev ifb0",
        shell=True, capture_output=True, text=True
    ).stdout

    down_current = parse_bytes(down_raw)
    up_current   = parse_bytes(up_raw)

    # ── debug — I can see the upload/download bytes for each class here ──
    # print(f"[debug] down_current = {down_current}")
    # print(f"[debug] up_current   = {up_current}")
    # print(f"[debug] known_devices = {known_devices}")
    # print(f"[debug] active_class_ids = {set(known_devices.values())}")
    # ─────────────────────────────────

    # only compute stats for actively tracked class_ids
    active_class_ids = set(known_devices.values())
    result           = {}

    for class_id in active_class_ids:

        down_bytes_now = down_current.get(class_id, 0)
        up_bytes_now   = up_current.get(class_id,   0)

        if class_id in prev_counters:
            prev    = prev_counters[class_id]
            elapsed = now - prev['time']

            if elapsed > 0:
                # bytes/sec = delta bytes / elapsed seconds
                # max(0,...) guards against counter reset on tc flush
                down_bps = max(0, (down_bytes_now - prev['down']) / elapsed)
                up_bps   = max(0, (up_bytes_now   - prev['up'])   / elapsed)
            else:
                down_bps = 0.0
                up_bps   = 0.0
        else:
            # first reading for this class — no previous to diff against
            # will show 0 on first cycle, real value from second cycle onward
            down_bps = 0.0
            up_bps   = 0.0

        # store current as new previous for next cycle
        prev_counters[class_id] = {
            'down': down_bytes_now,
            'up'  : up_bytes_now,
            'time': now,
        }

        result[class_id] = {
            'down_bps': down_bps,
            'up_bps'  : up_bps,
        }

    return result

def enforce(all_devices, interface, download_bytes_per_sec, upload_bytes_per_sec):
    global known_devices, is_setup_done, next_class_id

    # setup runs only once
    if not is_setup_done:
        setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec)
        is_setup_done = True

    # update parent class rate every cycle
    # in case total bandwidth changed (e.g remeasured)
    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)
    down_burst       = max(15, total_down_kbits // 8)
    up_burst         = max(15, total_up_kbits   // 8)

    run_cmd(f"tc class change dev {interface} parent 1: classid 1:1 htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1: classid 1:1 htb rate {total_up_kbits}kbit burst {up_burst}kb")

    # find disconnected devices
    # compare known_devices against current all_devices
    current_ips = []
    for device in all_devices:
        current_ips.append(device['ip'])

    disconnected_ips = []
    for ip in known_devices:
        if ip not in current_ips:
            disconnected_ips.append(ip)

    # remove disconnected devices from tc and known_devices
    for ip in disconnected_ips:
        class_id = known_devices[ip]
        remove_device(ip, class_id, interface)
        del known_devices[ip]

        # clean up prev_counters for disconnected/removed devices
        if class_id in prev_counters:
            del prev_counters[class_id]


    # add new or update existing devices
    for device in all_devices:
        ip = device['ip']

        if ip not in known_devices:
            # new device — assign next available class_id
            known_devices[ip] = next_class_id
            next_class_id     = next_class_id + 1
            add_device(device, known_devices[ip], interface)
        else:
            # existing device — use its permanent class_id
            update_device(device, known_devices[ip], interface)

    # read rela tc byte counters and write enforced values
    # this is needed for dashboard to compare enforcement vs allocation and check if they match within tolerance
    tc_stats = read_stats(interface)

    for device in all_devices:
        ip          = device['ip']
        class_id    = known_devices.get(ip)     # changed from known_devices[ip] to known_devices.get[ip]

        if class_id and class_id in tc_stats:
            device['enforced_down_bps'] = tc_stats[class_id]['down_bps']
            device['enforced_up_bps']   = tc_stats[class_id]['up_bps']
        else:
            # first cycle — no previous counter to diff against yet
            device['enforced_down_bps'] = 0.0
            device['enforced_up_bps']   = 0.0
