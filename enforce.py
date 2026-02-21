import subprocess

known_devices  = {}     # ip → class_id
is_setup_done  = False
next_class_id  = 10     # fix 1: global counter, never reuses ids

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)

def setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec):

    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)

    run_cmd(f"tc qdisc del dev {interface} root 2>/dev/null")
    run_cmd(f"tc qdisc add dev {interface} root handle 1: htb default 999")

    down_burst = max(1, total_down_kbits // 8)
    run_cmd(f"tc class add dev {interface} parent 1: classid 1:1 htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class add dev {interface} parent 1: classid 1:999 htb rate 100mbit burst 12kb")
    run_cmd(f"tc qdisc add dev {interface} parent 1:999 handle 999: fq_codel")

    run_cmd(f"tc qdisc del dev {interface} ingress 2>/dev/null")
    run_cmd(f"tc qdisc del dev ifb0 root 2>/dev/null")
    run_cmd(f"modprobe ifb")
    run_cmd(f"ip link set ifb0 up")
    run_cmd(f"tc qdisc add dev {interface} ingress")
    run_cmd(f"tc filter add dev {interface} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0")

    run_cmd(f"tc qdisc add dev ifb0 root handle 1: htb default 999")

    up_burst = max(1, total_up_kbits // 8)
    run_cmd(f"tc class add dev ifb0 parent 1: classid 1:1 htb rate {total_up_kbits}kbit burst {up_burst}kb")
    run_cmd(f"tc class add dev ifb0 parent 1: classid 1:999 htb rate 100mbit burst 12kb")
    run_cmd(f"tc qdisc add dev ifb0 parent 1:999 handle 999: fq_codel")

    print("tc setup done")

def add_device(device, class_id, interface):

    ip         = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(1, down_kbits // 8)
    up_burst   = max(1, up_kbits   // 8)

    run_cmd(f"tc class add dev {interface} parent 1:1 classid 1:{class_id} htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}0: fq_codel target 5ms interval 100ms quantum 1514")
    run_cmd(f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{class_id}")

    run_cmd(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
    run_cmd(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}0: fq_codel target 5ms interval 100ms quantum 1514")
    run_cmd(f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 flowid 1:{class_id}")

    print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [new]")

def update_device(device, class_id, interface):

    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(1, down_kbits // 8)
    up_burst   = max(1, up_kbits   // 8)

    # class change → smooth update, no traffic interruption
    run_cmd(f"tc class change dev {interface} parent 1:1 classid 1:{class_id} htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")

    print(f"{device['ip']} → down={down_kbits} Kbps | up={up_kbits} Kbps  [updated]")

def remove_device(ip, class_id, interface):
    # delete this device's class from both interfaces
    # filters attached to class are automatically removed too
    run_cmd(f"tc class del dev {interface} classid 1:{class_id} 2>/dev/null")
    run_cmd(f"tc class del dev ifb0 classid 1:{class_id} 2>/dev/null")
    print(f"{ip} → removed from tc  [disconnected]")

def enforce(all_devices, interface, download_bytes_per_sec, upload_bytes_per_sec):
    global known_devices, is_setup_done, next_class_id

    # fix 1 — setup runs only once
    if not is_setup_done:
        setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec)
        is_setup_done = True

    # fix 2 — update parent class rate every cycle
    # in case total bandwidth changed (e.g remeasured)
    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)
    down_burst       = max(1, total_down_kbits // 8)
    up_burst         = max(1, total_up_kbits   // 8)

    run_cmd(f"tc class change dev {interface} parent 1: classid 1:1 htb rate {total_down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1: classid 1:1 htb rate {total_up_kbits}kbit burst {up_burst}kb")

    # fix 3 — find disconnected devices
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

    # fix 1 — assign class_id using global counter not loop index
    # so ip always keeps same class_id regardless of list order
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