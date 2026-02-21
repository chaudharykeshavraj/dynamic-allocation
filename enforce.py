import subprocess

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)

# ─────────────────────────────────────────────────────────────
# SETUP — runs ONCE at start only
# builds the permanent tc skeleton
# later we only UPDATE class rates, not rebuild everything
# ─────────────────────────────────────────────────────────────
def setup_tc(interface, download_bytes_per_sec, upload_bytes_per_sec):

    total_down_kbits = int((download_bytes_per_sec * 8) / 1000)
    total_up_kbits   = int((upload_bytes_per_sec   * 8) / 1000)

    # ── DOWNLOAD SIDE ────────────────────────────────────────

    # clear old rules
    run_cmd(f"tc qdisc del dev {interface} root 2>/dev/null")

    # root HTB qdisc
    run_cmd(f"tc qdisc add dev {interface} root handle 1: htb default 999")

    # ROOT rate class — total bandwidth ceiling for all devices
    down_burst = max(1, total_down_kbits // 8)
    run_cmd(f"tc class add dev {interface} parent 1: classid 1:1 htb rate {total_down_kbits}kbit burst {down_burst}kb")

    # default class — unmatched devices not blocked
    run_cmd(f"tc class add dev {interface} parent 1: classid 1:999 htb rate 100mbit burst 12kb")
    run_cmd(f"tc qdisc add dev {interface} parent 1:999 handle 999: fq_codel")

    # ── UPLOAD SIDE (ifb trick) ───────────────────────────────

    run_cmd(f"tc qdisc del dev {interface} ingress 2>/dev/null")
    run_cmd(f"tc qdisc del dev ifb0 root 2>/dev/null")

    run_cmd(f"modprobe ifb")
    run_cmd(f"ip link set ifb0 up")

    # redirect all incoming (upload) packets to ifb0
    run_cmd(f"tc qdisc add dev {interface} ingress")
    run_cmd(f"tc filter add dev {interface} parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0")

    # root HTB on ifb0
    run_cmd(f"tc qdisc add dev ifb0 root handle 1: htb default 999")

    # ROOT rate class on ifb0
    up_burst = max(1, total_up_kbits // 8)
    run_cmd(f"tc class add dev ifb0 parent 1: classid 1:1 htb rate {total_up_kbits}kbit burst {up_burst}kb")

    # default class on ifb0
    run_cmd(f"tc class add dev ifb0 parent 1: classid 1:999 htb rate 100mbit burst 12kb")
    run_cmd(f"tc qdisc add dev ifb0 parent 1:999 handle 999: fq_codel")


# ─────────────────────────────────────────────────────────────
# ADD DEVICE — called once when a new device is first seen
# creates HTB class + FQ-CoDel + filter for this device
# ─────────────────────────────────────────────────────────────
def add_device(device, class_id, interface):

    ip         = device['ip']
    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(1, down_kbits // 8)
    up_burst   = max(1, up_kbits   // 8)

    # ── DOWNLOAD ──────────────────────────────────────────────
    # HTB class — rate limit for this device download
    run_cmd(f"tc class add dev {interface} parent 1:1 classid 1:{class_id} htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")

    # FQ-CoDel inside this device's HTB class
    # target 5ms    → max acceptable queue delay
    # interval 100ms → drop if delay exceeds target for this long
    # quantum 1514  → one ethernet frame per round, ensures per flow fairness
    run_cmd(f"tc qdisc add dev {interface} parent 1:{class_id} handle {class_id}0: fq_codel target 5ms interval 100ms quantum 1514")

    # filter — match dst IP → send to this device's download class
    run_cmd(f"tc filter add dev {interface} protocol ip parent 1:0 prio 1 u32 match ip dst {ip}/32 flowid 1:{class_id}")

    # ── UPLOAD ────────────────────────────────────────────────
    # same structure on ifb0, match src IP (upload FROM device)
    run_cmd(f"tc class add dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")
    run_cmd(f"tc qdisc add dev ifb0 parent 1:{class_id} handle {class_id}0: fq_codel target 5ms interval 100ms quantum 1514")
    run_cmd(f"tc filter add dev ifb0 protocol ip parent 1:0 prio 1 u32 match ip src {ip}/32 flowid 1:{class_id}")

    print(f"{ip} → down={down_kbits} Kbps | up={up_kbits} Kbps  [new device added]")


# ─────────────────────────────────────────────────────────────
# UPDATE DEVICE — called every 5 seconds per existing device
# only changes the RATE inside existing class
# does NOT recreate qdisc or filters — avoids packet loss
# ─────────────────────────────────────────────────────────────
def update_device(device, class_id, interface):

    down_kbits = max(1, int((device['allocated_bytes_download'] * 8) / 1000))
    up_kbits   = max(1, int((device['allocated_bytes_upload']   * 8) / 1000))
    down_burst = max(1, down_kbits // 8)
    up_burst   = max(1, up_kbits   // 8)

    # class change → updates rate WITHOUT deleting and recreating
    # smooth update, no traffic interruption
    run_cmd(f"tc class change dev {interface} parent 1:1 classid 1:{class_id} htb rate {down_kbits}kbit ceil {down_kbits}kbit burst {down_burst}kb")
    run_cmd(f"tc class change dev ifb0 parent 1:1 classid 1:{class_id} htb rate {up_kbits}kbit ceil {up_kbits}kbit burst {up_burst}kb")

    print(f"{device['ip']} → down={down_kbits} Kbps | up={up_kbits} Kbps  [updated]")


# ─────────────────────────────────────────────────────────────
# ENFORCE — you call this every 5 seconds from main.py
# adds new devices, updates existing ones
# ─────────────────────────────────────────────────────────────

# tracks which IPs already have tc classes created
# ip → class_id
known_devices = {}

def enforce(all_devices, interface):
    global known_devices

    for i, device in enumerate(all_devices):
        ip       = device['ip']
        class_id = 10 + i

        if ip not in known_devices:
            # first time seeing this device → create full tc structure
            known_devices[ip] = class_id
            add_device(device, class_id, interface)
        else:
            # device already exists → just update the rate
            class_id = known_devices[ip]
            update_device(device, class_id, interface)