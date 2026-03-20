from scapy.all import sniff, IP
import subprocess
import json
import tempfile
import os
import time
import re
from collections import defaultdict

# stores previous tc drop counts per class_id
# tc counters are cumulative so we subtract previous to get THIS interval only
previous_drops   = defaultdict(int)
previous_backlog = defaultdict(int)

# Priority Table
PROTOCOL_PRIORITY = {
    "WHATSAPP_CALL"  : 5,
    "ZOOM"           : 5,
    "SKYPE"          : 5,
    "GOOGLE_MEET"    : 5,
    "DISCORD"        : 5,
    "VIBER_MESSAGE"  : 2,
    "VIBER_CALL"     : 5,
    "RTP"            : 5,
    "STEAM"          : 4,
    "XBOX"           : 4,
    "PLAYSTATION"    : 4,
    "ROBLOX"         : 4,
    "YOUTUBE"        : 3,
    "NETFLIX"        : 3,
    "TIKTOK"         : 3,
    "INSTAGRAM"      : 3,
    "FACEBOOK"       : 2,
    "TWITTER"        : 2,
    "HTTP"           : 2,
    "HTTPS"          : 2,
    "BITTORRENT"     : 1,
    "UNKNOWN"        : 1,
}

NFSTREAM_TO_PROTOCOL = {
    "TLS.Instagram"    : "INSTAGRAM",
    "Instagram"        : "INSTAGRAM",
    "Instagram_Video"  : "INSTAGRAM",
    "QUIC.Instagram"   : "INSTAGRAM",
    "TLS.Facebook"     : "FACEBOOK",
    "Facebook"         : "FACEBOOK",
    "Facebook_Video"   : "FACEBOOK",
    "QUIC.Facebook"    : "FACEBOOK",
    "YouTube"          : "YOUTUBE",
    "Youtube"          : "YOUTUBE",
    "YouTube_QUIC"     : "YOUTUBE",
    "QUIC"             : "YOUTUBE",
    "Google_QUIC"      : "YOUTUBE",
    "QUIC.YouTube"     : "YOUTUBE",
    "WhatsApp"         : "WHATSAPP_CALL",
    "WhatsAppCall"     : "WHATSAPP_CALL",
    "TLS.WhatsApp"     : "WHATSAPP_CALL",
    "WhatsApp_VOIP"    : "WHATSAPP_CALL",
    "Viber"            : "VIBER_MESSAGE",
    "ViberCall"        : "VIBER_CALL",
    "Viber_VOIP"       : "VIBER_CALL",
    "RTP"              : "RTP",
    "RTCP"             : "RTP",
    "SIP"              : "VOIP",
    "Steam"            : "STEAM",
    "SteamGame"        : "STEAM",
    "Blizzard"         : "BLIZZARD",
    "EpicGames"        : "EPICGAMES",
    "RiotGames"        : "RIOTGAMES",
    "Xbox"             : "XBOX",
    "PlayStation"      : "PLAYSTATION",
    "Roblox"           : "ROBLOX",
    "GeForceNow"       : "GEFORCENOW",
    "PathOfExile"      : "PATHOFEXILE",
    "GoogleDrive"      : "GOOGLE_DRIVE",
    "GoogleDocs"       : "GOOGLE_DRIVE",
    "MS_OneDrive"      : "ONEDRIVE",
    "OneDrive"         : "ONEDRIVE",
    "BitTorrent"       : "BITTORRENT",
    "Bittorrent"       : "BITTORRENT",
    "uTorrent"         : "BITTORRENT",
    "TLS"              : "HTTPS",
    "SSL"              : "HTTPS",
}

def normalize_protocol(proto):
    if not proto:
        return "UNKNOWN"
    mapped = NFSTREAM_TO_PROTOCOL.get(proto)
    if mapped:
        return mapped
    for prefix in ["TLS.", "SSL.", "HTTP."]:
        if proto.startswith(prefix):
            proto = proto[len(prefix):]
    return proto.upper()

def get_priority(protocol_name):
    key = normalize_protocol(protocol_name)
    return PROTOCOL_PRIORITY.get(key, 1)

def get_flows(interface, duration):
    with tempfile.NamedTemporaryFile(mode='r+', suffix='.json', delete=False) as tmp:
        tmp_filename = tmp.name

    cmd = ['ndpiReader', '-i', interface, '-s', str(duration),
           '-k', tmp_filename, '-K', 'json']

    try:
        subprocess.run(cmd, capture_output=True, text=True,
                       timeout=duration + 2, check=True)
        flows = []
        with open(tmp_filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        flows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return flows
    except Exception as e:
        print(f"ndpiReader error: {e}")
        return []
    finally:
        if os.path.exists(tmp_filename):
            os.unlink(tmp_filename)

def aggregate_flows(flows):
    devices = defaultdict(lambda: {'up': 0, 'down': 0, 'protocols': defaultdict(int)})
    for f in flows:
        src_ip     = f.get('src_ip')
        dst_ip     = f.get('dest_ip')
        proto      = f.get('ndpi', {}).get('proto', 'UNKNOWN')
        xfer       = f.get('xfer', {})
        up_bytes   = xfer.get('src2dst_bytes', 0)
        down_bytes = xfer.get('dst2src_bytes', 0)

        if src_ip and src_ip.startswith('192.168.'):
            devices[src_ip]['up']               += up_bytes
            devices[src_ip]['protocols'][proto] += up_bytes

        if dst_ip and dst_ip.startswith('192.168.'):
            devices[dst_ip]['down']               += down_bytes
            devices[dst_ip]['protocols'][proto]   += down_bytes

    return devices

def get_tc_demand_boost(interface, interval):
    """
    Read tc class statistics to find dropped and backlogged packets.
    These represent UNSATISFIED demand that scapy cannot see.

    true_demand = scapy_throughput + dropped/interval + backlog/interval

    Returns dict: class_id → extra_bytes_per_sec
    """
    global previous_drops, previous_backlog

    tc_extra = {}   # class_id → extra bytes/sec

    try:
        result = subprocess.run(
            ['tc', '-s', 'class', 'show', 'dev', interface],
            capture_output = True,
            text           = True
        )

        lines      = result.stdout.splitlines()
        current_id = None
        dropped    = 0
        backlog    = 0

        for line in lines:
            line = line.strip()

            # new class found — save previous class data first
            if 'class htb' in line:
                if current_id is not None:
                    # calculate drops in THIS interval only (cumulative counter)
                    drops_this   = max(0, dropped - previous_drops[current_id])
                    backlog_this = max(0, backlog  - previous_backlog[current_id])

                    # extra demand = unsatisfied bytes this interval
                    tc_extra[current_id] = (drops_this + backlog_this) / interval

                    # update previous for next interval
                    previous_drops[current_id]   = dropped
                    previous_backlog[current_id] = backlog

                # start tracking new class
                parts      = line.split()
                current_id = parts[2]   # e.g. 1:10
                dropped    = 0
                backlog    = 0

            elif current_id:
                # backlog line: "backlog 45234b 32p requeue 0"
                m = re.search(r'backlog\s+(\d+)b', line)
                if m:
                    backlog = int(m.group(1))

                # dropped line: "dropped 823, overlimits 12"
                m = re.search(r'dropped\s+(\d+)', line)
                if m:
                    dropped = int(m.group(1))

        # save last class
        if current_id is not None:
            drops_this   = max(0, dropped - previous_drops[current_id])
            backlog_this = max(0, backlog  - previous_backlog[current_id])
            tc_extra[current_id] = (drops_this + backlog_this) / interval
            previous_drops[current_id]   = dropped
            previous_backlog[current_id] = backlog

    except Exception as e:
        print(f"  tc stats error: {e}")

    return tc_extra

def monitor(interface='wlp3s0', interval=5):

    tx_bytes = {}
    rx_bytes = {}

    def count_packet(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            size   = len(pkt)

            if src_ip.startswith("192.168."):
                if src_ip not in tx_bytes:
                    tx_bytes[src_ip] = 0
                tx_bytes[src_ip] += size

            if dst_ip.startswith("192.168."):
                if dst_ip not in rx_bytes:
                    rx_bytes[dst_ip] = 0
                rx_bytes[dst_ip] += size

    print(f"[{time.strftime('%H:%M:%S')}] Capturing packets for {interval} seconds...")
    sniff(iface=interface, prn=count_packet, timeout=interval, store=False)

    print(f"[{time.strftime('%H:%M:%S')}] Analyzing protocols with nDPI...")
    flows     = get_flows(interface, interval)
    ndpi_data = aggregate_flows(flows)

    # get tc demand boost — dropped + backlog = unsatisfied demand
    # import known_devices from enforce to map class_id → ip
    try:
        from enforce import known_devices
        # reverse map: class_id → ip
        class_to_ip = {v: k for k, v in known_devices.items()}
        tc_extra    = get_tc_demand_boost(interface, interval)

        # convert class_id → ip mapping
        ip_extra = {}
        for class_id, extra in tc_extra.items():
            if class_id in class_to_ip:
                ip_extra[class_to_ip[class_id]] = extra

    except Exception:
        ip_extra = {}

    all_ips = set(tx_bytes.keys()) | set(rx_bytes.keys()) | set(ndpi_data.keys())

    if not all_ips:
        print("No devices detected.")
        return []

    all_devices = []

    for ip in sorted(all_ips):

        up   = tx_bytes.get(ip, 0)
        down = rx_bytes.get(ip, 0)

        # base bytes per second from scapy
        up_per_sec   = up   / interval
        down_per_sec = down / interval

        # add unsatisfied demand from tc stats
        # dropped + backlog = what device wanted but could not get
        boost        = ip_extra.get(ip, 0)
        down_per_sec = down_per_sec + boost

        if ip in ndpi_data and ndpi_data[ip]['protocols']:
            raw_proto = max(ndpi_data[ip]['protocols'].items(),
                           key=lambda x: x[1])[0]
        else:
            raw_proto = 'UNKNOWN'

        normalized_proto = normalize_protocol(raw_proto)
        priority         = get_priority(normalized_proto)

        device = {
            "ip"                       : ip,
            "up_bytes_per_sec"         : up_per_sec,
            "down_bytes_per_sec"       : down_per_sec,
            "protocol"                 : normalized_proto,
            "priority"                 : priority,
            "allocated_bytes_download" : 0,
            "allocated_bytes_upload"   : 0,
        }

        all_devices.append(device)

    # print summary table
    print(f"\n{'='*75}")
    print(f"{'IP':<18} {'Upload B/s':>12} {'Download B/s':>14} {'Protocol':<15} {'Pri':>4}")
    print(f"{'='*75}")
    for d in all_devices:
        print(f"{d['ip']:<18} {d['up_bytes_per_sec']:>12.2f} "
              f"{d['down_bytes_per_sec']:>14.2f} {d['protocol']:<15} {d['priority']:>4}")
    print(f"{'='*75}\n")

    return all_devices
