from scapy.all import sniff, IP
import subprocess
import json
import tempfile
import os
import time
from collections import defaultdict

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
    "BLIZZARD"       : 4,
    "EPICGAMES"      : 4,
    "RIOTGAMES"      : 4,
    "GEFORCENOW"     : 4,
    "PATHOFEXILE"    : 4,
    "GAMES"          : 4,
    "GOOGLE_DRIVE"   : 2,
    "ONEDRIVE"       : 2,
    "CDN_DOWNLOAD"   : 2,
}

NFSTREAM_TO_PROTOCOL = {
    # Instagram
    "TLS.Instagram"      : "INSTAGRAM",
    "Instagram"          : "INSTAGRAM",
    "Instagram_Video"    : "INSTAGRAM",
    "QUIC.Instagram"     : "INSTAGRAM",
    # Facebook
    "TLS.Facebook"       : "FACEBOOK",
    "Facebook"           : "FACEBOOK",
    "Facebook_Video"     : "FACEBOOK",
    "QUIC.Facebook"      : "FACEBOOK",
    # YouTube
    "YouTube"            : "YOUTUBE",
    "Youtube"            : "YOUTUBE",
    "YouTube_QUIC"       : "YOUTUBE",
    "QUIC"               : "YOUTUBE",
    "Google_QUIC"        : "YOUTUBE",
    "QUIC.YouTube"       : "YOUTUBE",
    # WhatsApp
    "WhatsApp"           : "WHATSAPP_CALL",
    "WhatsAppCall"       : "WHATSAPP_CALL",
    "TLS.WhatsApp"       : "WHATSAPP_CALL",
    "WhatsApp_VOIP"      : "WHATSAPP_CALL",
    # Viber
    "Viber"              : "VIBER_MESSAGE",
    "ViberCall"          : "VIBER_CALL",
    "Viber_VOIP"         : "VIBER_CALL",
    # VoIP/Real-time protocols
    "RTP"                : "RTP",
    "RTCP"               : "RTP",
    "SIP"                : "VOIP",
    # Gaming platforms
    "Steam"              : "STEAM",
    "SteamGame"          : "STEAM",
    "Blizzard"           : "BLIZZARD",
    "EpicGames"          : "EPICGAMES",
    "RiotGames"          : "RIOTGAMES",
    "Xbox"               : "XBOX",
    "PlayStation"        : "PLAYSTATION",
    "Roblox"             : "ROBLOX",
    "GeForceNow"         : "GEFORCENOW",
    "PathOfExile"        : "PATHOFEXILE",
    # Cloud storage / bulky downloads
    "GoogleDrive"        : "GOOGLE_DRIVE",
    "GoogleDocs"         : "GOOGLE_DRIVE",
    "MS_OneDrive"        : "ONEDRIVE",
    "OneDrive"           : "ONEDRIVE",
    # P2P
    "BitTorrent"         : "BITTORRENT",
    "Bittorrent"         : "BITTORRENT",
    "uTorrent"           : "BITTORRENT",
    # Generic
    "TLS"                : "HTTPS",
    "SSL"                : "HTTPS",
}

def normalize_protocol(proto):
    """First try direct mapping, then strip common prefixes."""
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
    """Get priority for a protocol. Supports both raw and normalized names."""
    key = normalize_protocol(protocol_name)
    return PROTOCOL_PRIORITY.get(key, 1)

def get_flows(interface, duration):
    """Run ndpiReader and return list of flow dicts."""
    with tempfile.NamedTemporaryFile(mode='r+', suffix='.json', delete=False) as tmp:
        tmp_filename = tmp.name

    cmd = [
        'ndpiReader',
        '-i', interface,
        '-s', str(duration),
        '-k', tmp_filename,
        '-K', 'json'
    ]

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 2, check=True)

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
    """Aggregate per IP: upload bytes, download bytes, and protocol counts."""
    devices = defaultdict(lambda: {'up': 0, 'down': 0, 'protocols': defaultdict(int)})

    for f in flows:
        src_ip     = f.get('src_ip')
        dst_ip     = f.get('dest_ip')
        ndpi_info  = f.get('ndpi', {})
        proto      = ndpi_info.get('proto', 'UNKNOWN')
        xfer       = f.get('xfer', {})
        up_bytes   = xfer.get('src2dst_bytes', 0)
        down_bytes = xfer.get('dst2src_bytes', 0)

        if src_ip and src_ip.startswith('192.168.') and src_ip != '192.168.4.1':   # exclude router's own traffic i.e. gateway IP
            devices[src_ip]['up']               += up_bytes
            devices[src_ip]['protocols'][proto] += up_bytes

        if dst_ip and dst_ip.startswith('192.168.') and dst_ip != '192.168.4.1':   # exclude router's own traffic i.e. gateway IP
            devices[dst_ip]['down']               += down_bytes
            devices[dst_ip]['protocols'][proto]   += down_bytes

    return devices

def monitor(interface='wlp3s0', interval=5):

    tx_bytes = {}
    rx_bytes = {}

    def count_packet(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            size   = len(pkt)

            if src_ip.startswith("192.168.") and src_ip != "192.168.4.1":   # exclude router's own traffic i.e. gateway IP
                if src_ip not in tx_bytes:
                    tx_bytes[src_ip] = 0
                tx_bytes[src_ip] = tx_bytes[src_ip] + size

            if dst_ip.startswith("192.168.") and dst_ip != "192.168.4.1":   # exclude router's own traffic i.e. gateway IP
                if dst_ip not in rx_bytes:
                    rx_bytes[dst_ip] = 0
                rx_bytes[dst_ip] = rx_bytes[dst_ip] + size

    print(f"[{time.strftime('%H:%M:%S')}] Capturing packets for {interval} seconds...")
    sniff(iface=interface, prn=count_packet, timeout=interval, store=False)

    print(f"[{time.strftime('%H:%M:%S')}] Analyzing protocols with nDPI...")
    flows     = get_flows(interface, interval)
    ndpi_data = aggregate_flows(flows)

    # collect all unique IPs from both sources
    all_ips = set(tx_bytes.keys()) | set(rx_bytes.keys()) | set(ndpi_data.keys())

    if not all_ips:
        print("No devices detected.")
        return []

    all_devices = []

    for ip in sorted(all_ips):

        up   = tx_bytes.get(ip, 0)
        down = rx_bytes.get(ip, 0)

        # get dominant protocol from nDPI by highest byte count
        if ip in ndpi_data and ndpi_data[ip]['protocols']:
            raw_proto = max(ndpi_data[ip]['protocols'].items(), key=lambda x: x[1])[0]
        else:
            raw_proto = 'UNKNOWN'

        normalized_proto = normalize_protocol(raw_proto)
        priority         = get_priority(normalized_proto)

        device = {
            "ip"                       : ip,
            "up_bytes_per_sec"         : up   / interval,
            "down_bytes_per_sec"       : down / interval,
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
        print(f"{d['ip']:<18} {d['up_bytes_per_sec']:>12.2f} {d['down_bytes_per_sec']:>14.2f} {d['protocol']:<15} {d['priority']:>4}")
    print(f"{'='*75}\n")

    return all_devices