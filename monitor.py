#!/usr/bin/env python3
from scapy.all import sniff, IP
import subprocess
import json
import tempfile
import os
import time
import signal
import sys
from collections import defaultdict
import csv
from datetime import datetime

# Priority Table
PROTOCOL_PRIORITY = {
    "WHATSAPP_CALL": 5,
    "ZOOM": 5,
    "SKYPE": 5,
    "GOOGLE_MEET": 5,
    "DISCORD": 5,
    "VIBER_MESSAGE": 2,
    "VIBER_CALL": 5,
    "RTP": 5,
    "STEAM": 4,
    "XBOX": 4,
    "PLAYSTATION": 4,
    "ROBLOX": 4,
    "YOUTUBE": 3,
    "NETFLIX": 3,
    "TIKTOK": 3,
    "INSTAGRAM": 3,
    "FACEBOOK": 2,
    "TWITTER": 2,
    "HTTP": 2,
    "HTTPS": 2,
    "BITTORRENT": 1,
    "UNKNOWN": 1,
    # Gaming additions
    "BLIZZARD": 4,
    "EPICGAMES": 4,
    "RIOTGAMES": 4,
    "GEFORCENOW": 4,
    "PATHOFEXILE": 4,
    "GAMES": 4,
    # Bulky downloads
    "GOOGLE_DRIVE": 2,
    "ONEDRIVE": 2,
    "CDN_DOWNLOAD": 2,
}

# Mapping from ndpiReader protocol names to our keys
NFSTREAM_TO_PROTOCOL = {
    # Instagram
    "TLS.Instagram": "INSTAGRAM",
    "Instagram": "INSTAGRAM",
    "Instagram_Video": "INSTAGRAM",
    "QUIC.Instagram": "INSTAGRAM",
    # Facebook
    "TLS.Facebook": "FACEBOOK",
    "Facebook": "FACEBOOK",
    "Facebook_Video": "FACEBOOK",
    "QUIC.Facebook": "FACEBOOK",
    # YouTube
    "YouTube": "YOUTUBE",
    "Youtube": "YOUTUBE",
    "YouTube_QUIC": "YOUTUBE",
    "QUIC": "YOUTUBE",
    "Google_QUIC": "YOUTUBE",
    "QUIC.YouTube": "YOUTUBE",
    # WhatsApp
    "WhatsApp": "WHATSAPP_CALL",
    "WhatsAppCall": "WHATSAPP_CALL",
    "TLS.WhatsApp": "WHATSAPP_CALL",
    "WhatsApp_VOIP": "WHATSAPP_CALL",
    # Viber
    "Viber": "VIBER_MESSAGE",
    "ViberCall": "VIBER_CALL",
    "Viber_VOIP": "VIBER_CALL",
    # VoIP/Real-time protocols
    "RTP": "RTP",
    "RTCP": "RTP",
    "SIP": "VOIP",
    # Gaming platforms
    "Steam": "STEAM",
    "SteamGame": "STEAM",
    "Blizzard": "BLIZZARD",
    "EpicGames": "EPICGAMES",
    "RiotGames": "RIOTGAMES",
    "Xbox": "XBOX",
    "PlayStation": "PLAYSTATION",
    "Roblox": "ROBLOX",
    "GeForceNow": "GEFORCENOW",
    "PathOfExile": "PATHOFEXILE",
    # Cloud storage / bulky downloads
    "GoogleDrive": "GOOGLE_DRIVE",
    "GoogleDocs": "GOOGLE_DRIVE",
    "MS_OneDrive": "ONEDRIVE",
    "OneDrive": "ONEDRIVE",
    # P2P
    "BitTorrent": "BITTORRENT",
    "Bittorrent": "BITTORRENT",
    "uTorrent": "BITTORRENT",
    # Generic
    "TLS": "HTTPS",
    "SSL": "HTTPS",
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

# ndpiReader integration
def get_flows(interface='wlp3s0', duration=5):
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
        subprocess.run(cmd, capture_output=True, text=True, timeout=duration+2, check=True)
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
        src_ip = f.get('src_ip')
        dst_ip = f.get('dest_ip')
        ndpi_info = f.get('ndpi', {})
        proto = ndpi_info.get('proto', 'UNKNOWN')
        xfer = f.get('xfer', {})
        up_bytes = xfer.get('src2dst_bytes', 0)
        down_bytes = xfer.get('dst2src_bytes', 0)

        if src_ip and src_ip.startswith('192.168.'):
            devices[src_ip]['up'] += up_bytes
            devices[src_ip]['protocols'][proto] += up_bytes
        if dst_ip and dst_ip.startswith('192.168.'):
            devices[dst_ip]['down'] += down_bytes
            devices[dst_ip]['protocols'][proto] += down_bytes
    return devices

_app_cache = {}

# Main monitoring function
def monitor(interface='wlp3s0', interval=5):
    """
    Capture one interval of traffic, analyze protocols, and return a list of
    device dicts. The looping is handled by the caller (main.py).
    """
    global _app_cache

    tx_bytes = {}  # Upload bytes per IP
    rx_bytes = {}  # Download bytes per IP

    def count_packet(pkt):
        """Count packet sizes per IP."""
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            size = len(pkt)
            if src_ip.startswith("192.168."):
                tx_bytes[src_ip] = tx_bytes.get(src_ip, 0) + size
            if dst_ip.startswith("192.168."):
                rx_bytes[dst_ip] = rx_bytes.get(dst_ip, 0) + size

    print(f"[{time.strftime('%H:%M:%S')}] Capturing packets...")
    sniff(iface=interface, prn=count_packet, timeout=interval, store=False)

    print(f"[{time.strftime('%H:%M:%S')}] Analyzing protocols with nDPI...")
    flows = get_flows(interface, interval)
    ndpi_devices = aggregate_flows(flows)

    # Collect all unique IPs from both packet counts and nDPI data
    all_ips = set(tx_bytes.keys()) | set(rx_bytes.keys()) | set(ndpi_devices.keys())

    if not all_ips:
        print("  No devices detected.")
        return []

    all_devices = []
    now = time.time()

    for ip in sorted(all_ips):
        up_bytes = tx_bytes.get(ip, 0)
        down_bytes = rx_bytes.get(ip, 0)

        # Determine primary protocol from nDPI data
        if ip in ndpi_devices and ndpi_devices[ip]['protocols']:
            raw_proto = max(ndpi_devices[ip]['protocols'].items(), key=lambda x: x[1])[0]
        else:
            raw_proto = 'UNKNOWN'

        # Apply cache for QUIC/TLS for better app identification
        if raw_proto in ['QUIC', 'TLS'] and ip in _app_cache:
            cached_app, ts = _app_cache[ip]
            if now - ts < 30:  # 30 sec cache
                proto = cached_app
            else:
                proto = raw_proto
                del _app_cache[ip]
        else:
            proto = raw_proto
            if proto not in ['QUIC', 'TLS', 'UNKNOWN']:
                _app_cache[ip] = (proto, now)

        # Normalize protocol and get priority
        normalized_proto = normalize_protocol(proto)
        priority = get_priority(normalized_proto)

        # Convert to KB/s
        up_kbps = up_bytes / interval / 1024
        down_kbps = down_bytes / interval / 1024

        device = {
            "ip": ip,
            "up_bytes": up_kbps,
            "down_bytes": down_kbps,
            "protocol": normalized_proto,
            "priority": priority,
            "allocated_bytes_download": 0,
            "allocated_bytes_upload": 0
        }

        all_devices.append(device)

    # Print result table to console
    print(f"\n{'='*83}")
    print(f"{'IP':<18} {'Upload(KB/s)':>12} {'Download(KB/s)':>19}    {'Protocol':<15} {'Priority':>8}")
    print(f"{'='*83}")
    for device in all_devices:
        print(f"{device['ip']:<18} {device['up_bytes']:>12.2f} {device['down_bytes']:>19.2f}    {device['protocol']:<15} {device['priority']:>8}")
    print(f"{'='*83}")

    return all_devices


if __name__ == "__main__":
    import signal
    def signal_handler(sig, frame):
        print("\n\nStopping monitoring...")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    iface = sys.argv[1] if len(sys.argv) > 1 else 'wlp3s0'
    interval = 5
    print(f"Starting monitoring on {iface} every {interval}s. Press Ctrl+C to stop.\n")
    while True:
        monitor(interface=iface, interval=interval)