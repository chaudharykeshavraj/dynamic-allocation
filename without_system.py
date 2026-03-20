#!/usr/bin/env python3
"""
without_system.py - Run monitor in a continuous loop
Captures network traffic every INTERVAL seconds and saves to CSV
No bandwidth allocation or tc rules - pure monitoring
"""

import time
import signal
import sys
import os
import csv
import subprocess
import json
import tempfile
import threading
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP

# ── Config ────────────────────────────────────────────────────
INTERFACE = 'wlp3s0'
INTERVAL = 5  # seconds

# ── Priority Table ────────────────────────────────────────────
PROTOCOL_PRIORITY = {
    "WHATSAPP_CALL": 5, "ZOOM": 5, "SKYPE": 5, "GOOGLE_MEET": 5,
    "DISCORD": 5, "VIBER_CALL": 5, "RTP": 5, "FACETIME": 5,
    "VIBER_MESSAGE": 2, "STEAM": 4, "XBOX": 4, "PLAYSTATION": 4,
    "ROBLOX": 4, "PUBG": 4, "SUPERCELL": 4, "FREEFIRE": 4,
    "MOBILELEGENDS": 4, "YOUTUBE": 3, "NETFLIX": 3, "TIKTOK": 3,
    "INSTAGRAM": 3, "FACEBOOK": 2, "TWITTER": 2, "ESEWA": 2,
    "HTTP": 2, "HTTPS": 2, "BITTORRENT": 1, "UNKNOWN": 1,
}

# ── nDPI → Our Protocol ───────────────────────────────────────
NFSTREAM_TO_PROTOCOL = {
    "TLS.Instagram": "INSTAGRAM", "Instagram": "INSTAGRAM",
    "TLS.Facebook": "FACEBOOK", "Facebook": "FACEBOOK",
    "YouTube": "YOUTUBE", "Youtube": "YOUTUBE", "GoogleVideo": "YOUTUBE",
    "WhatsApp": "WHATSAPP_CALL", "WhatsAppCall": "WHATSAPP_CALL",
    "Viber": "VIBER_MESSAGE", "ViberCall": "VIBER_CALL",
    "Zoom": "ZOOM", "GoogleMeet": "GOOGLE_MEET", "Discord": "DISCORD",
    "Skype": "SKYPE", "SkypeTeams": "SKYPE", "MicrosoftTeams": "SKYPE",
    "RTP": "RTP", "RTCP": "RTP", "SIP": "RTP", "STUN": "RTP",
    "TikTok": "TIKTOK", "Netflix": "NETFLIX", "Twitter": "TWITTER",
    "Steam": "STEAM", "Xbox": "XBOX", "PlayStation": "PLAYSTATION",
    "Roblox": "ROBLOX", "BitTorrent": "BITTORRENT",
    "TLS": "HTTPS", "SSL": "HTTPS", "QUIC": "HTTPS",
}

# ── IP Range → Protocol ───────────────────────────────────────
IP_TO_PROTOCOL = [
    ("142.250.", "YOUTUBE"), ("216.58.", "YOUTUBE"), ("172.217.", "YOUTUBE"), ("74.125.", "YOUTUBE"),
    ("157.240.", "FACEBOOK"), ("179.60.", "FACEBOOK"), ("31.13.", "FACEBOOK"),
    ("50.22.", "WHATSAPP_CALL"), ("54.148.", "WHATSAPP_CALL"),
    ("23.246.", "NETFLIX"), ("37.77.", "NETFLIX"),
    ("161.117.", "TIKTOK"), ("103.45.", "TIKTOK"),
    ("3.7.", "ZOOM"), ("99.79.", "ZOOM"),
    ("162.159.", "DISCORD"), ("66.22.", "DISCORD"),
    ("93.184.", "SUPERCELL"), ("185.60.", "SUPERCELL"),
    ("103.28.", "PUBG"), ("110.93.", "PUBG"),
    ("5.0.", "VIBER_CALL"), ("45.33.", "VIBER_MESSAGE"),
    ("74.125.", "GOOGLE_MEET"), ("108.177.", "GOOGLE_MEET"),
]

PORT_TO_PROTOCOL = {
    10012: "PUBG", 7777: "PUBG", 9339: "SUPERCELL", 9340: "SUPERCELL",
    5060: "RTP", 5061: "RTP", 3478: "RTP", 3479: "RTP",
    4244: "WHATSAPP_CALL", 8801: "ZOOM", 8802: "ZOOM", 50000: "DISCORD",
}

_protocol_cache = {}
_cache_timeout_secs = 30

# CSV file path
WITHOUT_SYSTEM_CSV = "without_system.csv"


def identify_from_ip(dst_ip):
    for prefix, protocol in IP_TO_PROTOCOL:
        if dst_ip.startswith(prefix):
            return protocol
    return None


def identify_from_port(dst_port):
    return PORT_TO_PROTOCOL.get(dst_port)


def normalize_protocol(proto):
    if not proto:
        return "UNKNOWN"
    mapped = NFSTREAM_TO_PROTOCOL.get(proto)
    if mapped:
        return mapped
    for prefix in ["TLS.", "SSL.", "HTTP.", "QUIC.", "DNS."]:
        if proto.upper().startswith(prefix.upper()):
            stripped = proto[len(prefix):]
            mapped = NFSTREAM_TO_PROTOCOL.get(stripped)
            if mapped:
                return mapped
    return proto.upper()


def get_priority(protocol_name):
    return PROTOCOL_PRIORITY.get(normalize_protocol(protocol_name), 1)


def get_flows(interface, duration):
    with tempfile.NamedTemporaryFile(mode='r+', suffix='.json', delete=False) as tmp:
        tmp_filename = tmp.name

    cmd = ['ndpiReader', '-i', interface, '-s', str(duration), '-k', tmp_filename, '-K', 'json']

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
    devices = defaultdict(lambda: {
        'up': 0, 'down': 0, 'protocols': defaultdict(int),
        'dst_ips': defaultdict(int), 'dst_ports': defaultdict(int)
    })

    for f in flows:
        src_ip = f.get('src_ip')
        dst_ip = f.get('dest_ip')
        dst_port = f.get('dest_port', 0)
        proto = f.get('ndpi', {}).get('proto', 'UNKNOWN')
        xfer = f.get('xfer', {})
        up_bytes = xfer.get('src2dst_bytes', 0)
        down_bytes = xfer.get('dst2src_bytes', 0)

        if src_ip and src_ip.startswith('192.168.'):
            devices[src_ip]['up'] += up_bytes
            devices[src_ip]['protocols'][proto] += up_bytes
            if dst_ip:
                devices[src_ip]['dst_ips'][dst_ip] += up_bytes
            if dst_port:
                devices[src_ip]['dst_ports'][dst_port] += up_bytes

        if dst_ip and dst_ip.startswith('192.168.'):
            devices[dst_ip]['down'] += down_bytes
            devices[dst_ip]['protocols'][proto] += down_bytes
            if src_ip:
                devices[dst_ip]['dst_ips'][src_ip] += down_bytes
            if dst_port:
                devices[dst_ip]['dst_ports'][dst_port] += down_bytes

    return devices


def resolve_best_protocol(ip, ndpi_proto, ndpi_devices, now):
    normalized = normalize_protocol(ndpi_proto)
    if normalized not in ('HTTPS', 'HTTP', 'UNKNOWN', 'TLS', 'QUIC', 'SSL'):
        _protocol_cache[ip] = (normalized, now)
        return normalized

    if ip in ndpi_devices:
        dst_ips = ndpi_devices[ip].get('dst_ips', {})
        if dst_ips:
            for dst_ip in sorted(dst_ips, key=dst_ips.get, reverse=True)[:5]:
                ip_proto = identify_from_ip(dst_ip)
                if ip_proto:
                    _protocol_cache[ip] = (ip_proto, now)
                    return ip_proto

        dst_ports = ndpi_devices[ip].get('dst_ports', {})
        if dst_ports:
            for port in sorted(dst_ports, key=dst_ports.get, reverse=True)[:3]:
                port_proto = identify_from_port(int(port))
                if port_proto:
                    _protocol_cache[ip] = (port_proto, now)
                    return port_proto

    if ip in _protocol_cache:
        cached_proto, cached_time = _protocol_cache[ip]
        if now - cached_time < _cache_timeout_secs:
            return cached_proto

    return normalized


def get_kernel_bytes(interface):
    with open('/proc/net/dev') as f:
        for line in f:
            if interface in line:
                parts = line.split()
                return int(parts[1]), int(parts[9])
    return 0, 0


def create_csv_if_not_exists():
    if not os.path.exists(WITHOUT_SYSTEM_CSV):
        print(f"  Creating new CSV file: {WITHOUT_SYSTEM_CSV}")
        with open(WITHOUT_SYSTEM_CSV, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp", "ip", "up_bytes_per_sec", "down_bytes_per_sec",
                "protocol", "priority", "total_down_bps", "total_up_bps"
            ])
        return True
    return False


def append_to_csv(devices, total_down_bps, total_up_bps, timestamp):
    create_csv_if_not_exists()
    
    with open(WITHOUT_SYSTEM_CSV, mode="a", newline="") as file:
        writer = csv.writer(file)
        for device in devices:
            writer.writerow([
                timestamp,
                device['ip'],
                device['up_bytes_per_sec'],
                device['down_bytes_per_sec'],
                device['protocol'],
                device['priority'],
                total_down_bps,
                total_up_bps,
            ])
    
    print(f"  Appended {len(devices)} devices to {WITHOUT_SYSTEM_CSV}")


def monitor(interface='wlp3s0', interval=5):
    """
    DIRECT MIRROR: Reports EXACT throughput measured by Linux kernel.
    Captures for exactly 'interval' seconds.
    """
    
    # Snapshot before monitoring
    rx_start, tx_start = get_kernel_bytes(interface)
    
    # Container for per-IP breakdown
    tx_bytes = defaultdict(int)
    rx_bytes = defaultdict(int)
    flows_result = [None]

    def count_packet(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            size = len(pkt)

            if src_ip.startswith("192.168."):
                tx_bytes[src_ip] += size
            if dst_ip.startswith("192.168."):
                rx_bytes[dst_ip] += size

    def run_ndpi():
        flows_result[0] = get_flows(interface, interval)

    print(f"[{time.strftime('%H:%M:%S')}] Capturing packets + nDPI for {interval} seconds...")

    ndpi_thread = threading.Thread(target=run_ndpi)
    ndpi_thread.start()
    sniff(iface=interface, prn=count_packet, timeout=interval, store=False)
    ndpi_thread.join(timeout=interval + 3)

    # Snapshot after monitoring
    rx_end, tx_end = get_kernel_bytes(interface)
    
    # Calculate total throughput
    total_rx_bytes = rx_end - rx_start
    total_tx_bytes = tx_end - tx_start
    total_down_bps = total_rx_bytes / interval
    total_up_bps = total_tx_bytes / interval

    flows = flows_result[0] or []
    ndpi_data = aggregate_flows(flows)

    all_ips = set(tx_bytes.keys()) | set(rx_bytes.keys()) | set(ndpi_data.keys())
    
    if not all_ips:
        print("No devices detected.")
        return []

    now = time.time()
    all_devices = []

    total_packet_down = sum(rx_bytes.values())
    total_packet_up = sum(tx_bytes.values())

    for ip in sorted(all_ips):
        up_packets = tx_bytes.get(ip, 0)
        down_packets = rx_bytes.get(ip, 0)
        
        # Scale to match kernel totals
        if total_packet_down > 0:
            down_scaled = (down_packets / total_packet_down) * total_rx_bytes
        else:
            down_scaled = down_packets
            
        if total_packet_up > 0:
            up_scaled = (up_packets / total_packet_up) * total_tx_bytes
        else:
            up_scaled = up_packets

        down_bytes_per_sec = down_scaled / interval
        up_bytes_per_sec = up_scaled / interval

        # Protocol detection
        if ip in ndpi_data and ndpi_data[ip]['protocols']:
            raw_proto = max(ndpi_data[ip]['protocols'].items(), key=lambda x: x[1])[0]
        else:
            raw_proto = 'UNKNOWN'

        best_proto = resolve_best_protocol(ip, raw_proto, ndpi_data, now)
        priority = get_priority(best_proto)

        device = {
            "ip": ip,
            "up_bytes_per_sec": up_bytes_per_sec,
            "down_bytes_per_sec": down_bytes_per_sec,
            "protocol": best_proto,
            "priority": priority,
        }
        all_devices.append(device)

    # Print summary
    print(f"\n{'='*80}")
    print(f"KERNEL GROUND TRUTH - Total: Down={total_down_bps/1024:.1f} KB/s ({total_down_bps*8/1e6:.2f} Mbps), Up={total_up_bps/1024:.1f} KB/s ({total_up_bps*8/1e6:.2f} Mbps)")
    print(f"{'='*80}")
    print(f"{'IP':<18} {'Upload KB/s':>12} {'Download KB/s':>14} {'Protocol':<15} {'Pri':>4} {'% of Total':>12}")
    print(f"{'='*80}")
    
    for d in all_devices:
        down_kbps = d['down_bytes_per_sec'] / 1024
        up_kbps = d['up_bytes_per_sec'] / 1024
        pct = (d['down_bytes_per_sec'] + d['up_bytes_per_sec']) / (total_down_bps + total_up_bps + 1) * 100
        print(f"{d['ip']:<18} {up_kbps:>12.1f} {down_kbps:>14.1f} {d['protocol']:<15} {d['priority']:>4} {pct:>11.1f}%")
    
    print(f"{'='*80}\n")
    
    # Save to CSV
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    append_to_csv(all_devices, total_down_bps, total_up_bps, timestamp)

    return all_devices


# ── Signal Handler ────────────────────────────────────────────
def signal_handler(sig, frame):
    print("\n\n" + "="*50)
    print("Stopping without_system monitoring...")
    print(f"Data saved to: {WITHOUT_SYSTEM_CSV}")
    print("="*50)
    sys.exit(0)


# ── Main Loop ─────────────────────────────────────────────────
def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    print("\n" + "="*60)
    print(" WITHOUT SYSTEM MONITOR - Continuous Traffic Capture")
    print("="*60)
    print(f"Interface: {INTERFACE}")
    print(f"Interval: {INTERVAL} seconds")
    print(f"Output: {WITHOUT_SYSTEM_CSV}")
    print("\nPress Ctrl+C to stop\n")
    print("="*60 + "\n")
    
    interval_count = 0
    
    while True:
        interval_count += 1
        
        print(f"\n{'─'*60}")
        print(f"Interval {interval_count} - {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'─'*60}")
        
        try:
            # Run one monitoring cycle
            devices = monitor(INTERFACE, INTERVAL)
            
            if len(devices) == 0:
                print("No devices detected this interval")
            else:
                print(f"\n✓ Interval {interval_count} complete - {len(devices)} devices captured")
                
        except Exception as e:
            print(f"✗ Error during monitoring: {e}")
            import traceback
            traceback.print_exc()
        
        # Wait before next interval
        print(f"\nWaiting {INTERVAL} seconds for next capture...")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()