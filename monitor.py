from scapy.all import sniff, IP, TCP, UDP
import subprocess
import json
import tempfile
import os
import time
import re
import threading
from collections import defaultdict

previous_drops = defaultdict(int)
previous_backlog = defaultdict(int)

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
    "Instagram_Video": "INSTAGRAM", "QUIC.Instagram": "INSTAGRAM",
    "TLS.Facebook": "FACEBOOK", "Facebook": "FACEBOOK",
    "Facebook_Video": "FACEBOOK", "QUIC.Facebook": "FACEBOOK",
    "DNS.Facebook": "FACEBOOK", "DNS.FACEBOOK": "FACEBOOK",
    "STUN.FacebookVOIP": "FACEBOOK", "STUN.FACEBOOKVOIP": "FACEBOOK",
    "YouTube": "YOUTUBE", "Youtube": "YOUTUBE", "YouTube_QUIC": "YOUTUBE",
    "QUIC.YouTube": "YOUTUBE", "DNS.YouTube": "YOUTUBE", "DNS.YOUTUBE": "YOUTUBE",
    "GoogleVideo": "YOUTUBE", "WhatsApp": "WHATSAPP_CALL",
    "WhatsAppCall": "WHATSAPP_CALL", "TLS.WhatsApp": "WHATSAPP_CALL",
    "WhatsApp_VOIP": "WHATSAPP_CALL", "WhatsAppFiles": "WHATSAPP_CALL",
    "WHATSAPPFILES": "WHATSAPP_CALL", "DNS.WhatsApp": "WHATSAPP_CALL",
    "Viber": "VIBER_MESSAGE", "ViberCall": "VIBER_CALL",
    "Viber_VOIP": "VIBER_CALL", "QUIC.Viber": "VIBER_CALL",
    "DNS.Viber": "VIBER_MESSAGE", "Zoom": "ZOOM", "DNS.Zoom": "ZOOM",
    "GoogleMeet": "GOOGLE_MEET", "Google_Meet": "GOOGLE_MEET",
    "DNS.GoogleMeet": "GOOGLE_MEET", "Discord": "DISCORD",
    "DNS.Discord": "DISCORD", "Skype": "SKYPE", "SkypeTeams": "SKYPE",
    "SKYPE_TEAMS": "SKYPE", "MicrosoftTeams": "SKYPE", "RTP": "RTP",
    "RTCP": "RTP", "SIP": "RTP", "STUN": "RTP", "TikTok": "TIKTOK",
    "DNS.TikTok": "TIKTOK", "Netflix": "NETFLIX", "DNS.Netflix": "NETFLIX",
    "Twitter": "TWITTER", "DNS.Twitter": "TWITTER", "Steam": "STEAM",
    "SteamGame": "STEAM", "Blizzard": "SUPERCELL", "EpicGames": "PUBG",
    "RiotGames": "PUBG", "Xbox": "XBOX", "PlayStation": "PLAYSTATION",
    "Roblox": "ROBLOX", "GeForceNow": "STEAM", "GoogleServices": "HTTPS",
    "GOOGLESERVICES": "HTTPS", "QUIC.GoogleServices": "HTTPS",
    "QUIC.GOOGLESERVICES": "HTTPS", "GoogleDrive": "HTTPS",
    "MS_OneDrive": "HTTPS", "BitTorrent": "BITTORRENT",
    "Bittorrent": "BITTORRENT", "uTorrent": "BITTORRENT",
    "TLS": "HTTPS", "SSL": "HTTPS", "QUIC": "HTTPS",
}

# ── IP Range → Protocol ───────────────────────────────────────
IP_TO_PROTOCOL = [
    ("142.250.", "YOUTUBE"), ("216.58.", "YOUTUBE"), ("172.217.", "YOUTUBE"), ("74.125.", "YOUTUBE"),
    ("157.240.", "FACEBOOK"), ("179.60.", "FACEBOOK"), ("31.13.", "FACEBOOK"), ("66.220.", "FACEBOOK"),
    ("69.63.", "FACEBOOK"), ("50.22.", "WHATSAPP_CALL"), ("54.148.", "WHATSAPP_CALL"),
    ("23.246.", "NETFLIX"), ("37.77.", "NETFLIX"), ("161.117.", "TIKTOK"), ("103.45.", "TIKTOK"),
    ("120.232.", "TIKTOK"), ("3.7.", "ZOOM"), ("99.79.", "ZOOM"), ("170.114.", "ZOOM"),
    ("162.159.", "DISCORD"), ("66.22.", "DISCORD"), ("93.184.", "SUPERCELL"), ("185.60.", "SUPERCELL"),
    ("103.28.", "PUBG"), ("110.93.", "PUBG"), ("103.69.", "ESEWA"), ("103.1.", "ESEWA"),
    ("5.0.", "VIBER_CALL"), ("45.33.", "VIBER_MESSAGE"), ("74.125.", "GOOGLE_MEET"),
    ("108.177.", "GOOGLE_MEET"), ("103.28.", "STEAM"), ("185.25.", "STEAM"),
]

PORT_TO_PROTOCOL = {
    10012: "PUBG", 7777: "PUBG", 9339: "SUPERCELL", 9340: "SUPERCELL",
    40000: "MOBILELEGENDS", 5555: "MOBILELEGENDS", 5060: "RTP", 5061: "RTP",
    3478: "RTP", 3479: "RTP", 4244: "WHATSAPP_CALL", 8801: "ZOOM",
    8802: "ZOOM", 50000: "DISCORD", 5242: "WHATSAPP_CALL",
}

# ── Protocol Cache with Confidence ────────────────────────────
_protocol_cache = {}
_protocol_confidence = defaultdict(int)
_cache_timeout_secs = 60  # Increased from 30
MIN_CONFIDENCE = 3  # Need 3 consecutive detections to change


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
            mapped = NFSTREAM_TO_PROTOCOL.get(stripped.upper())
            if mapped:
                return mapped
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
    devices = defaultdict(lambda: {
        'up': 0, 'down': 0, 'protocols': defaultdict(int),
        'dst_ips': defaultdict(int), 'dst_ports': defaultdict(int),
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
    global _protocol_cache, _protocol_confidence
    
    normalized = normalize_protocol(ndpi_proto)
    
    # High confidence protocols that should be trusted immediately
    high_confidence_protocols = (
        'WHATSAPP_CALL', 'ZOOM', 'SKYPE', 'GOOGLE_MEET', 'DISCORD',
        'VIBER_CALL', 'RTP', 'STEAM', 'XBOX', 'PLAYSTATION', 'ROBLOX',
        'PUBG', 'SUPERCELL', 'YOUTUBE', 'NETFLIX', 'TIKTOK'
    )
    
    # If nDPI gave us a specific high-confidence protocol
    if normalized in high_confidence_protocols:
        _protocol_confidence[ip] = MIN_CONFIDENCE
        _protocol_cache[ip] = (normalized, now)
        return normalized
    
    # If we have high confidence in cached protocol, keep it
    cached = _protocol_cache.get(ip)
    if cached and _protocol_confidence[ip] >= MIN_CONFIDENCE:
        cached_proto, cached_time = cached
        if now - cached_time < _cache_timeout_secs:
            return cached_proto
    
    # Try destination IP range matching
    if ip in ndpi_devices:
        dst_ips = ndpi_devices[ip].get('dst_ips', {})
        if dst_ips:
            for dst_ip in sorted(dst_ips, key=dst_ips.get, reverse=True)[:5]:
                ip_proto = identify_from_ip(dst_ip)
                if ip_proto:
                    _protocol_confidence[ip] = _protocol_confidence.get(ip, 0) + 1
                    if _protocol_confidence[ip] >= MIN_CONFIDENCE:
                        _protocol_cache[ip] = (ip_proto, now)
                        return ip_proto
        
        # Try destination port matching
        dst_ports = ndpi_devices[ip].get('dst_ports', {})
        if dst_ports:
            for port in sorted(dst_ports, key=dst_ports.get, reverse=True)[:3]:
                port_proto = identify_from_port(int(port))
                if port_proto:
                    _protocol_confidence[ip] = _protocol_confidence.get(ip, 0) + 1
                    if _protocol_confidence[ip] >= MIN_CONFIDENCE:
                        _protocol_cache[ip] = (port_proto, now)
                        return port_proto
    
    # No match - decrease confidence
    _protocol_confidence[ip] = max(0, _protocol_confidence.get(ip, 0) - 1)
    
    # Use cached if available
    if cached:
        cached_proto, cached_time = cached
        if now - cached_time < _cache_timeout_secs:
            return cached_proto
    
    return normalized


def get_tc_demand_boost(interface, interval):
    global previous_drops, previous_backlog
    tc_extra = {}

    try:
        result = subprocess.run(
            ['tc', '-s', 'class', 'show', 'dev', interface],
            capture_output=True, text=True
        )

        lines = result.stdout.splitlines()
        current_id = None
        dropped = 0
        backlog = 0

        for line in lines:
            line = line.strip()

            if 'class htb' in line:
                if current_id is not None:
                    drops_this = max(0, dropped - previous_drops[current_id])
                    backlog_this = max(0, backlog - previous_backlog[current_id])
                    tc_extra[current_id] = (drops_this + backlog_this) / interval
                    previous_drops[current_id] = dropped
                    previous_backlog[current_id] = backlog

                parts = line.split()
                current_id = parts[2]
                dropped = 0
                backlog = 0

            elif current_id:
                m = re.search(r'backlog\s+(\d+)b', line)
                if m:
                    backlog = int(m.group(1))
                m = re.search(r'dropped\s+(\d+)', line)
                if m:
                    dropped = int(m.group(1))

        if current_id is not None:
            drops_this = max(0, dropped - previous_drops[current_id])
            backlog_this = max(0, backlog - previous_backlog[current_id])
            tc_extra[current_id] = (drops_this + backlog_this) / interval
            previous_drops[current_id] = dropped
            previous_backlog[current_id] = backlog

    except Exception as e:
        print(f"  tc stats error: {e}")

    return tc_extra


def monitor(interface='wlp3s0', interval=5):
    tx_bytes = {}
    rx_bytes = {}
    flows_result = [None]

    def count_packet(pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            size = len(pkt)

            if src_ip.startswith("192.168."):
                if src_ip not in tx_bytes:
                    tx_bytes[src_ip] = 0
                tx_bytes[src_ip] += size

            if dst_ip.startswith("192.168."):
                if dst_ip not in rx_bytes:
                    rx_bytes[dst_ip] = 0
                rx_bytes[dst_ip] += size

    def run_ndpi():
        flows_result[0] = get_flows(interface, interval)

    print(f"[{time.strftime('%H:%M:%S')}] Capturing packets + nDPI for {interval} seconds...")

    ndpi_thread = threading.Thread(target=run_ndpi)
    ndpi_thread.start()
    sniff(iface=interface, prn=count_packet, timeout=interval, store=False)
    ndpi_thread.join(timeout=interval + 3)

    flows = flows_result[0] or []
    ndpi_data = aggregate_flows(flows)

    print(f"[{time.strftime('%H:%M:%S')}] Processing results...")

    # get tc demand boost
    try:
        from enforce import known_devices
        class_to_ip = {v: k for k, v in known_devices.items()}
        tc_extra = get_tc_demand_boost(interface, interval)
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

    now = time.time()
    all_devices = []

    for ip in sorted(all_ips):
        up = tx_bytes.get(ip, 0)
        down = rx_bytes.get(ip, 0)

        up_per_sec = up / interval
        down_per_sec = down / interval

        # add unsatisfied demand from tc stats
        boost = ip_extra.get(ip, 0)
        down_per_sec = down_per_sec + boost

        # get raw nDPI protocol
        if ip in ndpi_data and ndpi_data[ip]['protocols']:
            raw_proto = max(ndpi_data[ip]['protocols'].items(),
                           key=lambda x: x[1])[0]
        else:
            raw_proto = 'UNKNOWN'

        # resolve best protocol using all 5 layers with confidence
        best_proto = resolve_best_protocol(ip, raw_proto, ndpi_data, now)
        priority = get_priority(best_proto)

        device = {
            "ip": ip,
            "up_bytes_per_sec": up_per_sec,
            "down_bytes_per_sec": down_per_sec,
            "protocol": best_proto,
            "priority": priority,
            "allocated_bytes_download": 0,
            "allocated_bytes_upload": 0,
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