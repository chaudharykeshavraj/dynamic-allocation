from scapy.all import sniff, IP, TCP, UDP
import subprocess
import json
import tempfile
import os
import time
import re
import threading
from collections import defaultdict

previous_drops   = defaultdict(int)
previous_backlog = defaultdict(int)

# ── Priority Table ────────────────────────────────────────────
PROTOCOL_PRIORITY = {
    "WHATSAPP_CALL"  : 5,
    "ZOOM"           : 5,
    "SKYPE"          : 5,
    "GOOGLE_MEET"    : 5,
    "DISCORD"        : 5,
    "VIBER_CALL"     : 5,
    "RTP"            : 5,
    "FACETIME"       : 5,
    "VIBER_MESSAGE"  : 2,
    "STEAM"          : 4,
    "XBOX"           : 4,
    "PLAYSTATION"    : 4,
    "ROBLOX"         : 4,
    "PUBG"           : 4,
    "SUPERCELL"      : 4,
    "FREEFIRE"       : 4,
    "MOBILELEGENDS"  : 4,
    "YOUTUBE"        : 3,
    "NETFLIX"        : 3,
    "TIKTOK"         : 3,
    "INSTAGRAM"      : 3,
    "FACEBOOK"       : 2,
    "TWITTER"        : 2,
    "ESEWA"          : 2,
    "HTTP"           : 2,
    "HTTPS"          : 2,
    "BITTORRENT"     : 1,
    "UNKNOWN"        : 1,
}

# ── nDPI → Our Protocol ───────────────────────────────────────
NFSTREAM_TO_PROTOCOL = {
    # Instagram
    "TLS.Instagram"        : "INSTAGRAM",
    "Instagram"            : "INSTAGRAM",
    "Instagram_Video"      : "INSTAGRAM",
    "QUIC.Instagram"       : "INSTAGRAM",
    # Facebook
    "TLS.Facebook"         : "FACEBOOK",
    "Facebook"             : "FACEBOOK",
    "Facebook_Video"       : "FACEBOOK",
    "QUIC.Facebook"        : "FACEBOOK",
    "DNS.Facebook"         : "FACEBOOK",
    "DNS.FACEBOOK"         : "FACEBOOK",
    "STUN.FacebookVOIP"    : "FACEBOOK",
    "STUN.FACEBOOKVOIP"    : "FACEBOOK",
    # YouTube
    "YouTube"              : "YOUTUBE",
    "Youtube"              : "YOUTUBE",
    "YouTube_QUIC"         : "YOUTUBE",
    "QUIC.YouTube"         : "YOUTUBE",
    "DNS.YouTube"          : "YOUTUBE",
    "DNS.YOUTUBE"          : "YOUTUBE",
    "GoogleVideo"          : "YOUTUBE",
    # WhatsApp
    "WhatsApp"             : "WHATSAPP_CALL",
    "WhatsAppCall"         : "WHATSAPP_CALL",
    "TLS.WhatsApp"         : "WHATSAPP_CALL",
    "WhatsApp_VOIP"        : "WHATSAPP_CALL",
    "WhatsAppFiles"        : "WHATSAPP_CALL",
    "WHATSAPPFILES"        : "WHATSAPP_CALL",
    "DNS.WhatsApp"         : "WHATSAPP_CALL",
    # Viber
    "Viber"                : "VIBER_MESSAGE",
    "ViberCall"            : "VIBER_CALL",
    "Viber_VOIP"           : "VIBER_CALL",
    "QUIC.Viber"           : "VIBER_CALL",
    "DNS.Viber"            : "VIBER_MESSAGE",
    # Zoom
    "Zoom"                 : "ZOOM",
    "DNS.Zoom"             : "ZOOM",
    # Google Meet
    "GoogleMeet"           : "GOOGLE_MEET",
    "Google_Meet"          : "GOOGLE_MEET",
    "DNS.GoogleMeet"       : "GOOGLE_MEET",
    # Discord
    "Discord"              : "DISCORD",
    "DNS.Discord"          : "DISCORD",
    # Skype / Teams
    "Skype"                : "SKYPE",
    "SkypeTeams"           : "SKYPE",
    "SKYPE_TEAMS"          : "SKYPE",
    "MicrosoftTeams"       : "SKYPE",
    # VoIP
    "RTP"                  : "RTP",
    "RTCP"                 : "RTP",
    "SIP"                  : "RTP",
    "STUN"                 : "RTP",
    # TikTok
    "TikTok"               : "TIKTOK",
    "DNS.TikTok"           : "TIKTOK",
    # Netflix
    "Netflix"              : "NETFLIX",
    "DNS.Netflix"          : "NETFLIX",
    # Twitter/X
    "Twitter"              : "TWITTER",
    "DNS.Twitter"          : "TWITTER",
    # Gaming
    "Steam"                : "STEAM",
    "SteamGame"            : "STEAM",
    "Blizzard"             : "SUPERCELL",
    "EpicGames"            : "PUBG",
    "RiotGames"            : "PUBG",
    "Xbox"                 : "XBOX",
    "PlayStation"          : "PLAYSTATION",
    "Roblox"               : "ROBLOX",
    "GeForceNow"           : "STEAM",
    # Google services
    "GoogleServices"       : "HTTPS",
    "GOOGLESERVICES"       : "HTTPS",
    "QUIC.GoogleServices"  : "HTTPS",
    "QUIC.GOOGLESERVICES"  : "HTTPS",
    "GoogleDrive"          : "HTTPS",
    "MS_OneDrive"          : "HTTPS",
    # P2P
    "BitTorrent"           : "BITTORRENT",
    "Bittorrent"           : "BITTORRENT",
    "uTorrent"             : "BITTORRENT",
    # Generic encrypted
    "TLS"                  : "HTTPS",
    "SSL"                  : "HTTPS",
    "QUIC"                 : "HTTPS",
}

# ── IP Range → Protocol ───────────────────────────────────────
# When nDPI only sees HTTPS/TLS, check destination IP ranges
# These are well-known IP blocks for major services
IP_TO_PROTOCOL = [
    # YouTube / Google Video
    ("142.250.", "YOUTUBE"),
    ("216.58.",  "YOUTUBE"),
    ("172.217.", "YOUTUBE"),
    ("74.125.",  "YOUTUBE"),

    # Facebook / Instagram / WhatsApp (Meta)
    ("157.240.", "FACEBOOK"),
    ("179.60.",  "FACEBOOK"),
    ("31.13.",   "FACEBOOK"),
    ("66.220.",  "FACEBOOK"),
    ("69.63.",   "FACEBOOK"),

    # WhatsApp specific
    ("50.22.",   "WHATSAPP_CALL"),
    ("54.148.",  "WHATSAPP_CALL"),

    # Netflix
    ("23.246.",  "NETFLIX"),
    ("37.77.",   "NETFLIX"),
    ("198.38.",  "NETFLIX"),

    # TikTok / ByteDance
    ("161.117.", "TIKTOK"),
    ("103.45.",  "TIKTOK"),
    ("120.232.", "TIKTOK"),

    # Zoom
    ("3.7.",     "ZOOM"),
    ("99.79.",   "ZOOM"),
    ("170.114.", "ZOOM"),

    # Discord
    ("162.159.", "DISCORD"),
    ("66.22.",   "DISCORD"),

    # Supercell games (Clash of Clans, Clash Royale, Brawl Stars)
    ("93.184.",  "SUPERCELL"),
    ("185.60.",  "SUPERCELL"),

    # PUBG Mobile
    ("103.28.",  "PUBG"),
    ("110.93.",  "PUBG"),

    # eSewa (Nepal payment service)
    ("103.69.",  "ESEWA"),
    ("103.1.",   "ESEWA"),

    # Viber
    ("5.0.",     "VIBER_CALL"),
    ("45.33.",   "VIBER_MESSAGE"),

    # Google Meet
    ("74.125.",  "GOOGLE_MEET"),
    ("108.177.", "GOOGLE_MEET"),

    # Steam gaming
    ("103.28.",  "STEAM"),
    ("185.25.",  "STEAM"),
]

# ── Port → Protocol ───────────────────────────────────────────
# Last resort — identify by destination port
PORT_TO_PROTOCOL = {
    # Gaming ports
    10012  : "PUBG",
    7777   : "PUBG",
    9339   : "SUPERCELL",  # Supercell games
    9340   : "SUPERCELL",
    40000  : "MOBILELEGENDS",
    5555   : "MOBILELEGENDS",
    # VoIP
    5060   : "RTP",        # SIP
    5061   : "RTP",
    3478   : "RTP",        # STUN
    3479   : "RTP",
    # WhatsApp call ports
    4244   : "WHATSAPP_CALL",
    # Zoom
    8801   : "ZOOM",
    8802   : "ZOOM",
    # Discord
    50000  : "DISCORD",
    # Viber
    4244   : "VIBER_CALL",
    5242   : "WHATSAPP_CALL",
}

# ── Protocol Cache ────────────────────────────────────────────
# stores last identified specific protocol per IP
# avoids losing identity when traffic briefly shows as HTTPS
_protocol_cache     = {}
_cache_timeout_secs = 30   # keep cached protocol for 30 seconds

def identify_from_ip(dst_ip):
    """Check destination IP against known service IP ranges."""
    for prefix, protocol in IP_TO_PROTOCOL:
        if dst_ip.startswith(prefix):
            return protocol
    return None

def identify_from_port(dst_port):
    """Check destination port against known service ports."""
    return PORT_TO_PROTOCOL.get(dst_port)

def normalize_protocol(proto):
    """
    Normalize nDPI protocol name to our standard names.
    Handles all common nDPI output formats.
    """
    if not proto:
        return "UNKNOWN"

    # direct mapping first
    mapped = NFSTREAM_TO_PROTOCOL.get(proto)
    if mapped:
        return mapped

    # strip common prefixes and try again
    for prefix in ["TLS.", "SSL.", "HTTP.", "QUIC.", "DNS."]:
        if proto.upper().startswith(prefix.upper()):
            stripped = proto[len(prefix):]
            mapped   = NFSTREAM_TO_PROTOCOL.get(stripped)
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
    """Run ndpiReader and return list of flow dicts."""
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
    """
    Aggregate per IP: bytes, protocol counts, and destination IPs.
    Also tries IP-based and port-based identification.
    """
    devices = defaultdict(lambda: {
        'up'       : 0,
        'down'     : 0,
        'protocols': defaultdict(int),
        'dst_ips'  : defaultdict(int),
        'dst_ports': defaultdict(int),
    })

    for f in flows:
        src_ip   = f.get('src_ip')
        dst_ip   = f.get('dest_ip')
        dst_port = f.get('dest_port', 0)
        proto    = f.get('ndpi', {}).get('proto', 'UNKNOWN')
        xfer     = f.get('xfer', {})
        up_bytes   = xfer.get('src2dst_bytes', 0)
        down_bytes = xfer.get('dst2src_bytes', 0)

        if src_ip and src_ip.startswith('192.168.'):
            devices[src_ip]['up']                    += up_bytes
            devices[src_ip]['protocols'][proto]      += up_bytes
            if dst_ip:
                devices[src_ip]['dst_ips'][dst_ip]   += up_bytes
            if dst_port:
                devices[src_ip]['dst_ports'][dst_port] += up_bytes

        if dst_ip and dst_ip.startswith('192.168.'):
            devices[dst_ip]['down']                  += down_bytes
            devices[dst_ip]['protocols'][proto]      += down_bytes
            if src_ip:
                devices[dst_ip]['dst_ips'][src_ip]   += down_bytes
            if dst_port:
                devices[dst_ip]['dst_ports'][dst_port] += down_bytes

    return devices

def resolve_best_protocol(ip, ndpi_proto, ndpi_devices, now):
    """
    Multi-layer protocol resolution:
    Layer 1 → nDPI direct identification (most accurate)
    Layer 2 → Destination IP range matching
    Layer 3 → Destination port matching
    Layer 4 → Protocol cache (last known good protocol)
    Layer 5 → HTTPS fallback
    """

    # layer 1 — nDPI gave us a specific protocol
    normalized = normalize_protocol(ndpi_proto)
    if normalized not in ('HTTPS', 'HTTP', 'UNKNOWN', 'TLS', 'QUIC', 'SSL'):
        # nDPI identified something specific — trust it
        _protocol_cache[ip] = (normalized, now)
        return normalized

    # layer 2 — check destination IP ranges
    if ip in ndpi_devices:
        dst_ips = ndpi_devices[ip].get('dst_ips', {})
        if dst_ips:
            # check top destination IPs by byte count
            for dst_ip in sorted(dst_ips, key=dst_ips.get, reverse=True)[:5]:
                ip_proto = identify_from_ip(dst_ip)
                if ip_proto:
                    _protocol_cache[ip] = (ip_proto, now)
                    return ip_proto

    # layer 3 — check destination ports
    if ip in ndpi_devices:
        dst_ports = ndpi_devices[ip].get('dst_ports', {})
        if dst_ports:
            for port in sorted(dst_ports, key=dst_ports.get, reverse=True)[:3]:
                port_proto = identify_from_port(int(port))
                if port_proto:
                    _protocol_cache[ip] = (port_proto, now)
                    return port_proto

    # layer 4 — use cached protocol if recent enough
    if ip in _protocol_cache:
        cached_proto, cached_time = _protocol_cache[ip]
        if now - cached_time < _cache_timeout_secs:
            return cached_proto

    # layer 5 — fallback to HTTPS
    return normalized

def get_tc_demand_boost(interface, interval):
    """
    Read tc class statistics for dropped and backlogged packets.
    true_demand = scapy_throughput + dropped/interval + backlog/interval
    Returns dict: class_id → extra_bytes_per_sec
    """
    global previous_drops, previous_backlog
    tc_extra = {}

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

            if 'class htb' in line:
                if current_id is not None:
                    drops_this   = max(0, dropped - previous_drops[current_id])
                    backlog_this = max(0, backlog  - previous_backlog[current_id])
                    tc_extra[current_id] = (drops_this + backlog_this) / interval
                    previous_drops[current_id]   = dropped
                    previous_backlog[current_id] = backlog

                parts      = line.split()
                current_id = parts[2]
                dropped    = 0
                backlog    = 0

            elif current_id:
                m = re.search(r'backlog\s+(\d+)b', line)
                if m:
                    backlog = int(m.group(1))
                m = re.search(r'dropped\s+(\d+)', line)
                if m:
                    dropped = int(m.group(1))

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

    # shared result container for threading
    flows_result = [None]

    def count_packet(pkt):
        """Scapy packet counter — runs during sniff."""
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

    def run_ndpi():
        """ndpiReader runs in parallel thread — same 5 seconds."""
        flows_result[0] = get_flows(interface, interval)

    # ── Run scapy and ndpiReader simultaneously ───────────────
    # both capture the SAME 5 second window
    # total time = 5 seconds not 10 seconds
    print(f"[{time.strftime('%H:%M:%S')}] Capturing packets + nDPI for {interval} seconds...")

    ndpi_thread = threading.Thread(target=run_ndpi)
    ndpi_thread.start()

    # scapy sniff runs in main thread
    sniff(iface=interface, prn=count_packet, timeout=interval, store=False)

    # wait for ndpi thread to finish
    ndpi_thread.join(timeout=interval + 3)

    flows     = flows_result[0] or []
    ndpi_data = aggregate_flows(flows)

    print(f"[{time.strftime('%H:%M:%S')}] Processing results...")

    # get tc demand boost
    try:
        from enforce import known_devices
        class_to_ip = {v: k for k, v in known_devices.items()}
        tc_extra    = get_tc_demand_boost(interface, interval)
        ip_extra    = {}
        for class_id, extra in tc_extra.items():
            if class_id in class_to_ip:
                ip_extra[class_to_ip[class_id]] = extra
    except Exception:
        ip_extra = {}

    all_ips = set(tx_bytes.keys()) | set(rx_bytes.keys()) | set(ndpi_data.keys())

    if not all_ips:
        print("No devices detected.")
        return []

    now         = time.time()
    all_devices = []

    for ip in sorted(all_ips):

        up   = tx_bytes.get(ip, 0)
        down = rx_bytes.get(ip, 0)

        up_per_sec   = up   / interval
        down_per_sec = down / interval

        # add unsatisfied demand from tc stats
        boost        = ip_extra.get(ip, 0)
        down_per_sec = down_per_sec + boost

        # get raw nDPI protocol
        if ip in ndpi_data and ndpi_data[ip]['protocols']:
            raw_proto = max(ndpi_data[ip]['protocols'].items(),
                           key=lambda x: x[1])[0]
        else:
            raw_proto = 'UNKNOWN'

        # resolve best protocol using all 5 layers
        best_proto = resolve_best_protocol(ip, raw_proto, ndpi_data, now)
        priority   = get_priority(best_proto)

        device = {
            "ip"                       : ip,
            "up_bytes_per_sec"         : up_per_sec,
            "down_bytes_per_sec"       : down_per_sec,
            "protocol"                 : best_proto,
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
