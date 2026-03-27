from scapy.all import sniff, IP, TCP, UDP, Raw
import subprocess
import json
import tempfile
import os
import time
import re
import threading
from collections import defaultdict

# ── tc boost tracking ─────────────────────────────────────────
_prev_drops_down   = defaultdict(int)
_prev_drops_up     = defaultdict(int)
_prev_backlog_down = defaultdict(int)
_prev_backlog_up   = defaultdict(int)

AVG_PACKET_SIZE = 1200   # tc drops PACKETS not bytes

# ── RFC 4594 Traffic Classes → Internal Priority ──────────────
#
# RFC 4594 classifies traffic by LATENCY SENSITIVITY and ability
# to recover from bandwidth shortage, not by social importance.
#
# RFC 4594 Class          DSCP   Priority  Rationale
# ─────────────────────────────────────────────────────────────
# Telephony (VoIP)        EF     5         <10ms latency, no buffer
# Multimedia Conferencing AF41   5         Video call, interactive
# Real-Time Interactive   CS4    4         Gaming: loss = unplayable
# Multimedia Streaming    AF31   3         Buffered, degrades gracefully
# Broadcast Video         CS3    3         Live stream, some buffer
# Low-Latency Data        AF21   2         Web/social: elastic, retryable
# High-Throughput Data    AF11   2         Downloads: fully elastic
# Standard / Best Effort  DF     1         Background, unknown
# Low-Priority Data       CS1    1         Bulk, scavenger traffic

# ── Class 5: Telephony + Multimedia Conferencing (EF/AF41) ────
TELEPHONY_CLASS = {
    "ZOOM", "MICROSOFT_TEAMS", "GOOGLE_MEET",
    "VIBER_CALL", "RTP", "FACETIME",
    "FACEBOOK_VOIP", "STUN.FacebookVOIP",  # Added missing Facebook VoIP
}

# ── Class 4: Real-Time Interactive (CS4) ──────────────────────
REALTIME_INTERACTIVE_CLASS = {
    "STEAM", "XBOX", "PLAYSTATION", "ROBLOX",
    "PUBG", "SUPERCELL", "FREEFIRE", "MOBILELEGENDS",
}

# ── Class 3: Multimedia Streaming (AF31/CS3) ──────────────────
MULTIMEDIA_STREAMING_CLASS = {
    "YOUTUBE", "NETFLIX", "TIKTOK", "INSTAGRAM",
    "SPOTIFY", "APPLEPUSH", "APNS", "APPLE", "SNAPCHAT", "EDUCATION",
    "ESEWA", "KHALTI", "CONNECTIPS", "BANKING",
}

# ── Class 2: Low-Latency / High-Throughput Data (AF21/AF11) ───
LOW_LATENCY_DATA_CLASS = {
    "VIBER_MESSAGE", "FACEBOOK", "TWITTER", "WHATSAPP_MESSAGE", "DISCORD_MESSAGE",
    "MEROSHARE", "HAMROPATRO", "BUSSEWA",
    "INDRIVE", "YANGO", "OPENAI", "ANTHROPIC",
    "HTTP", "HTTPS", "HTTP_PROXY", "GOOGLE_PLAY",
}

# ── Class 1: Standard / Low-Priority (DF/CS1) ─────────────────
BEST_EFFORT_CLASS = {
    "BITTORRENT", "UNKNOWN",
}

# ── Build flat PROTOCOL_PRIORITY from class sets ──────────────
_CLASS_TO_PRIORITY = [
    (TELEPHONY_CLASS,            5),
    (REALTIME_INTERACTIVE_CLASS, 4),
    (MULTIMEDIA_STREAMING_CLASS, 3),
    (LOW_LATENCY_DATA_CLASS,     2),
    (BEST_EFFORT_CLASS,          1),
]

PROTOCOL_PRIORITY = {}
for _class_set, _priority in _CLASS_TO_PRIORITY:
    for _proto in _class_set:
        PROTOCOL_PRIORITY[_proto] = _priority

# ── nDPI/ndpiReader → Our Protocol ───────────────────────────
NFSTREAM_TO_PROTOCOL = {
    "TLS.Instagram": "INSTAGRAM", "Instagram": "INSTAGRAM",
    "Instagram_Video": "INSTAGRAM", "QUIC.Instagram": "INSTAGRAM",
    "TLS.Facebook": "FACEBOOK", "Facebook": "FACEBOOK",
    "Facebook_Video": "FACEBOOK", "QUIC.Facebook": "FACEBOOK",
    "DNS.Facebook": "FACEBOOK", "DNS.FACEBOOK": "FACEBOOK",
    "STUN.FacebookVOIP": "FACEBOOK_VOIP",  # Changed from FACEBOOK to FACEBOOK_VOIP
    "STUN.FACEBOOKVOIP": "FACEBOOK_VOIP",
    "YouTube": "YOUTUBE", "Youtube": "YOUTUBE", "YouTube_QUIC": "YOUTUBE",
    "QUIC.YouTube": "YOUTUBE", "DNS.YouTube": "YOUTUBE",
    "GoogleVideo": "YOUTUBE",
    "WhatsApp": "WHATSAPP_MESSAGE", "WhatsAppCall": "WHATSAPP_MESSAGE",
    "TLS.WhatsApp": "WHATSAPP_MESSAGE", "WhatsApp_VOIP": "WHATSAPP_MESSAGE",
    "WhatsAppFiles": "WHATSAPP_MESSAGE", "DNS.WhatsApp": "WHATSAPP_MESSAGE",
    "Viber": "VIBER_MESSAGE", "ViberCall": "VIBER_CALL",
    "Viber_VOIP": "VIBER_CALL", "QUIC.Viber": "VIBER_CALL",
    "DNS.Viber": "VIBER_MESSAGE",
    "Zoom": "ZOOM", "DNS.Zoom": "ZOOM",
    "GoogleMeet": "GOOGLE_MEET", "Google_Meet": "GOOGLE_MEET",
    "DNS.GoogleMeet": "GOOGLE_MEET",
    "Discord": "DISCORD_MESSAGE", "DNS.Discord": "DISCORD_MESSAGE",
    "Skype": "MICROSOFT_TEAMS", "SkypeTeams": "MICROSOFT_TEAMS",
    "SKYPE_TEAMS": "MICROSOFT_TEAMS", "MicrosoftTeams": "MICROSOFT_TEAMS",
    "RTP": "RTP", "RTCP": "RTP", "SIP": "RTP", "STUN": "RTP",
    "TikTok": "TIKTOK", "DNS.TikTok": "TIKTOK",
    "Netflix": "NETFLIX", "DNS.Netflix": "NETFLIX",
    "Twitter": "TWITTER", "DNS.Twitter": "TWITTER",
    "Steam": "STEAM", "SteamGame": "STEAM",
    "Blizzard": "SUPERCELL", "EpicGames": "PUBG", "RiotGames": "PUBG",
    "Xbox": "XBOX", "PlayStation": "PLAYSTATION", "Roblox": "ROBLOX",
    "GeForceNow": "STEAM",
    "GoogleServices": "HTTPS", "GOOGLESERVICES": "HTTPS",
    "QUIC.GoogleServices": "HTTPS", "GoogleDrive": "HTTPS",
    "MS_OneDrive": "HTTPS",
    "BitTorrent": "BITTORRENT", "Bittorrent": "BITTORRENT",
    "uTorrent": "BITTORRENT",
    "TLS": "HTTPS", "SSL": "HTTPS", "QUIC": "HTTPS",
    "Spotify": "SPOTIFY", "TLS.Spotify": "SPOTIFY",
    "QUIC.Spotify": "SPOTIFY", "DNS.Spotify": "SPOTIFY",
    "ApplePush": "APPLEPUSH", "APPLEPUSH": "APPLEPUSH",
    "AppleID": "APPLE", "Apple": "APPLE",
    "TLS.Apple": "APPLE", "DNS.Apple": "APPLE",
    "HTTP_Proxy": "HTTP_PROXY", "HTTPProxy": "HTTP_PROXY",
    "GooglePlay": "GOOGLE_PLAY", "TLS.GooglePlay": "GOOGLE_PLAY",
    "Snapchat": "SNAPCHAT", "TLS.Snapchat": "SNAPCHAT",
    "coursera": "EDUCATION", "edx": "EDUCATION", "udemy": "EDUCATION", "khanacademy": "EDUCATION",
    "duolingo": "EDUCATION", "skillshare": "EDUCATION", 
}

# ── IP Range → Protocol ───────────────────────────────────────
IP_TO_PROTOCOL = [
    ("142.250.", "YOUTUBE"), ("216.58.",  "YOUTUBE"),
    ("172.217.", "YOUTUBE"), ("74.125.",  "YOUTUBE"),
    ("216.239.", "YOUTUBE"), ("124.41.",  "YOUTUBE"),
    ("157.240.", "INSTAGRAM"), ("179.60.", "INSTAGRAM"),
    ("31.13.",   "FACEBOOK"),  ("66.220.", "FACEBOOK"),
    ("69.63.",   "FACEBOOK"),  ("103.211.","INSTAGRAM"),
    ("50.22.",   "WHATSAPP_CALL"), ("54.148.", "WHATSAPP_CALL"),
    ("23.246.",  "NETFLIX"),   ("37.77.",   "NETFLIX"),
    ("198.38.",  "NETFLIX"),
    ("161.117.", "TIKTOK"),    ("103.45.", "TIKTOK"),
    ("120.232.", "TIKTOK"),
    ("3.7.",     "ZOOM"),      ("99.79.",  "ZOOM"),
    ("170.114.", "ZOOM"),
    ("162.159.", "DISCORD_MESSAGE"),   ("66.22.",  "DISCORD_MESSAGE"),
    ("57.144.",  "SPOTIFY"),
    ("17.57.",   "APPLE"),     ("17.248.", "APPLE"),
    ("17.172.",  "APPLE"),
    ("139.5.",   "GOOGLE_PLAY"),
    ("93.184.",  "SUPERCELL"), ("185.60.", "SUPERCELL"),
    ("103.28.",  "PUBG"),      ("110.93.", "PUBG"),
    # ── Nepali services ──────────────────────────────────────
    # ("103.69.",  "ESEWA"),     ("103.1.",  "ESEWA"),
    ("202.51.",  "KHALTI"),    ("103.90.", "KHALTI"),
    ("202.166.", "CONNECTIPS"),
    ("202.79.",  "MEROSHARE"),
    # ── Other ────────────────────────────────────────────────
    ("5.0.",     "VIBER_CALL"),  ("45.33.", "VIBER_MESSAGE"),
    ("108.177.", "GOOGLE_MEET"), ("185.25.", "STEAM"),
]

# ── Port → Protocol ───────────────────────────────────────────
PORT_TO_PROTOCOL = {
    10012: "PUBG",    7777:  "PUBG",
    9339:  "SUPERCELL", 9340: "SUPERCELL",
    40000: "MOBILELEGENDS", 5555: "MOBILELEGENDS",
    5060:  "RTP",  5061: "RTP", 3478: "RTP", 3479: "RTP",
    4244:  "WHATSAPP_CALL", 5242: "WHATSAPP_CALL",
    8801:  "ZOOM", 8802: "ZOOM",
    50000: "DISCORD_MESSAGE",
    5222:  "SPOTIFY",
    5228:  "GOOGLE_PLAY",
    2195:  "APPLEPUSH", 2196: "APPLEPUSH",
}

# ── SNI Domain → Protocol ─────────────────────────────────────
# SNI (Server Name Indication) is transmitted in plaintext inside
# the TLS ClientHello handshake — visible even for HTTPS traffic.
# This allows detection of any TLS-based application by its domain
# name without relying on nDPI's fixed protocol database.
# This is the primary method for detecting Nepali apps and any
# other apps not in nDPI's database.

SNI_TO_PROTOCOL = {
    # ── Nepali fintech ────────────────────────────────────────
    "esewa.com.np"           : "ESEWA",
    "esewa.com"              : "ESEWA",
    "khalti.com"             : "KHALTI",
    "api.khalti.com"         : "KHALTI",
    "connectips.com"         : "CONNECTIPS",
    "nchl.com.np"            : "CONNECTIPS",
    "meroshare.com.np"       : "MEROSHARE",
    "meroshare.cdsc.com.np"  : "MEROSHARE",
    # ── Nepali apps ───────────────────────────────────────────
    "hamropatro.com"         : "HAMROPATRO",
    "bussewa.com"            : "BUSSEWA",
    "api.bussewa.com"        : "BUSSEWA",
    "indrive.com"            : "INDRIVE",
    "yango.com"              : "YANGO",
    # ── Nepali banking ────────────────────────────────────────
    "nabilbank.com"          : "BANKING",
    "nimb.com.np"            : "BANKING",
    "everestbankltd.com"     : "BANKING",
    "nicasiabank.com"        : "BANKING",
    "kumaribank.com"         : "BANKING",
    "primecommercialbank.com": "BANKING",
    "siddarthbank.com"       : "BANKING",
    "globalimebank.com"      : "BANKING",
    "laxmisunrise.com"       : "BANKING",
    "citizensbank.com"       : "BANKING",
    # ── International ─────────────────────────────────────────
    "api.openai.com"         : "OPENAI",
    "chatgpt.com"            : "OPENAI",
    "claude.ai"              : "ANTHROPIC",
    "meet.google.com"        : "GOOGLE_MEET",
    "snapchat.com"           : "SNAPCHAT",
    "sc-cdn.net"             : "SNAPCHAT",
    "open.spotify.com"       : "SPOTIFY",
    "spclient.wg.spotify.com": "SPOTIFY",
    "facebook.com"           : "FACEBOOK",
    "facebook.net"           : "FACEBOOK",
    "instagram.com"          : "INSTAGRAM",
    "youtube.com"            : "YOUTUBE",
    "discord.com"            : "DISCORD_MESSAGE",
    "discordapp.com"         : "DISCORD_MESSAGE",
    "gateway.discord.gg"     : "DISCORD_MESSAGE",
    "googlevideo.com"        : "YOUTUBE",
    "ytimg.com"              : "YOUTUBE",
    "netflix.com"            : "NETFLIX",
    "nflxvideo.net"          : "NETFLIX",
    "cdninstagram.com"       : "INSTAGRAM",
    "fbcdn.net"              : "FACEBOOK",
    "whatsapp.com"           : "WHATSAPP_MESSAGE",
    "whatsapp.net"           : "WHATSAPP_MESSAGE",
    "zoom.com"               : "ZOOM",
    "tiktok.com"             : "TIKTOK",
    "tiktokcdn.com"          : "TIKTOK",
    "roblox.com"             : "ROBLOX",
    "rbxcdn.com"             : "ROBLOX",
    "store.steampowered.com" : "STEAM",
    "steamcommunity.com"     : "STEAM",
    # ── Education ─────────────────────
    "coursera.org"           : "EDUCATION",
    "edx.org"                : "EDUCATION",
    "udemy.com"              : "EDUCATION",
    "khanacademy.org"        : "EDUCATION",
    "duolingo.com"           : "EDUCATION",
    "skillshare.com"         : "EDUCATION"
}

# SNI cache: ip → (protocol, timestamp)
_sni_cache         = {}
_sni_cache_timeout = 60   # SNI valid for 2 minutes

# Protocol cache and confidence
_protocol_cache      = {}
_protocol_confidence = defaultdict(int)
_cache_timeout_secs  = 60
MIN_CONFIDENCE       = 3

# IPs that should never be treated as end devices
EXCLUDED_DEVICE_IPS = {
    "192.168.4.1",   # local gateway
    "192.168.4.255", # broadcast address seen in some captures
    "192.168.1.100", "192.168.1.5", "192.168.101.4", "192.168.101.8",
    "192.168.1.21", "192.168.1.65", "192.168.101.16"
}


def extract_sni(payload: bytes) -> str:
    """
    Parse TLS ClientHello to extract the SNI hostname.

    TLS ClientHello byte layout:
      [0]      Content Type  = 0x16 (Handshake)
      [1-2]    TLS Version
      [3-4]    Record Length
      [5]      Handshake Type = 0x01 (ClientHello)
      [6-8]    Handshake Length
      [9-10]   Client Version
      [11-42]  Random (32 bytes)
      [43]     Session ID Length
      [...]    Session ID
      [...]    Cipher Suites Length + Cipher Suites
      [...]    Compression Methods Length + Methods
      [...]    Extensions Length
      [...]    Extensions list:
                 Each extension:
                   2 bytes Type
                   2 bytes Data Length
                   N bytes Data
               SNI Extension (Type = 0x0000):
                   2 bytes Server Name List Length
                   1 byte  Name Type (0x00 = host_name)
                   2 bytes Name Length
                   N bytes Hostname (ASCII)
    """
    try:
        if len(payload) < 6:
            return None
        if payload[0] != 0x16:        # not TLS Handshake
            return None
        if payload[5] != 0x01:        # not ClientHello
            return None

        pos = 43
        if pos >= len(payload):
            return None

        # skip session id
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return None

        # skip cipher suites
        cipher_len = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2 + cipher_len
        if pos + 1 > len(payload):
            return None

        # skip compression methods
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None

        # parse extensions
        ext_total = int.from_bytes(payload[pos:pos+2], 'big')
        pos += 2
        end = pos + ext_total

        while pos + 4 <= end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos+2],   'big')
            ext_len  = int.from_bytes(payload[pos+2:pos+4], 'big')
            pos += 4

            if ext_type == 0x0000:   # SNI extension type
                if pos + 2 > len(payload):
                    break
                pos += 2             # skip server name list length
                if pos + 1 > len(payload):
                    break
                name_type = payload[pos]
                pos += 1
                if name_type != 0x00:
                    break            # only host_name (0x00) supported
                if pos + 2 > len(payload):
                    break
                name_len = int.from_bytes(payload[pos:pos+2], 'big')
                pos += 2
                if pos + name_len > len(payload):
                    break
                sni = payload[pos:pos+name_len].decode('ascii', errors='ignore')
                return sni.lower().strip()

            pos += ext_len

    except Exception:
        pass
    return None


def identify_from_sni(sni: str) -> str:
    """
    Match SNI hostname against SNI_TO_PROTOCOL table.
    Checks exact match first then suffix match for subdomains.
    e.g. 'api.esewa.com.np' matches entry 'esewa.com.np'
    """
    if not sni:
        return None
    if sni in SNI_TO_PROTOCOL:
        return SNI_TO_PROTOCOL[sni]
    for domain, protocol in SNI_TO_PROTOCOL.items():
        if sni.endswith('.' + domain):
            return protocol
    return None


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
            mapped   = NFSTREAM_TO_PROTOCOL.get(stripped)
            if mapped:
                return mapped
            mapped = NFSTREAM_TO_PROTOCOL.get(stripped.upper())
            if mapped:
                return mapped
    return proto.upper()


def get_priority(protocol_name):
    return PROTOCOL_PRIORITY.get(normalize_protocol(protocol_name), 1)


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
        src_ip   = f.get('src_ip')
        dst_ip   = f.get('dest_ip')
        dst_port = f.get('dest_port', 0)
        proto    = f.get('ndpi', {}).get('proto', 'UNKNOWN')
        xfer     = f.get('xfer', {})
        up_bytes   = xfer.get('src2dst_bytes', 0)
        down_bytes = xfer.get('dst2src_bytes', 0)
        if src_ip and src_ip.startswith('192.168.'):
            devices[src_ip]['up']                      += up_bytes
            devices[src_ip]['protocols'][proto]        += up_bytes
            if dst_ip:
                devices[src_ip]['dst_ips'][dst_ip]     += up_bytes
            if dst_port:
                devices[src_ip]['dst_ports'][dst_port] += up_bytes
        if dst_ip and dst_ip.startswith('192.168.'):
            devices[dst_ip]['down']                    += down_bytes
            devices[dst_ip]['protocols'][proto]        += down_bytes
            if src_ip:
                devices[dst_ip]['dst_ips'][src_ip]     += down_bytes
            if dst_port:
                devices[dst_ip]['dst_ports'][dst_port] += down_bytes
    return devices


def resolve_best_protocol(ip, ndpi_proto, ndpi_devices, now):
    """
    6-layer protocol resolution (best → fallback):

    Layer 1: nDPI high-confidence direct match
    Layer 2: SNI cache — TLS hostname extracted by scapy
             detects any TLS app including Nepali apps
    Layer 3: IP range matching
    Layer 4: Port matching
    Layer 5: Confidence-scored cache (60 sec, MIN_CONFIDENCE=3)
    Layer 6: nDPI normalized fallback
    """
    normalized = normalize_protocol(ndpi_proto)

    # Layer 1: nDPI high-confidence
    high_confidence = (
        'WHATSAPP_CALL', 'ZOOM', 'GOOGLE_MEET', 'DISCORD',
        'VIBER_CALL', 'RTP', 'STEAM', 'XBOX', 'PLAYSTATION', 'ROBLOX',
        'PUBG', 'SUPERCELL', 'YOUTUBE', 'NETFLIX', 'TIKTOK',
        'SPOTIFY', 'MICROSOFT_TEAMS',
    )
    if normalized in high_confidence:
        _protocol_confidence[ip] = MIN_CONFIDENCE
        _protocol_cache[ip]      = (normalized, now)
        return normalized

    # Layer 2: SNI cache
    sni_entry = _sni_cache.get(ip)
    if sni_entry:
        sni_proto, sni_time = sni_entry
        if now - sni_time < _sni_cache_timeout:
            _protocol_confidence[ip] = MIN_CONFIDENCE
            _protocol_cache[ip]      = (sni_proto, now)
            return sni_proto

    cached = _protocol_cache.get(ip)
    if cached and _protocol_confidence[ip] >= MIN_CONFIDENCE:
        cached_proto, cached_time = cached
        if now - cached_time < _cache_timeout_secs:
            return cached_proto

    if ip in ndpi_devices:
        # Layer 3: IP range
        for dst_ip in sorted(ndpi_devices[ip].get('dst_ips', {}),
                             key=ndpi_devices[ip]['dst_ips'].get, reverse=True)[:5]:
            ip_proto = identify_from_ip(dst_ip)
            if ip_proto:
                _protocol_confidence[ip] = _protocol_confidence.get(ip, 0) + 1
                if _protocol_confidence[ip] >= MIN_CONFIDENCE:
                    _protocol_cache[ip] = (ip_proto, now)
                return ip_proto

        # Layer 4: Port
        for port in sorted(ndpi_devices[ip].get('dst_ports', {}),
                           key=ndpi_devices[ip]['dst_ports'].get, reverse=True)[:3]:
            port_proto = identify_from_port(int(port))
            if port_proto:
                _protocol_confidence[ip] = _protocol_confidence.get(ip, 0) + 1
                if _protocol_confidence[ip] >= MIN_CONFIDENCE:
                    _protocol_cache[ip] = (port_proto, now)
                return port_proto

    # Layer 5: confidence cache fallback
    _protocol_confidence[ip] = max(0, _protocol_confidence.get(ip, 0) - 1)
    if cached:
        cached_proto, cached_time = cached
        if now - cached_time < _cache_timeout_secs:
            return cached_proto

    # Layer 6: nDPI fallback
    return normalized


def _parse_tc_boost(tc_output, prev_drops, prev_backlog, interval):
    extra    = {}
    curr_id  = None
    dropped  = 0
    backlog  = 0
    SKIP_IDS = {1, 999}

    for line in tc_output.splitlines():
        line = line.strip()
        m = re.search(r'class htb 1:(\d+)', line)
        if m:
            if curr_id is not None and curr_id not in SKIP_IDS:
                drops_this    = max(0, dropped - prev_drops[curr_id])
                backlog_this  = max(0, backlog  - prev_backlog[curr_id])
                dropped_bytes = drops_this * AVG_PACKET_SIZE
                if interval > 0:
                    extra[curr_id] = (dropped_bytes + backlog_this) / interval
                prev_drops[curr_id]   = dropped
                prev_backlog[curr_id] = backlog
            cid     = int(m.group(1))
            curr_id = None if cid in SKIP_IDS else cid
            dropped = backlog = 0
            continue
        if 'class fq_codel' in line:
            curr_id = None
            continue
        if curr_id is not None and curr_id not in SKIP_IDS:
            m = re.search(r'backlog\s+(\d+)b', line)
            if m:
                backlog = int(m.group(1))
            m = re.search(r'dropped\s+(\d+)', line)
            if m:
                dropped = int(m.group(1))

    if curr_id is not None and curr_id not in SKIP_IDS:
        drops_this    = max(0, dropped - prev_drops[curr_id])
        backlog_this  = max(0, backlog  - prev_backlog[curr_id])
        dropped_bytes = drops_this * AVG_PACKET_SIZE
        if interval > 0:
            extra[curr_id] = (dropped_bytes + backlog_this) / interval
        prev_drops[curr_id]   = dropped
        prev_backlog[curr_id] = backlog
    return extra


def get_tc_demand_boost(interface, interval):
    ip_extra_down = {}
    ip_extra_up   = {}
    try:
        from enforce import known_devices
        class_to_ip = {v: k for k, v in known_devices.items()}

        down_raw = subprocess.run(
            ['tc', '-s', 'class', 'show', 'dev', interface],
            capture_output=True, text=True).stdout
        for cid, extra in _parse_tc_boost(
                down_raw, _prev_drops_down, _prev_backlog_down, interval).items():
            if cid in class_to_ip:
                ip_extra_down[class_to_ip[cid]] = extra

        up_raw = subprocess.run(
            ['tc', '-s', 'class', 'show', 'dev', 'ifb0'],
            capture_output=True, text=True).stdout
        for cid, extra in _parse_tc_boost(
                up_raw, _prev_drops_up, _prev_backlog_up, interval).items():
            if cid in class_to_ip:
                ip_extra_up[class_to_ip[cid]] = extra
    except Exception as e:
        print(f"  tc boost error: {e}")
    return ip_extra_down, ip_extra_up


def monitor(interface='wlp3s0', interval=5):
    tx_bytes     = {}       # Upload bytes (device → internet)
    rx_bytes     = {}       # Download bytes (internet → device)
    flows_result = [None]

    def count_packet(pkt):
        """
        Scapy packet handler — two jobs:

        1. Count bytes per IP for demand measurement

        2. Extract SNI from TLS ClientHello (Layer 2 detection)
           TLS ClientHello contains the SNI hostname in plaintext
           even for HTTPS traffic. Scapy reads Raw payload bytes
           and parse_sni() walks the TLS record structure to find
           extension type 0x0000 (SNI) and decode the hostname.
           This detects eSewa, Khalti, bank apps, and any HTTPS
           app that nDPI does not have in its protocol database.
        """
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        size   = len(pkt)

        # Device uploading
        if src_ip.startswith("192.168."):
            tx_bytes[src_ip] = tx_bytes.get(src_ip, 0) + size
        # Device downloading
        if dst_ip.startswith("192.168."):
            rx_bytes[dst_ip] = rx_bytes.get(dst_ip, 0) + size

        # SNI extraction
        # ClientHello sent FROM device (src=192.168.x.x) TO internet
        if (pkt.haslayer(TCP) and pkt.haslayer(Raw)
                and src_ip.startswith("192.168.")):
            sni = extract_sni(bytes(pkt[Raw].load))
            if sni:
                proto = identify_from_sni(sni)      # Detects Nepali apps like Sewa, Yango, etc.
                if proto:
                    _sni_cache[src_ip] = (proto, time.time())
                    print(f"  [SNI] {src_ip} → {sni} → {proto}")

    def run_ndpi():
        flows_result[0] = get_flows(interface, interval)

    print(f"[{time.strftime('%H:%M:%S')}] Capturing for {interval} seconds...")
    ndpi_thread = threading.Thread(target=run_ndpi)
    ndpi_thread.start()
    sniff(iface=interface, prn=count_packet, timeout=interval, store=False)
    ndpi_thread.join(timeout=interval + 3)

    flows     = flows_result[0] or []
    ndpi_data = aggregate_flows(flows)

    ip_extra_down, ip_extra_up = get_tc_demand_boost(interface, interval)   # Call the fuction to get dropped bytes per IP

    all_ips = set(tx_bytes.keys()) | set(rx_bytes.keys()) | set(ndpi_data.keys())
    all_ips -= EXCLUDED_DEVICE_IPS
    if not all_ips:
        print("  No devices detected.")
        return []

    now         = time.time()
    all_devices = []

    for ip in sorted(all_ips):
        up_per_sec   = tx_bytes.get(ip, 0) / interval
        down_per_sec = rx_bytes.get(ip, 0) / interval

        down_per_sec += ip_extra_down.get(ip, 0)
        up_per_sec   += ip_extra_up.get(ip, 0)

        if ip in ndpi_data and ndpi_data[ip]['protocols']:
            raw_proto = max(ndpi_data[ip]['protocols'].items(),
                            key=lambda x: x[1])[0]
        else:
            raw_proto = 'UNKNOWN'

        best_proto = resolve_best_protocol(ip, raw_proto, ndpi_data, now)

        all_devices.append({
            "ip"                       : ip,
            "up_bytes_per_sec"         : up_per_sec,
            "down_bytes_per_sec"       : down_per_sec,
            "protocol"                 : best_proto,
            "priority"                 : get_priority(best_proto),
            "allocated_bytes_download" : 0,
            "allocated_bytes_upload"   : 0,
        })

    print(f"\n{'='*75}")
    print(f"{'IP':<18} {'Upload B/s':>12} {'Download B/s':>14} "
          f"{'Protocol':<15} {'Pri':>4}")
    print(f"{'='*75}")
    for d in all_devices:
        print(f"{d['ip']:<18} {d['up_bytes_per_sec']:>12.0f} "
              f"{d['down_bytes_per_sec']:>14.0f} "
              f"{d['protocol']:<15} {d['priority']:>4}")
    print(f"{'='*75}\n")
    return all_devices