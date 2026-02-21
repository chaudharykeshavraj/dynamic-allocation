#!/usr/bin/env python3
import subprocess, json, time, sys, tempfile, os
from collections import defaultdict

# Priority table (extend as needed)
PROTOCOL_PRIORITY = {
    "WHATSAPP_CALL": 5, "ZOOM": 5, "SKYPE": 5, "GOOGLE_MEET": 5, "DISCORD": 5, "VOIP": 5,
    "STEAM": 4, "XBOX": 4, "PLAYSTATION": 4, "ROBLOX": 4,
    "YOUTUBE": 3, "NETFLIX": 3, "TIKTOK": 3, "INSTAGRAM": 3,
    "FACEBOOK": 2, "TWITTER": 2, "HTTP": 2, "HTTPS": 2, "GOOGLE_DRIVE": 2,
    "GOOGLE_SERVICES": 2, "MICROSOFT_365": 2,
    "DNS": 1, "BITTORRENT": 1, "UNKNOWN": 1,
}

# Enhanced mapping
NFSTREAM_TO_PROTOCOL = {
    "TLS.Instagram": "INSTAGRAM", "TLS.instagram": "INSTAGRAM",
    "Instagram": "INSTAGRAM", "Instagram_Video": "INSTAGRAM",
    "QUIC.Instagram": "INSTAGRAM", "TLS.graph.instagram.com": "INSTAGRAM",
    "TLS.ig": "INSTAGRAM",
    "TLS.Facebook": "FACEBOOK", "Facebook": "FACEBOOK",
    "Facebook_Video": "FACEBOOK", "Facebook_Messenger": "FACEBOOK",
    "SSL.Facebook": "FACEBOOK", "TLS.fb": "FACEBOOK", "TLS.fbcdn": "FACEBOOK",
    "QUIC.Facebook": "FACEBOOK",
    "YouTube": "YOUTUBE", "Youtube": "YOUTUBE", "YouTube_QUIC": "YOUTUBE",
    "TLS.YouTube": "YOUTUBE", "TLS.youtube": "YOUTUBE",
    "TLS.googlevideo": "YOUTUBE", "TLS.ytimg": "YOUTUBE",
    "QUIC.YouTube": "YOUTUBE",
    "QUIC": "YOUTUBE",  # generic QUIC → video
    "Google_QUIC": "YOUTUBE",
    "QUIC.GoogleServices": "GOOGLE_SERVICES",
    "WhatsApp": "WHATSAPP_CALL", "WhatsAppCall": "WHATSAPP_CALL",
    "TLS.WhatsApp": "WHATSAPP_CALL", "TLS.whatsapp": "WHATSAPP_CALL",
    "WhatsApp_VOIP": "WHATSAPP_CALL", "QUIC.WhatsApp": "WHATSAPP_CALL",
    "TLS.DoH_DoT": "DNS",
    "TLS.Microsoft365": "MICROSOFT_365",
    "TLS": "HTTPS", "SSL": "HTTPS",
    "QUIC.Google": "GOOGLE_DOWNLOAD",      # optional, if you want to separate
    "QUIC.GoogleServices": "GOOGLE_DOWNLOAD",
    "RTP": "VOIP",                          # critical!
    "RTP/AVP": "VOIP",
    "GoogleDrive": "GOOGLE_DRIVE",
    "GoogleDocs": "GOOGLE_DRIVE",
    "MS_OneDrive": "ONEDRIVE",
    "OneDrive": "ONEDRIVE",
    "BitTorrent": "BITTORRENT",
    "Bittorrent": "BITTORRENT",
    "uTorrent": "BITTORRENT",
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

def get_priority(proto):
    key = normalize_protocol(proto)
    return PROTOCOL_PRIORITY.get(key, 1)

# Simple cache
app_cache = {}  # IP -> (app, timestamp)

def get_flows(interface='wlp3s0', duration=5):
    with tempfile.NamedTemporaryFile(mode='r+', suffix='.json', delete=False) as tmp:
        tmp_filename = tmp.name
    cmd = ['ndpiReader', '-i', interface, '-s', str(duration), '-k', tmp_filename, '-K', 'json']
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
        print(f"Error: {e}")
        return []
    finally:
        if os.path.exists(tmp_filename):
            os.unlink(tmp_filename)

def aggregate_flows(flows):
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

def main(interface='wlp3s0', interval=5):
    global app_cache
    print(f"Testing nDPI on {interface} every {interval} seconds. Press Ctrl+C to stop.\n")
    try:
        while True:
            start = time.time()
            flows = get_flows(interface, interval)
            devices = aggregate_flows(flows)

            if devices:
                print(f"\n{'='*80}")
                print(f"{'IP':<18} {'Upload (KB/s)':>12} {'Download (KB/s)':>12} {'Primary Protocol':<20} {'Priority':>8}")
                print(f"{'='*80}")
                for ip, data in sorted(devices.items()):
                    if data['protocols']:
                        # Determine primary protocol by bytes
                        raw_primary = max(data['protocols'].items(), key=lambda x: x[1])[0]
                    else:
                        raw_primary = 'UNKNOWN'

                    # Apply cache for QUIC/TLS
                    now = time.time()
                    if raw_primary in ['QUIC', 'TLS'] and ip in app_cache:
                        cached_app, ts = app_cache[ip]
                        if now - ts < 30:  # 30 sec cache
                            primary = cached_app
                        else:
                            primary = raw_primary
                            del app_cache[ip]
                    else:
                        primary = raw_primary
                        # Cache specific apps
                        if primary not in ['QUIC', 'TLS', 'UNKNOWN']:
                            app_cache[ip] = (primary, now)

                    priority = get_priority(primary)
                    up_kbps = data['up'] / interval / 1024
                    down_kbps = data['down'] / interval / 1024
                    print(f"{ip:<18} {up_kbps:>12.2f} {down_kbps:>12.2f} {primary:<20} {priority:>8}")
                print(f"{'='*80}\n")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] No flows captured.")

            elapsed = time.time() - start
            if elapsed < interval:
                time.sleep(interval - elapsed)
    except KeyboardInterrupt:
        print("\nTest stopped.")

if __name__ == '__main__':
    iface = sys.argv[1] if len(sys.argv) > 1 else 'wlp3s0'
    main(iface)