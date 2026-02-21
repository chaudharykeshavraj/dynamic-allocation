from scapy.all import sniff, IP, TCP, UDP
import ndpi

# Priority table
PROTOCOL_PRIORITY = {
    "WHATSAPP_CALL"  : 5,
    "ZOOM"           : 5,
    "SKYPE"          : 5,
    "GOOGLE_MEET"    : 5,
    "DISCORD"        : 5,
    "VOIP"           : 5,
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

def get_priority(protocol_name):
    # Convert to uppercase to match our table keys
    protocol_upper = protocol_name.upper()

    # Check if protocol exists in our table
    if protocol_upper in PROTOCOL_PRIORITY:
        return PROTOCOL_PRIORITY[protocol_upper]
    else:
        # Anything unknown gets lowest priority
        return 1

def detect_protocol(pkt):
    """Use nDPI to detect what application this packet belongs to"""
    try:
        # Create nDPI detector
        detector = ndpi.NDPIWrapper()

        # Convert scapy packet to raw bytes for nDPI
        raw_bytes = bytes(pkt)

        # nDPI detects the protocol from raw packet bytes
        result = detector.detect_protocol(raw_bytes)

        # result gives us protocol name like "YouTube", "WhatsApp" etc
        protocol_name = result.protocol_name

        return protocol_name

    except Exception as e:
        # If nDPI fails for any reason, return UNKNOWN
        return "UNKNOWN"

def measure_bandwidth(interface='wlp3s0', interval=5):

    while True:

        tx_bytes = {}
        rx_bytes = {}
        # Store detected protocol per IP
        # One device may use multiple protocols
        # We store the most common one or highest priority one
        device_protocols = {}

        def count_packet(pkt):
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                size   = len(pkt)

                # Detect protocol using nDPI
                protocol = detect_protocol(pkt)

                if src_ip.startswith("192.168."):
                    if src_ip not in tx_bytes:
                        tx_bytes[src_ip] = 0
                    tx_bytes[src_ip] = tx_bytes[src_ip] + size

                    # Update protocol for this device
                    # If new protocol has higher priority, replace old one
                    if src_ip not in device_protocols:
                        device_protocols[src_ip] = protocol
                    else:
                        old_priority = get_priority(device_protocols[src_ip])
                        new_priority = get_priority(protocol)
                        if new_priority > old_priority:
                            device_protocols[src_ip] = protocol

                if dst_ip.startswith("192.168."):
                    if dst_ip not in rx_bytes:
                        rx_bytes[dst_ip] = 0
                    rx_bytes[dst_ip] = rx_bytes[dst_ip] + size

                    if dst_ip not in device_protocols:
                        device_protocols[dst_ip] = protocol
                    else:
                        old_priority = get_priority(device_protocols[dst_ip])
                        new_priority = get_priority(protocol)
                        if new_priority > old_priority:
                            device_protocols[dst_ip] = protocol

        print(f"Watching network for {interval} seconds...")
        sniff(iface=interface, prn=count_packet, timeout=interval, store=False)

        # Collect all unique IPs
        all_ips = []
        for ip in tx_bytes:
            if ip not in all_ips:
                all_ips.append(ip)
        for ip in rx_bytes:
            if ip not in all_ips:
                all_ips.append(ip)

        # Build all_devices 2D list with priority auto assigned
        all_devices = []

        for ip in all_ips:

            if ip in tx_bytes:
                up = tx_bytes[ip]
            else:
                up = 0

            if ip in rx_bytes:
                down = rx_bytes[ip]
            else:
                down = 0

            # Get detected protocol for this device
            if ip in device_protocols:
                detected_protocol = device_protocols[ip]
            else:
                detected_protocol = "UNKNOWN"

            # Auto assign priority based on protocol
            auto_priority = get_priority(detected_protocol)

            device = {
                "ip"               : ip,
                "up_bytes"         : up/interval,
                "down_bytes"       : down/interval,
                "protocol"         : detected_protocol,   # what app they are using
                "priority"         : auto_priority,       # auto assigned!
                "allocated_bytes_download"  : 0,
                "allocated_bytes_upload"  : 0
            }

            all_devices.append(device)

        if len(all_devices) == 0:
            print("No devices found, trying again...")
            continue

        # Print result
        print(f"\n{'='*75}")
        print(f"{'IP':<18} {'Upload':>12} {'Download':>12} {'Protocol':<15} {'Priority':>8}")
        print(f"{'='*75}")

        for device in all_devices:
            print(f"{device['ip']:<18} {device['up_bytes']:>12} {device['down_bytes']:>12} {device['protocol']:<15} {device['priority']:>8}")

        print(f"{'='*75}\n")

measure_bandwidth(interface='wlp3s0', interval=5)
