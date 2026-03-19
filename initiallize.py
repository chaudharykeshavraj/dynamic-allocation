import subprocess
from ml_part.predict import initialize_all_devices, get_known_ips

# default values for devices with no trained model
DEFAULT_PRIORITY   = 1
DEFAULT_DOWN_BYTES = 100 * 1024   # 100 KB/s seed
DEFAULT_UP_BYTES   = 100 * 1024   # 100 KB/s seed
DEFAULT_PROTOCOL   = 'UNKNOWN'

def get_connected_ips(interface):
    """
    Scan ARP table to find currently connected devices.
    ARP table updated by OS when device sends any packet.
    Returns list of IPs currently on the network.
    """
    connected = []

    try:
        result = subprocess.run(
            ['arp', '-a', '-i', interface],
            capture_output = True,
            text           = True
        )

        for line in result.stdout.splitlines():
            # arp format: hostname (192.168.4.72) at xx:xx:xx ...
            if '(' in line and ')' in line:
                ip = line.split('(')[1].split(')')[0]
                if ip.startswith('192.168.'):
                    connected.append(ip)

    except Exception as e:
        print(f"  ARP scan error: {e}")

    return connected

def initiallize(interface, down_bps, up_bps):
    """
    Called ONCE at startup before main loop.

    Step 1 → ARP scan finds connected devices
    Step 2 → get_known_ips() from predict.py
             finds connected devices that have trained models
    Step 3 → initialize_all_devices() from predict.py
             loads last 3 rows from dataset/ per device
             predicts traffic class using trained model
             maps class to seed demand bytes
             returns device list with seed demand + nDPI priority
    Step 4 → devices WITHOUT model get default seed demand
    Step 5 → returns ALL connected devices ready for allocation.py
    """

    print("\n--- Initiallization ---")

    # step 1 — find who is connected right now via ARP
    connected_ips = get_connected_ips(interface)

    if len(connected_ips) == 0:
        print("  No connected devices found")
        return []

    print(f"  Connected devices  : {connected_ips}")

    # step 2 — get_known_ips() from predict.py
    # scans ml_part/models/ for devices with trained pkl files
    known_ips     = get_known_ips()
    with_model    = [ip for ip in connected_ips if ip     in known_ips]
    without_model = [ip for ip in connected_ips if ip not in known_ips]

    print(f"  With trained model : {with_model}")
    print(f"  Without model      : {without_model}")

    all_initial_devices = []

    # step 3 — initialize_all_devices() from predict.py
    # loads last 3 rows from dataset/ip.csv
    # predicts class → maps to seed bytes
    # priority taken from nDPI history in CSV (NOT from ML)
    if len(with_model) > 0:
        ml_devices = initialize_all_devices(with_model)
        all_initial_devices.extend(ml_devices)
        print(f"  ML initiallized    : {len(ml_devices)} devices")

    # step 4 — devices without model get default values
    for ip in without_model:
        print(f"  {ip} → no model, using defaults")

        all_initial_devices.append({
            "ip"                       : ip,
            "down_bytes_per_sec"       : DEFAULT_DOWN_BYTES,
            "up_bytes_per_sec"         : DEFAULT_UP_BYTES,
            "protocol"                 : DEFAULT_PROTOCOL,
            "priority"                 : DEFAULT_PRIORITY,
            "allocated_bytes_download" : 0,
            "allocated_bytes_upload"   : 0,
        })

    print(f"\n  Total initiallized : {len(all_initial_devices)} devices")
    return all_initial_devices