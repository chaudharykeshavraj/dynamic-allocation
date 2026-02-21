import signal
import sys
import csv
import os
from datetime import datetime

from monitor  import monitor
from allocation import allocate
from enforce  import enforce
from measure_bandwidth import measure_total_bandwidth

def signal_handler(sig, frame):
    print("\nStopping...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

INTERFACE = 'wlp3s0'
INTERVAL  = 5

# Data Storage for ML
def get_csv_filename():
    """Get daily CSV filename: data/YYYY-MM-DD.csv"""
    date_str = datetime.now().strftime('%Y-%m-%d')
    os.makedirs('data', exist_ok=True)
    return f'data/{date_str}.csv'

def init_csv_headers():
    """Create CSV with headers if it doesn't exist."""
    filename = get_csv_filename()
    if not os.path.exists(filename):
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'IP', 'Upload_KB_s', 'Download_KB_s',
                'Priority', 'Allocated_Upload', 'Allocated_Download'
            ])

def save_device_data(devices):
    """Append device data to daily CSV for ML training."""
    filename = get_csv_filename()
    init_csv_headers()
    
    with open(filename, 'a', newline='') as f:
        writer = csv.writer(f)
        for device in devices:
            writer.writerow([
                device['ip'],
                f"{device.get('up_bytes', 0):.2f}",
                f"{device.get('down_bytes', 0):.2f}",
                device['priority'],
                device.get('allocated_bytes_upload', 0),
                device.get('allocated_bytes_download', 0)
            ])

# measure once at start
print("Measuring network bandwidth...")
DOWN_BPS, UP_BPS = measure_total_bandwidth()

print(f"Download pool = {(DOWN_BPS * 8) / 1_000_000:.2f} Mbps")
print(f"Upload pool   = {(UP_BPS   * 8) / 1_000_000:.2f} Mbps")

while True:

    print("\nStep 1: Monitoring ")
    all_devices = monitor(INTERFACE, INTERVAL)

    if len(all_devices) == 0:
        print("No devices found, retrying...")
        continue

    print(f"Found {len(all_devices)} device(s)")

    print("\nStep 2: Allocating")
    all_devices = allocate(all_devices, DOWN_BPS, UP_BPS)

    print("\nStep 3: Enforcing")
    enforce(all_devices, INTERFACE, DOWN_BPS, UP_BPS)

    print("\nStep 4: Saving data to CSV for ML")
    save_device_data(all_devices)
    print(f"Data saved to: {get_csv_filename()}")

    print("\nCycle complete, starting next")
