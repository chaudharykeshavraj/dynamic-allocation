import signal
import sys
import csv
import os
from datetime import datetime

from collection import collect
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

    collect(all_devices)

    print("\nCycle complete, starting next")
