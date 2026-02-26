import signal
import sys
import webbrowser
import threading
import time
from datetime import datetime

from collection import collect
from monitor  import monitor
from allocation import allocate
from enforce  import enforce
from measure_bandwidth import measure_total_bandwidth
from dashboard import app, live_state

def signal_handler(sig, frame):
    print("\nStopping...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

INTERFACE = 'wlp3s0'
INTERVAL  = 5

# Start the dashboard in a separate thread
def start_dashboard():
    print("\n" + "="*50)
    print("Starting dashboard at http://localhost:5000")
    print("="*50 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

start_dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
start_dashboard_thread.start()

# wait a moment for the dashboard to start
time.sleep(1.5)
webbrowser.open("http://localhost:5000")

# measure once at start
print("Measuring network bandwidth...")
DOWN_BPS, UP_BPS = measure_total_bandwidth()

print(f"Download pool = {(DOWN_BPS * 8) / 1_000_000:.2f} Mbps")
print(f"Upload pool   = {(UP_BPS   * 8) / 1_000_000:.2f} Mbps")

# push initial pool values to dashboard
live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000


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

    print("\nStep 5: Updating dashboard")
    live_state['devices'] = all_devices
    live_state['updated'] = datetime.now()

    print("\nCycle complete, starting next")
