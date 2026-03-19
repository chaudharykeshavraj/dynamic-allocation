import signal
import sys
import webbrowser
import threading
import time
from datetime import datetime

from collection        import collect
from monitor           import monitor
from allocation        import allocate        # ← allocation.py
from enforce           import enforce, setup_tc
from measure_bandwidth import measure_total_bandwidth
from initiallize       import initiallize     # ← initiallize.py
from dashboard         import app, live_state

def signal_handler(sig, frame):
    print("\nStopping...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

INTERFACE = 'wlp3s0'
INTERVAL  = 5

# ── Dashboard ─────────────────────────────────────────────────
def start_dashboard():
    print("\n" + "="*50)
    print("Starting dashboard at http://localhost:5000")
    print("="*50 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

start_dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
start_dashboard_thread.start()
time.sleep(1.5)
webbrowser.open("http://localhost:5000")

# ── Measure Bandwidth ─────────────────────────────────────────
print("Measuring network bandwidth...")
DOWN_BPS, UP_BPS = measure_total_bandwidth()
print(f"Download pool = {(DOWN_BPS * 8) / 1_000_000:.2f} Mbps")
print(f"Upload pool   = {(UP_BPS   * 8) / 1_000_000:.2f} Mbps")

live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000

# ── Setup TC Once ─────────────────────────────────────────────
setup_tc(INTERFACE, DOWN_BPS, UP_BPS)

# ── ML Initiallization — Runs Once Before Main Loop ──────────
# initiallize() does:
#   1. ARP scan → find connected devices
#   2. devices WITH model → predict.py predicts class → seed demand
#   3. devices WITHOUT model → default seed demand
#   4. returns device list for allocation and enforce
print("\nInitiallizing devices...")
initial_devices = initiallize(INTERFACE, DOWN_BPS, UP_BPS)

if len(initial_devices) > 0:
    # allocation.py distributes total bandwidth
    # based on ML seed demand and nDPI priority
    initial_allocated = allocate(initial_devices, DOWN_BPS, UP_BPS)

    # enforce sets tc rules before monitor starts
    # devices get correct bandwidth from second 0
    enforce(initial_allocated, INTERFACE, DOWN_BPS, UP_BPS)
    print(f"tc rules applied for {len(initial_devices)} devices!")
else:
    print("No initiallization, waiting for first monitor interval...")

# ── Main Loop — Normal Reactive From Here ─────────────────────
while True:

    print("\nStep 1: Monitoring")
    all_devices = monitor(INTERFACE, INTERVAL)

    if len(all_devices) == 0:
        print("No devices found, retrying...")
        continue

    print(f"Found {len(all_devices)} device(s)")

    print("\nStep 2: Allocating")
    all_devices = allocate(all_devices, DOWN_BPS, UP_BPS)

    print("\nStep 3: Enforcing")
    enforce(all_devices, INTERFACE, DOWN_BPS, UP_BPS)

    print("\nStep 4: Saving data")
    collect(all_devices)

    print("\nStep 5: Updating dashboard")
    live_state['devices'] = all_devices
    live_state['updated'] = datetime.now()

    print("\nCycle complete, starting next")