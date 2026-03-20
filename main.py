import signal
import sys
import webbrowser
import threading
import time
from datetime import datetime

from collection        import collect
from monitor           import monitor
from allocation        import allocate
from enforce           import enforce, setup_tc, reapply_all_devices
from measure_bandwidth import (
    measure_total_bandwidth,
    update_bandwidth_estimate,
    probe_real_capacity
)
from initiallize       import initiallize
from dashboard         import app, live_state

def signal_handler(sig, frame):
    print("\nStopping...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

INTERFACE     = 'wlp3s0'
INTERVAL      = 5
PROBE_EVERY_N = 12   # probe every 12 × 5sec = 60 seconds

# ── Dashboard ─────────────────────────────────────────────────
def start_dashboard():
    print("\n" + "="*50)
    print("Starting dashboard at http://localhost:5000")
    print("="*50 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
dashboard_thread.start()
time.sleep(1.5)
webbrowser.open("http://localhost:5000")

# ── Step 1: Measure BEFORE tc setup ───────────────────────────
# critical — must run before setup_tc()
# no tc rules active → real WiFi capacity visible
print("Measuring WiFi capacity...")
DOWN_BPS, UP_BPS = measure_total_bandwidth(INTERFACE)

live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000

# ── Step 2: Setup tc AFTER measurement ────────────────────────
setup_tc(INTERFACE, DOWN_BPS, UP_BPS)

# ── Step 3: ML Initialization ─────────────────────────────────
print("\nInitializing devices...")
initial_devices = initiallize(INTERFACE, DOWN_BPS, UP_BPS)

if len(initial_devices) > 0:
    initial_allocated = allocate(initial_devices, DOWN_BPS, UP_BPS)
    enforce(initial_allocated, INTERFACE, DOWN_BPS, UP_BPS)
    print(f"tc rules applied for {len(initial_devices)} devices!")
else:
    print("No initialization, waiting for first monitor interval...")

# ── Main Loop ──────────────────────────────────────────────────
interval_count = 0

while True:

    print(f"\n{'='*55}")
    print(f"Interval {interval_count + 1}")
    print(f"{'='*55}")

    # ── Probe every 60 seconds ────────────────────────────────
    # removes tc briefly, observes real capacity, restores tc
    # corrects capacity estimate that tc ceiling would otherwise trap
    if interval_count > 0 and interval_count % PROBE_EVERY_N == 0:
        DOWN_BPS, UP_BPS = probe_real_capacity(
            interface           = INTERFACE,
            setup_tc_func       = setup_tc,
            reapply_devices_func= reapply_all_devices
        )
        live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
        live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000

    # ── Monitor ───────────────────────────────────────────────
    print("\nStep 1: Monitoring")
    all_devices = monitor(INTERFACE, INTERVAL)

    if len(all_devices) == 0:
        print("No devices found, retrying...")
        interval_count += 1
        continue

    print(f"Found {len(all_devices)} device(s)")

    # ── Fine-tune capacity every interval ─────────────────────
    # reads /proc/net/dev — zero network cost
    # only adjusts upward — prevents tc ceiling trapping estimate
    DOWN_BPS, UP_BPS = update_bandwidth_estimate(INTERFACE)
    print(f"Capacity → down={( DOWN_BPS*8)/1_000_000:.2f} Mbps  up={(UP_BPS*8)/1_000_000:.2f} Mbps")

    live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
    live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000

    # ── Allocate ──────────────────────────────────────────────
    print("\nStep 2: Allocating")
    all_devices = allocate(all_devices, DOWN_BPS, UP_BPS)

    # ── Enforce ───────────────────────────────────────────────
    print("\nStep 3: Enforcing")
    enforce(all_devices, INTERFACE, DOWN_BPS, UP_BPS)

    # ── Collect ───────────────────────────────────────────────
    print("\nStep 4: Saving data")
    collect(all_devices)

    # ── Dashboard ─────────────────────────────────────────────
    print("\nStep 5: Updating dashboard")
    live_state['devices'] = all_devices
    live_state['updated'] = datetime.now()

    print("\nCycle complete")
    interval_count += 1