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
 
# ── Signal Handler ────────────────────────────────────────────
def signal_handler(sig, frame):
    print("\nStopping...")
    sys.exit(0)
 
signal.signal(signal.SIGINT, signal_handler)
 
# ── Config ────────────────────────────────────────────────────
INTERFACE        = 'wlp3s0'
INTERVAL         = 5
 
PROBE_EVERY_N    = 24   # every 120 sec (stable)
WARMUP_INTERVALS = 2    # no probe in first 2 cycles
 
MIN_MBPS = 2
MIN_BPS  = (MIN_MBPS * 1_000_000) / 8
 
interval_count   = 0
first_probe_done = False
 
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
 
# ── Step 1: Initial Bandwidth ─────────────────────────────────
print("Measuring network bandwidth...")
DOWN_BPS, UP_BPS = measure_total_bandwidth(INTERFACE)
 
# enforce minimum at start
if DOWN_BPS < MIN_BPS:
    DOWN_BPS = MIN_BPS
if UP_BPS < MIN_BPS * 0.3:
    UP_BPS = MIN_BPS * 0.3
 
live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000
 
print(f"Download pool = {live_state['down_mbps']:.2f} Mbps")
print(f"Upload pool   = {live_state['up_mbps']:.2f} Mbps")
 
# ── Step 2: Setup TC ──────────────────────────────────────────
setup_tc(INTERFACE, DOWN_BPS, UP_BPS)
 
# ── Step 3: Initialize Devices ────────────────────────────────
print("\nInitializing devices...")
initial_devices = initiallize(INTERFACE, DOWN_BPS, UP_BPS)
 
if len(initial_devices) > 0:
    initial_allocated = allocate(initial_devices, DOWN_BPS, UP_BPS)
    enforce(initial_allocated, INTERFACE, DOWN_BPS, UP_BPS)
    print(f"tc rules applied for {len(initial_devices)} devices!")
else:
    print("No devices found for initialization")
 
# ── Main Loop ─────────────────────────────────────────────────
while True:
 
    print(f"\n{'='*55}")
    print(f"Interval {interval_count + 1}")
    print(f"{'='*55}")
 
    # ── Step 1: Monitor ───────────────────────────────────────
    print("\nStep 1: Monitoring")
    all_devices = monitor(INTERFACE, INTERVAL)
 
    if len(all_devices) == 0:
        print("No devices found, retrying...")
        interval_count += 1
        continue
 
    print(f"Found {len(all_devices)} device(s)")
 
    # ── Step 2: Capacity ──────────────────────────────────────
    # Pool is fixed — just prints utilization info
    DOWN_BPS, UP_BPS = update_bandwidth_estimate(INTERFACE)
 
    # ── HARD FLOOR (VERY IMPORTANT) ───────────────────────────
    if DOWN_BPS < MIN_BPS:
        DOWN_BPS = MIN_BPS
 
    if UP_BPS < MIN_BPS * 0.3:
        UP_BPS = MIN_BPS * 0.3
 
    print(f"  Capacity → down={(DOWN_BPS*8)/1_000_000:.2f} Mbps  "
          f"up={(UP_BPS*8)/1_000_000:.2f} Mbps")
 
    # dashboard update
    live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
    live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000
 
    # ── Step 3: Allocate ──────────────────────────────────────
    print("\nStep 3: Allocating")
    all_devices = allocate(all_devices, DOWN_BPS, UP_BPS)
 
    # ── Step 4: Enforce ───────────────────────────────────────
    print("\nStep 4: Enforcing")
    enforce(all_devices, INTERFACE, DOWN_BPS, UP_BPS)
 
    # ── Step 5: Collect ───────────────────────────────────────
    print("\nStep 5: Saving data")
    collect(all_devices)
 
    # ── Step 6: Dashboard ─────────────────────────────────────
    print("\nStep 6: Updating dashboard")
    live_state['devices'] = all_devices
    live_state['updated'] = datetime.now()
 
    print("\nCycle complete")
    interval_count += 1