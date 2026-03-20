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
PROBE_EVERY_N    = 12       # probe every 12 × 5sec = 60 seconds
interval_count   = 0
first_probe_done = False    # ensures probe runs at interval 1

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

# ── Step 1: Measure Bandwidth BEFORE tc setup ─────────────────
# must run before setup_tc so no tc ceiling interferes
# observes real free-run traffic on wlp3s0 for 10 seconds
# if traffic detected → use 90% as pool
# if no traffic → default 5 Mbps (corrected at interval 1)
print("Measuring network bandwidth...")
DOWN_BPS, UP_BPS = measure_total_bandwidth(INTERFACE)

live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000
print(f"Download pool = {(DOWN_BPS * 8) / 1_000_000:.2f} Mbps")
print(f"Upload pool   = {(UP_BPS   * 8) / 1_000_000:.2f} Mbps")

# ── Step 2: Setup TC Once ─────────────────────────────────────
# builds permanent HTB skeleton on wlp3s0 and ifb0
# called only once — device rules updated via add/update_device
setup_tc(INTERFACE, DOWN_BPS, UP_BPS)

# ── Step 3: ML Initialization ─────────────────────────────────
# ARP scan finds connected devices
# ML predicts traffic class from last 3 rows of CSV history
# devices with no model get fair share default
# allocate + enforce sets tc rules BEFORE first monitor interval
# devices get correct bandwidth from second 0
print("\nInitializing devices...")
initial_devices = initiallize(INTERFACE, DOWN_BPS, UP_BPS)

if len(initial_devices) > 0:
    initial_allocated = allocate(initial_devices, DOWN_BPS, UP_BPS)
    enforce(initial_allocated, INTERFACE, DOWN_BPS, UP_BPS)
    print(f"tc rules applied for {len(initial_devices)} devices!")
else:
    print("No devices found for initialization")
    print("Waiting for first monitor interval...")

# ── Main Loop ─────────────────────────────────────────────────
while True:

    print(f"\n{'='*55}")
    print(f"Interval {interval_count + 1}")
    print(f"{'='*55}")

    # ── Step 1: Monitor ───────────────────────────────────────
    # captures packets for 5 seconds
    # runs scapy + ndpiReader simultaneously (threading)
    # adds tc drop/backlog boost to demand estimate
    print("\nStep 1: Monitoring")
    all_devices = monitor(INTERFACE, INTERVAL)

    if len(all_devices) == 0:
        print("No devices found, retrying...")
        interval_count += 1
        continue

    print(f"Found {len(all_devices)} device(s)")

    # ── Step 2: Probe Capacity ────────────────────────────────
    # interval 1: always probe — corrects 5 Mbps startup default
    #             devices now active after ML init → real traffic visible
    # every 60 sec: probe again — corrects any capacity drift
    #               removes tc for 3 sec, observes real free-run
    #               restores tc immediately after
    if not first_probe_done:
        print("\nStep 2: First interval probe (correcting startup capacity)...")
        DOWN_BPS, UP_BPS = probe_real_capacity(
            interface            = INTERFACE,
            setup_tc_func        = setup_tc,
            reapply_devices_func = reapply_all_devices
        )
        first_probe_done = True

    elif interval_count > 0 and interval_count % PROBE_EVERY_N == 0:
        print(f"\nStep 2: Periodic probe (interval {interval_count})...")
        DOWN_BPS, UP_BPS = probe_real_capacity(
            interface            = INTERFACE,
            setup_tc_func        = setup_tc,
            reapply_devices_func = reapply_all_devices
        )

    else:
        # no probe this interval
        # fine-tune estimate using /proc/net/dev observation
        # zero network cost — just reads kernel file
        # only adjusts upward (tc ceiling prevents downward observation)
        DOWN_BPS, UP_BPS = update_bandwidth_estimate(INTERFACE)

    print(f"  Capacity → down={( DOWN_BPS*8)/1_000_000:.2f} Mbps  "
          f"up={(UP_BPS*8)/1_000_000:.2f} Mbps")

    # update dashboard with latest capacity
    live_state['down_mbps'] = (DOWN_BPS * 8) / 1_000_000
    live_state['up_mbps']   = (UP_BPS   * 8) / 1_000_000

    # ── Step 3: Allocate ──────────────────────────────────────
    # distributes DOWN_BPS and UP_BPS fairly among devices
    # phase 1: minimum allocation using activity factor
    # phase 2: weighted remaining by priority × demand
    # demand cap: no device gets more than it actually needs
    # final normalization: total never exceeds pool
    print("\nStep 3: Allocating")
    all_devices = allocate(all_devices, DOWN_BPS, UP_BPS)

    # ── Step 4: Enforce ───────────────────────────────────────
    # applies tc class change per device
    # new devices → add_device() creates class + fq_codel + filter
    # existing devices → update_device() smoothly changes rate
    # upload enforced via ifb0 interface
    print("\nStep 4: Enforcing")
    enforce(all_devices, INTERFACE, DOWN_BPS, UP_BPS)

    # ── Step 5: Collect Data ──────────────────────────────────
    # saves to every_data.csv (all devices, all intervals)
    # saves to dataset/ip.csv (per device, for ML training)
    print("\nStep 5: Saving data")
    collect(all_devices)

    # ── Step 6: Update Dashboard ──────────────────────────────
    print("\nStep 6: Updating dashboard")
    live_state['devices'] = all_devices
    live_state['updated'] = datetime.now()

    print("\nCycle complete, starting next")
    interval_count += 1