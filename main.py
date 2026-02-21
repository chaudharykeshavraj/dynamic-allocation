from monitor  import monitor
from allocation import allocate
from enforce  import enforce
from measure_bandwidth import measure_total_bandwidth

INTERFACE = 'wlp3s0'
INTERVAL  = 5

# measure once at start
print("Measuring network bandwidth...")
DOWN_BPS, UP_BPS = measure_total_bandwidth()

print(f"Download pool = {(DOWN_BPS * 8) / 1_000_000:.2f} Mbps")
print(f"Upload pool   = {(UP_BPS   * 8) / 1_000_000:.2f} Mbps")

while True:

    print("\n Step 1: Monitoring ")
    all_devices = monitor(INTERFACE, INTERVAL)

    if len(all_devices) == 0:
        print("No devices found, retrying...")
        continue

    print(f"Found {len(all_devices)} device(s)")

    print("\ Step 2: Allocating")
    all_devices = allocate(all_devices, DOWN_BPS, UP_BPS)

    print("\nStep 3: Enforcing")
    enforce(all_devices, INTERFACE, DOWN_BPS, UP_BPS)

    print("\nCycle complete, starting next")
