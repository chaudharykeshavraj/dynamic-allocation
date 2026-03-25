from datetime import datetime
import csv
import os

def allocate(all_devices, download_bytes_per_sec, upload_bytes_per_sec):
    ALPHA = 0.2      # Equation 4.4: fraction of fair share
    BETA = 0.1       # Equation 4.5: baseline for idle devices
    EPS = 1e-9
    MIN_ACTIVE_BPS = 1000  # 1 KB/s threshold for active detection

    if len(all_devices) == 0:
        return all_devices

    # Step 1: Classify devices as active or idle
    active_devices = []
    idle_devices = []
    for device in all_devices:
        if (device['down_bytes_per_sec'] > MIN_ACTIVE_BPS or
                device['up_bytes_per_sec'] > MIN_ACTIVE_BPS):
            active_devices.append(device)
        else:
            idle_devices.append(device)

    print(f"  Active={len(active_devices)}  Idle={len(idle_devices)}")

    # Equation 4.3: Fair Share
    n_total = len(all_devices)
    fair_share_down = download_bytes_per_sec / n_total
    fair_share_up = upload_bytes_per_sec / n_total

    # Equation 4.4: Full Minimum Allocation
    full_min_down = ALPHA * fair_share_down
    full_min_up = ALPHA * fair_share_up

    print(f"  Fair Share: Down={fair_share_down/1e6:.2f} Mbps, Up={fair_share_up/1e6:.2f} Mbps")
    print(f"  Full Minimum: Down={full_min_down/1e6:.2f} Mbps, Up={full_min_up/1e6:.2f} Mbps")

    # Find maximum traffic for scaling (Equation 4.5 denominator)
    traffic_max_down = max([d['down_bytes_per_sec'] for d in all_devices] + [EPS])
    traffic_max_up = max([d['up_bytes_per_sec'] for d in all_devices] + [EPS])

    # Equation 4.5 & 4.6: Calculate Minimum Bandwidth for each device
    for device in all_devices:
        # Equation 4.5: Activity Factor
        if device in active_devices:
            # Active device: Activity Factor based on its traffic
            af_down = max(BETA, min(1.0, BETA + (1-BETA)*(device['down_bytes_per_sec']/traffic_max_down)))
            af_up = max(BETA, min(1.0, BETA + (1-BETA)*(device['up_bytes_per_sec']/traffic_max_up)))
        else:
            # Idle device: Activity Factor = BETA
            af_down = BETA
            af_up = BETA

        # Equation 4.6: Minimum Bandwidth_i = Full Minimum × Activity Factor
        device['allocated_bytes_download'] = full_min_down * af_down
        device['allocated_bytes_upload'] = full_min_up * af_up

    # Calculate total minimum allocation
    total_min_down = sum(d['allocated_bytes_download'] for d in all_devices)
    total_min_up = sum(d['allocated_bytes_upload'] for d in all_devices)

    print(f"  Total Minimum: Down={total_min_down/1e6:.2f} Mbps, Up={total_min_up/1e6:.2f} Mbps")

    # If minimum exceeds pool, scale down (safety)
    if total_min_down > download_bytes_per_sec:
        s = download_bytes_per_sec / (total_min_down + EPS)
        for d in all_devices:
            d['allocated_bytes_download'] *= s
        total_min_down = download_bytes_per_sec
        print(f"  Scaled down minimum due to pool limit")

    if total_min_up > upload_bytes_per_sec:
        s = upload_bytes_per_sec / (total_min_up + EPS)
        for d in all_devices:
            d['allocated_bytes_upload'] *= s
        total_min_up = upload_bytes_per_sec
        print(f"  Scaled down minimum due to pool limit")

    # Equation 4.7: Remaining Bandwidth
    rem_down = max(0.0, download_bytes_per_sec - total_min_down)
    rem_up = max(0.0, upload_bytes_per_sec - total_min_up)

    print(f"  Remaining: Down={rem_down/1e6:.2f} Mbps, Up={rem_up/1e6:.2f} Mbps")

    # If no remaining bandwidth or no active devices, return
    if (rem_down <= EPS and rem_up <= EPS) or len(active_devices) == 0:
        return all_devices

    # Calculate weighted demand for active devices only (Equation 4.8)
    # Weighted Demand = Priority × Demand
    total_weighted_down = 0
    total_weighted_up = 0

    for device in active_devices:
        device['weighted_down'] = device['priority'] * device['down_bytes_per_sec']
        device['weighted_up'] = device['priority'] * device['up_bytes_per_sec']
        total_weighted_down += device['weighted_down']
        total_weighted_up += device['weighted_up']

    print(f"  Weighted Demand (Priority × Demand):")
    for device in active_devices:
        print(f"    {device['ip']}: priority={device['priority']}, demand={device['down_bytes_per_sec']/1e6:.2f} Mbps, "
              f"weighted={device['weighted_down']/1e6:.2f}")

    # Distribute remaining bandwidth based on weighted demand (Equation 4.9)
    if total_weighted_down > EPS:
        for device in active_devices:
            share = device['weighted_down'] / total_weighted_down
            extra = rem_down * share
            device['allocated_bytes_download'] += extra
            print(f"    {device['ip']}: share={share:.2%}, extra={extra/1e6:.2f} Mbps")
    else:
        # Equal share if no weighted demand (should not happen with active devices, but safe)
        equal_share = rem_down / len(active_devices)
        for device in active_devices:
            device['allocated_bytes_download'] += equal_share

    if total_weighted_up > EPS:
        for device in active_devices:
            share = device['weighted_up'] / total_weighted_up
            extra = rem_up * share
            device['allocated_bytes_upload'] += extra
    else:
        equal_share = rem_up / len(active_devices)
        for device in active_devices:
            device['allocated_bytes_upload'] += equal_share

    # Final normalization to ensure we don't exceed pool
    total_down = sum(d['allocated_bytes_download'] for d in all_devices)
    total_up = sum(d['allocated_bytes_upload'] for d in all_devices)

    if total_down > download_bytes_per_sec + EPS:
        s = download_bytes_per_sec / (total_down + EPS)
        for d in all_devices:
            d['allocated_bytes_download'] *= s
    if total_up > upload_bytes_per_sec + EPS:
        s = upload_bytes_per_sec / (total_up + EPS)
        for d in all_devices:
            d['allocated_bytes_upload'] *= s

    # Print final allocation
    print(f"\n  Final Allocation (Equation 4.10):")
    for device in all_devices:
        status = "Active" if device in active_devices else "Idle"
        print(f"    {device['ip']} ({status}): Down={device['allocated_bytes_download']/1e6:.2f} Mbps, "
              f"Up={device['allocated_bytes_upload']/1e6:.2f} Mbps")

    total_allocated_down = sum(d['allocated_bytes_download'] for d in all_devices)
    total_allocated_up = sum(d['allocated_bytes_upload'] for d in all_devices)
    print(f"  Total: Down={total_allocated_down/1e6:.2f} Mbps / {download_bytes_per_sec/1e6:.2f} Mbps "
          f"Up={total_allocated_up/1e6:.2f} Mbps / {upload_bytes_per_sec/1e6:.2f} Mbps")

    return all_devices