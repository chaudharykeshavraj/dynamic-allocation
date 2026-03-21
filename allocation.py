from datetime import datetime
import csv
import os


def allocate(all_devices, download_bytes_per_sec, upload_bytes_per_sec):
    ALPHA          = 0.2
    BETA           = 0.1
    EPS            = 1e-9
    MIN_ACTIVE_BPS = 1000    # 1 KB/s — below this = idle
    MIN_IDLE_BPS   = 100     # FIX: idle gets 100 bytes/sec not 0
                             # tc rejects 0 Kbps — causes tc error

    number_of_devices = len(all_devices)
    if number_of_devices == 0:
        return all_devices

    # ── Separate active vs idle ───────────────────────────────
    active_devices = []
    idle_devices   = []

    for device in all_devices:
        is_active = (device['down_bytes_per_sec'] > MIN_ACTIVE_BPS or
                     device['up_bytes_per_sec']   > MIN_ACTIVE_BPS)
        if is_active:
            active_devices.append(device)
        else:
            idle_devices.append(device)

    print(f"  Active={len(active_devices)}  Idle={len(idle_devices)}")

    # FIX: idle gets minimum not zero
    # tc class htb rate 0kbit is invalid and causes tc error
    for device in idle_devices:
        device['allocated_bytes_download'] = float(MIN_IDLE_BPS)
        device['allocated_bytes_upload']   = float(MIN_IDLE_BPS)

    if len(active_devices) == 0:
        return all_devices

    # ── Fair share for active devices only ────────────────────
    fair_share_download = download_bytes_per_sec / len(active_devices)
    fair_share_upload   = upload_bytes_per_sec   / len(active_devices)

    full_minimum_allocation_download = fair_share_download * ALPHA
    full_minimum_allocation_upload   = fair_share_upload   * ALPHA

    traffic_max_download = EPS
    traffic_max_upload   = EPS
    for device in active_devices:
        traffic_max_download = max(traffic_max_download, device['down_bytes_per_sec'])
        traffic_max_upload   = max(traffic_max_upload,   device['up_bytes_per_sec'])

    total_minimum_download_allocated = 0.0
    total_minimum_upload_allocated   = 0.0
    total_weighted_demand_download   = 0.0
    total_weighted_demand_upload     = 0.0

    # ── Phase 1: minimum allocation ───────────────────────────
    for device in active_devices:
        activity_factor_download = BETA + (1 - BETA) * (
            device['down_bytes_per_sec'] / traffic_max_download
        )
        activity_factor_upload = BETA + (1 - BETA) * (
            device['up_bytes_per_sec'] / traffic_max_upload
        )
        activity_factor_download = max(BETA, min(1.0, activity_factor_download))
        activity_factor_upload   = max(BETA, min(1.0, activity_factor_upload))

        min_down = full_minimum_allocation_download * activity_factor_download
        min_up   = full_minimum_allocation_upload   * activity_factor_upload

        device['allocated_bytes_download'] = min_down
        device['allocated_bytes_upload']   = min_up

        total_minimum_download_allocated += min_down
        total_minimum_upload_allocated   += min_up
        total_weighted_demand_download   += device['priority'] * device['down_bytes_per_sec']
        total_weighted_demand_upload     += device['priority'] * device['up_bytes_per_sec']

    # ── Capacity guard ────────────────────────────────────────
    if total_minimum_download_allocated > download_bytes_per_sec:
        scale = download_bytes_per_sec / (total_minimum_download_allocated + EPS)
        for device in active_devices:
            device['allocated_bytes_download'] *= scale
        total_minimum_download_allocated = download_bytes_per_sec

    if total_minimum_upload_allocated > upload_bytes_per_sec:
        scale = upload_bytes_per_sec / (total_minimum_upload_allocated + EPS)
        for device in active_devices:
            device['allocated_bytes_upload'] *= scale
        total_minimum_upload_allocated = upload_bytes_per_sec

    # ── Phase 2: weighted remaining ───────────────────────────
    remaining_download = max(0.0, download_bytes_per_sec - total_minimum_download_allocated)
    remaining_upload   = max(0.0, upload_bytes_per_sec   - total_minimum_upload_allocated)

    if total_weighted_demand_download <= EPS:
        equal_share = remaining_download / len(active_devices)
        for device in active_devices:
            device['allocated_bytes_download'] += equal_share
    else:
        denom = total_weighted_demand_download + EPS
        for device in active_devices:
            weight = device['priority'] * device['down_bytes_per_sec']
            device['allocated_bytes_download'] += (weight / denom) * remaining_download

    if total_weighted_demand_upload <= EPS:
        equal_share = remaining_upload / len(active_devices)
        for device in active_devices:
            device['allocated_bytes_upload'] += equal_share
    else:
        denom = total_weighted_demand_upload + EPS
        for device in active_devices:
            weight = device['priority'] * device['up_bytes_per_sec']
            device['allocated_bytes_upload'] += (weight / denom) * remaining_upload

    # ── Demand cap with redistribution ───────────────────────
    excess_download = []
    excess_upload   = []

    for device in all_devices:
        if device['allocated_bytes_download'] > device['down_bytes_per_sec'] + EPS:
            excess = device['allocated_bytes_download'] - device['down_bytes_per_sec']
            excess_download.append((device, excess))
            device['allocated_bytes_download'] = device['down_bytes_per_sec']

        if device['allocated_bytes_upload'] > device['up_bytes_per_sec'] + EPS:
            excess = device['allocated_bytes_upload'] - device['up_bytes_per_sec']
            excess_upload.append((device, excess))
            device['allocated_bytes_upload'] = device['up_bytes_per_sec']

    if excess_download:
        total_excess  = sum(e for _, e in excess_download)
        unmet_devices = [d for d in active_devices
                         if d['allocated_bytes_download'] < d['down_bytes_per_sec'] - EPS]
        if unmet_devices:
            share = total_excess / len(unmet_devices)
            for d in unmet_devices:
                add = min(share, d['down_bytes_per_sec'] - d['allocated_bytes_download'])
                d['allocated_bytes_download'] += add

    if excess_upload:
        total_excess  = sum(e for _, e in excess_upload)
        unmet_devices = [d for d in active_devices
                         if d['allocated_bytes_upload'] < d['up_bytes_per_sec'] - EPS]
        if unmet_devices:
            share = total_excess / len(unmet_devices)
            for d in unmet_devices:
                add = min(share, d['up_bytes_per_sec'] - d['allocated_bytes_upload'])
                d['allocated_bytes_upload'] += add

    # ── Final normalization ───────────────────────────────────
    total_down = sum(d['allocated_bytes_download'] for d in all_devices)
    total_up   = sum(d['allocated_bytes_upload']   for d in all_devices)

    if total_down > download_bytes_per_sec + EPS:
        scale = download_bytes_per_sec / (total_down + EPS)
        for device in all_devices:
            device['allocated_bytes_download'] *= scale

    if total_up > upload_bytes_per_sec + EPS:
        scale = upload_bytes_per_sec / (total_up + EPS)
        for device in all_devices:
            device['allocated_bytes_upload'] *= scale

    # ── Save to CSV ───────────────────────────────────────────
    file_path  = "result/allocate_vs_demand.csv"
    file_exists = os.path.isfile(file_path)
    fieldnames = [
        "timestamp", "ip", "up_bytes_per_sec", "down_bytes_per_sec",
        "protocol", "priority", "allocated_bytes_download", "allocated_bytes_upload"
    ]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os.makedirs("result", exist_ok=True)

    with open(file_path, mode="a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        for device in all_devices:
            row             = device.copy()
            row["timestamp"] = timestamp
            writer.writerow(row)

    return all_devices
