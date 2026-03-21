from datetime import datetime
import csv
import os

def allocate(all_devices, download_bytes_per_sec, upload_bytes_per_sec):
    ALPHA          = 0.2
    BETA           = 0.1
    EPS            = 1e-9
    MIN_ACTIVE_BPS = 1000   # 1 KB/s threshold for active
    MIN_IDLE_BPS   = 100    # FIX: idle gets 100 B/s not 0 (tc rejects 0kbit)

    if len(all_devices) == 0:
        return all_devices

    active_devices = []
    idle_devices   = []
    for device in all_devices:
        if (device['down_bytes_per_sec'] > MIN_ACTIVE_BPS or
                device['up_bytes_per_sec'] > MIN_ACTIVE_BPS):
            active_devices.append(device)
        else:
            idle_devices.append(device)

    print(f"  Active={len(active_devices)}  Idle={len(idle_devices)}")

    # FIX: give idle minimum not zero — tc errors on 0kbit
    for device in idle_devices:
        device['allocated_bytes_download'] = float(MIN_IDLE_BPS)
        device['allocated_bytes_upload']   = float(MIN_IDLE_BPS)

    if len(active_devices) == 0:
        return all_devices

    fair_share_download = download_bytes_per_sec / len(active_devices)
    fair_share_upload   = upload_bytes_per_sec   / len(active_devices)
    full_min_down       = fair_share_download * ALPHA
    full_min_up         = fair_share_upload   * ALPHA

    traffic_max_down = EPS
    traffic_max_up   = EPS
    for d in active_devices:
        traffic_max_down = max(traffic_max_down, d['down_bytes_per_sec'])
        traffic_max_up   = max(traffic_max_up,   d['up_bytes_per_sec'])

    total_min_down = total_min_up = 0.0
    total_w_down   = total_w_up   = 0.0

    for d in active_devices:
        af_down = max(BETA, min(1.0, BETA + (1-BETA)*(d['down_bytes_per_sec']/traffic_max_down)))
        af_up   = max(BETA, min(1.0, BETA + (1-BETA)*(d['up_bytes_per_sec']  /traffic_max_up)))
        d['allocated_bytes_download'] = full_min_down * af_down
        d['allocated_bytes_upload']   = full_min_up   * af_up
        total_min_down += d['allocated_bytes_download']
        total_min_up   += d['allocated_bytes_upload']
        total_w_down   += d['priority'] * d['down_bytes_per_sec']
        total_w_up     += d['priority'] * d['up_bytes_per_sec']

    if total_min_down > download_bytes_per_sec:
        s = download_bytes_per_sec / (total_min_down + EPS)
        for d in active_devices:
            d['allocated_bytes_download'] *= s
        total_min_down = download_bytes_per_sec

    if total_min_up > upload_bytes_per_sec:
        s = upload_bytes_per_sec / (total_min_up + EPS)
        for d in active_devices:
            d['allocated_bytes_upload'] *= s
        total_min_up = upload_bytes_per_sec

    rem_down = max(0.0, download_bytes_per_sec - total_min_down)
    rem_up   = max(0.0, upload_bytes_per_sec   - total_min_up)
    n        = len(active_devices)

    for d in active_devices:
        d['allocated_bytes_download'] += ((d['priority']*d['down_bytes_per_sec'])/(total_w_down+EPS))*rem_down if total_w_down>EPS else rem_down/n
        d['allocated_bytes_upload']   += ((d['priority']*d['up_bytes_per_sec'])  /(total_w_up  +EPS))*rem_up   if total_w_up  >EPS else rem_up  /n

    # demand cap with redistribution
    for direction in ['download', 'upload']:
        demand_key = 'down_bytes_per_sec' if direction == 'download' else 'up_bytes_per_sec'
        alloc_key  = 'allocated_bytes_download' if direction == 'download' else 'allocated_bytes_upload'
        total_excess = 0.0
        for d in all_devices:
            if d[alloc_key] > d[demand_key] + EPS:
                total_excess      += d[alloc_key] - d[demand_key]
                d[alloc_key]       = d[demand_key]
        if total_excess > 0:
            unmet = [d for d in active_devices if d[alloc_key] < d[demand_key] - EPS]
            if unmet:
                share = total_excess / len(unmet)
                for d in unmet:
                    d[alloc_key] += min(share, d[demand_key] - d[alloc_key])

    # final normalization
    total_down = sum(d['allocated_bytes_download'] for d in all_devices)
    total_up   = sum(d['allocated_bytes_upload']   for d in all_devices)
    if total_down > download_bytes_per_sec + EPS:
        s = download_bytes_per_sec / (total_down + EPS)
        for d in all_devices:
            d['allocated_bytes_download'] *= s
    if total_up > upload_bytes_per_sec + EPS:
        s = upload_bytes_per_sec / (total_up + EPS)
        for d in all_devices:
            d['allocated_bytes_upload'] *= s

    return all_devices
