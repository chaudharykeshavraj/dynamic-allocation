def allocate(all_devices, download_bytes_per_sec, upload_bytes_per_sec):
    ALPHA = 0.2
    BETA  = 0.1
    EPS   = 1e-9

    number_of_devices = len(all_devices)
    if number_of_devices == 0:
        return all_devices

    fair_share_download = download_bytes_per_sec / number_of_devices
    fair_share_upload   = upload_bytes_per_sec   / number_of_devices

    full_minimum_allocation_download = fair_share_download * ALPHA
    full_minimum_allocation_upload   = fair_share_upload   * ALPHA

    # find max traffic across all devices for activity factor
    traffic_max_download = EPS
    traffic_max_upload   = EPS
    for device in all_devices:
        traffic_max_download = max(traffic_max_download, device['down_bytes_per_sec'])
        traffic_max_upload   = max(traffic_max_upload,   device['up_bytes_per_sec'])

    total_minimum_download_allocated = 0.0
    total_minimum_upload_allocated   = 0.0
    total_weighted_demand_download   = 0.0
    total_weighted_demand_upload     = 0.0

    # phase 1 — minimum allocation using activity factor
    for device in all_devices:

        activity_factor_download = BETA + (1 - BETA) * (
            device['down_bytes_per_sec'] / traffic_max_download
        )
        activity_factor_upload = BETA + (1 - BETA) * (
            device['up_bytes_per_sec'] / traffic_max_upload
        )

        # clamp between BETA and 1.0
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

    # capacity guard — scale if minimums exceed total
    if total_minimum_download_allocated > download_bytes_per_sec:
        scale = download_bytes_per_sec / (total_minimum_download_allocated + EPS)
        for device in all_devices:
            device['allocated_bytes_download'] *= scale
        total_minimum_download_allocated = download_bytes_per_sec

    if total_minimum_upload_allocated > upload_bytes_per_sec:
        scale = upload_bytes_per_sec / (total_minimum_upload_allocated + EPS)
        for device in all_devices:
            device['allocated_bytes_upload'] *= scale
        total_minimum_upload_allocated = upload_bytes_per_sec

    # phase 2 — weighted remaining allocation
    remaining_download = max(0.0, download_bytes_per_sec - total_minimum_download_allocated)
    remaining_upload   = max(0.0, upload_bytes_per_sec   - total_minimum_upload_allocated)

    if total_weighted_demand_download <= EPS:
        equal_share = remaining_download / number_of_devices
        for device in all_devices:
            device['allocated_bytes_download'] += equal_share
    else:
        denom = total_weighted_demand_download + EPS
        for device in all_devices:
            weight = device['priority'] * device['down_bytes_per_sec']
            device['allocated_bytes_download'] += (weight / denom) * remaining_download

    if total_weighted_demand_upload <= EPS:
        equal_share = remaining_upload / number_of_devices
        for device in all_devices:
            device['allocated_bytes_upload'] += equal_share
    else:
        denom = total_weighted_demand_upload + EPS
        for device in all_devices:
            weight = device['priority'] * device['up_bytes_per_sec']
            device['allocated_bytes_upload'] += (weight / denom) * remaining_upload

    # ── YOUR CLEVER FIX ──────────────────────────────────────
    # cap allocated to actual demand
    # no device should get more than what it actually needs
    # if only 2 devices connected with low demand
    # formula was giving more than demand — this fixes it
    # in real time: allocated > demand means wasted bandwidth
    # so we cap it and let remaining go to final normalization
    for device in all_devices:
        device['allocated_bytes_download'] = min(
            device['allocated_bytes_download'],
            device['down_bytes_per_sec'] + EPS   # +EPS avoids zero issues
        )
        device['allocated_bytes_upload'] = min(
            device['allocated_bytes_upload'],
            device['up_bytes_per_sec'] + EPS
        )

    # final normalization — hard cap guarantee
    # total never exceeds pool capacity
    total_down = sum(d['allocated_bytes_download'] for d in all_devices)
    total_up   = sum(d['allocated_bytes_upload']   for d in all_devices)

    if total_down > download_bytes_per_sec:
        scale = download_bytes_per_sec / (total_down + EPS)
        for device in all_devices:
            device['allocated_bytes_download'] *= scale

    if total_up > upload_bytes_per_sec:
        scale = upload_bytes_per_sec / (total_up + EPS)
        for device in all_devices:
            device['allocated_bytes_upload'] *= scale

    return all_devices
