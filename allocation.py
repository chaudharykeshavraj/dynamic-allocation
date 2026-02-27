def allocate(all_devices, download_bytes_per_sec, upload_bytes_per_sec):
    ALPHA = 0.2
    BETA  = 0.1
    EPS   = 1e-9
    IDLE_THRESHOLD = 1024      # 1 KB/sec — for background traffic
    
    number_of_devices = len(all_devices)
    if number_of_devices == 0:
        return all_devices

    # dynamic ceiling factor — shrinks headroom as more devices compete
    # 1 device → 2.0, 2 → 1.5, 4 → 1.25, 8 → 1.125
    # floor of 1.1 ensures minimum 10% headroom for bursty traffic
    DEMAND_CEIL_FACTOR = max(1.1, 1.0 + (1.0 / number_of_devices))

    fair_share_download = download_bytes_per_sec / number_of_devices
    fair_share_upload   = upload_bytes_per_sec   / number_of_devices

    full_minimum_allocation_download = fair_share_download * ALPHA
    full_minimum_allocation_upload   = fair_share_upload   * ALPHA


    traffic_max_download = EPS
    traffic_max_upload   = EPS

    for device in all_devices:
        traffic_max_download = max(traffic_max_download, device['down_bytes_per_sec'])
        traffic_max_upload   = max(traffic_max_upload,   device['up_bytes_per_sec'])

    total_minimum_download_allocated = 0.0
    total_minimum_upload_allocated   = 0.0
    total_weighted_demand_download   = 0.0
    total_weighted_demand_upload     = 0.0

    for device in all_devices:

        activity_factor_download = BETA + (1 - BETA) * (
            device['down_bytes_per_sec'] / traffic_max_download
        )
        activity_factor_upload = BETA + (1 - BETA) * (
            device['up_bytes_per_sec'] / traffic_max_upload
        )

        # clamp for safety
        activity_factor_download = max(BETA, min(1.0, activity_factor_download))
        activity_factor_upload   = max(BETA, min(1.0, activity_factor_upload))

        min_down = full_minimum_allocation_download * activity_factor_download
        min_up   = full_minimum_allocation_upload   * activity_factor_upload

        device['allocated_bytes_download'] = min_down
        device['allocated_bytes_upload']   = min_up

        total_minimum_download_allocated += min_down
        total_minimum_upload_allocated   += min_up

        total_weighted_demand_download += device['priority'] * device['down_bytes_per_sec']
        total_weighted_demand_upload   += device['priority'] * device['up_bytes_per_sec']

    # -------------------------------------------------
    # Capacity guard — scale ONLY if exceeding
    # -------------------------------------------------
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

    # -------------------------------------------------
    # Phase 2 — weighted remaining allocation
    # -------------------------------------------------
    remaining_download = max(0.0, download_bytes_per_sec - total_minimum_download_allocated)
    remaining_upload   = max(0.0, upload_bytes_per_sec   - total_minimum_upload_allocated)

    # ---- Download ----
    if total_weighted_demand_download <= EPS:
        equal_share = remaining_download / number_of_devices
        for device in all_devices:
            device['allocated_bytes_download'] += equal_share
    else:
        denom = total_weighted_demand_download + EPS
        for device in all_devices:
            weight = device['priority'] * device['down_bytes_per_sec']
            device['allocated_bytes_download'] += (weight / denom) * remaining_download

    # ---- Upload ----
    if total_weighted_demand_upload <= EPS:
        equal_share = remaining_upload / number_of_devices
        for device in all_devices:
            device['allocated_bytes_upload'] += equal_share
    else:
        denom = total_weighted_demand_upload + EPS
        for device in all_devices:
            weight = device['priority'] * device['up_bytes_per_sec']
            device['allocated_bytes_upload'] += (weight / denom) * remaining_upload

    # -------------------------------------------------
    # Pool usage check — only cap when pool is busy
    # If total demand is below 70% of pool, there is enough
    # bandwidth for everyone — no need to cap and risk the
    # feedback loop (tc caps throughput → monitor reads capped
    # value → allocation stays low → device starves).
    # -------------------------------------------------
    POOL_BUSY_THRESHOLD = 0.7
    total_demand_down = sum(d['down_bytes_per_sec'] for d in all_devices)
    total_demand_up   = sum(d['up_bytes_per_sec']   for d in all_devices)

    pool_busy_down = total_demand_down > (download_bytes_per_sec * POOL_BUSY_THRESHOLD)
    pool_busy_up   = total_demand_up   > (upload_bytes_per_sec   * POOL_BUSY_THRESHOLD)

    # -------------------------------------------------
    # Phase 3 — Demand ceiling cap (only when pool is busy)
    # No device gets more than DEMAND_CEIL_FACTOR × its demand
    # Excess is collected as spare for redistribution
    # -------------------------------------------------
    spare_download = 0.0
    spare_upload   = 0.0
    capped_down    = set()
    capped_up      = set()

    for i, device in enumerate(all_devices):
        if pool_busy_down:
            ceil_down = max(device['down_bytes_per_sec'] * DEMAND_CEIL_FACTOR, fair_share_download)
            if device['allocated_bytes_download'] > ceil_down and device['down_bytes_per_sec'] > IDLE_THRESHOLD:
                spare_download += device['allocated_bytes_download'] - ceil_down
                device['allocated_bytes_download'] = ceil_down
                capped_down.add(i)

        if pool_busy_up:
            ceil_up = max(device['up_bytes_per_sec'] * DEMAND_CEIL_FACTOR, fair_share_upload)
            if device['allocated_bytes_upload'] > ceil_up and device['up_bytes_per_sec'] > IDLE_THRESHOLD:
                spare_upload += device['allocated_bytes_upload'] - ceil_up
                device['allocated_bytes_upload'] = ceil_up
                capped_up.add(i)

    # -------------------------------------------------
    # Phase 4 — Redistribute spare to uncapped devices
    # Weighted by priority × demand
    # -------------------------------------------------
    uncapped_demand_down = sum(
        d['priority'] * d['down_bytes_per_sec']
        for i, d in enumerate(all_devices) if i not in capped_down
    )
    uncapped_demand_up = sum(
        d['priority'] * d['up_bytes_per_sec']
        for i, d in enumerate(all_devices) if i not in capped_up
    )

    if spare_download > 0 and uncapped_demand_down > EPS:
        for i, device in enumerate(all_devices):
            if i not in capped_down:
                weight = device['priority'] * device['down_bytes_per_sec']
                device['allocated_bytes_download'] += (weight / uncapped_demand_down) * spare_download

    if spare_upload > 0 and uncapped_demand_up > EPS:
        for i, device in enumerate(all_devices):
            if i not in capped_up:
                weight = device['priority'] * device['up_bytes_per_sec']
                device['allocated_bytes_upload'] += (weight / uncapped_demand_up) * spare_upload

    # =================================================
    # FINAL NORMALIZATION — HARD CAP GUARANTEE
    # =================================================
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
