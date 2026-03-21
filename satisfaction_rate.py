import pandas as pd
import numpy as np

# ── Config ────────────────────────────────────────────────────
WITH_SYSTEM_CSV    = '/Users/naveenkharel/Documents/allocation/allocate_vs_demand_vs_enforced 2.csv'
WITHOUT_SYSTEM_CSV = '/Users/naveenkharel/Documents/allocation/without_system.csv'

MIN_ACTIVE_BPS = 500    # ignore idle devices below this

# ── Load WITH system ──────────────────────────────────────────
dfw = pd.read_csv(WITH_SYSTEM_CSV)
dfw['timestamp'] = pd.to_datetime(dfw['timestamp'])
dfw = dfw[~dfw['ip'].isin(['192.168.4.1','192.168.4.255'])]
dfw = dfw[dfw['timestamp'] >= dfw['timestamp'].min()]
end_cut = dfw['timestamp'].min() + pd.Timedelta(seconds=408)
dfw = dfw[dfw['timestamp'] <= end_cut]

# ── Load WITHOUT system ───────────────────────────────────────
dfn = pd.read_csv(WITHOUT_SYSTEM_CSV)
dfn['timestamp'] = pd.to_datetime(dfn['timestamp'])
dfn = dfn[~dfn['ip'].isin(['192.168.4.1','192.168.4.255'])]

# ── Normalize to equal time buckets ───────────────────────────
# Both datasets cover same 6.8 min duration but different intervals
# WITH:    64 intervals @ ~6.4 sec
# WITHOUT: 80 intervals @ ~5.2 sec
# Solution: resample both to fixed 10-second buckets
# Each bucket = mean of all rows within that 10-sec window
# Result: same number of comparable buckets for both

BUCKET_SEC = 10   # bucket size in seconds

def resample_satisfaction(df, mode, bucket_sec):
    """
    Compute per-bucket average satisfaction.

    mode='with':
        satisfaction = allocated / demand  capped at 1.0
        measures: did device get what it asked for?

    mode='without':
        satisfaction = (device_share / fair_share)  capped at 1.0
        fair_share = 1 / n_active_devices
        measures: did device get its equitable portion?
    """
    # assign each row to a bucket index
    t0   = df['timestamp'].min()
    df   = df.copy()
    df['bucket'] = ((df['timestamp'] - t0).dt.total_seconds()
                    // bucket_sec).astype(int)

    bucket_sats = []

    for bucket_id in sorted(df['bucket'].unique()):
        g = df[(df['bucket'] == bucket_id) &
               (df['down_bytes_per_sec'] > MIN_ACTIVE_BPS)]

        if len(g) == 0:
            continue

        if mode == 'with':
            sats = (g['allocated_bytes_download'] /
                    (g['down_bytes_per_sec'] + 1e-9)).clip(upper=1.0)

        elif mode == 'without':
            n     = len(g)
            total = g['down_bytes_per_sec'].sum()
            sats  = ((g['down_bytes_per_sec'] / (total + 1e-9)) * n
                     ).clip(upper=1.0)

        bucket_sats.append({
            'bucket'      : bucket_id,
            'satisfaction': sats.mean(),
            'n_devices'   : len(g),
        })

    return pd.DataFrame(bucket_sats)

df_with_sat    = resample_satisfaction(dfw, 'with',    BUCKET_SEC)
df_without_sat = resample_satisfaction(dfn, 'without', BUCKET_SEC)

# ── Print Results ─────────────────────────────────────────────
avg_w = df_with_sat['satisfaction'].mean()
avg_n = df_without_sat['satisfaction'].mean()
improvement = (avg_w - avg_n) / avg_n * 100

print("=" * 58)
print("  BANDWIDTH SATISFACTION RATE  (equal 10-sec buckets)")
print("=" * 58)

print(f"\n  Bucket size     : {BUCKET_SEC} seconds")
print(f"  Buckets WITH    : {len(df_with_sat)}")
print(f"  Buckets WITHOUT : {len(df_without_sat)}")

print(f"\n{'Metric':<38} {'With':>8} {'Without':>9}")
print("-" * 58)
print(f"  {'Overall avg satisfaction':<36} {avg_w:>8.3f} {avg_n:>9.3f}")
print(f"  {'Improvement':<36} {f'+{improvement:.1f}%':>18}")
print(f"  {'Min satisfaction':<36} "
      f"{df_with_sat['satisfaction'].min():>8.3f} "
      f"{df_without_sat['satisfaction'].min():>9.3f}")
print(f"  {'Std deviation':<36} "
      f"{df_with_sat['satisfaction'].std():>8.3f} "
      f"{df_without_sat['satisfaction'].std():>9.3f}")

# per device
print(f"\n{'Per-Device Satisfaction':<38} {'With':>8} {'Without':>9}")
print("-" * 58)

IPS    = sorted(set(dfw['ip'].unique()) | set(dfn['ip'].unique()))
LABELS = {
    '192.168.4.79': 'Device A',
    '192.168.4.28': 'Device B',
    '192.168.4.72': 'Device C',
    '192.168.4.46': 'Device D',
}

for ip in IPS:
    label = LABELS.get(ip, ip)

    # with system per device
    d_w = dfw[(dfw['ip']==ip) & (dfw['down_bytes_per_sec']>MIN_ACTIVE_BPS)].copy()
    if len(d_w) > 0:
        w = (d_w['allocated_bytes_download'] /
             (d_w['down_bytes_per_sec']+1e-9)).clip(upper=1.0).mean()
    else:
        w = float('nan')

    # without system per device
    d_n_rows = []
    for ts in sorted(dfn['timestamp'].unique()):
        g = dfn[(dfn['timestamp']==ts) & (dfn['down_bytes_per_sec']>MIN_ACTIVE_BPS)]
        if len(g)==0: continue
        n     = len(g)
        total = g['down_bytes_per_sec'].sum()
        row   = g[g['ip']==ip]
        if len(row)==0: continue
        sat = min((row['down_bytes_per_sec'].iloc[0]/(total+1e-9))*n, 1.0)
        d_n_rows.append(sat)
    n_val = float(np.mean(d_n_rows)) if d_n_rows else float('nan')

    w_str = f"{w:.3f}" if not np.isnan(w) else "   N/A"
    n_str = f"{n_val:.3f}" if not np.isnan(n_val) else "    N/A"
    print(f"  {label} ({ip})  {w_str:>8} {n_str:>9}")

print("\n" + "=" * 58)
print("  DEFINITION")
print("=" * 58)
print(f"""
  With system:
    satisfaction = allocated / demand  (capped at 1.0)
    1.0 = device got everything it asked for
    <1.0 = system limited it due to congestion

  Without system:
    satisfaction = (device_share / fair_share)  (capped at 1.0)
    fair_share = 1 / n_active_devices
    1.0 = device got its equitable portion
    <1.0 = one device dominated, others were under-served

  Equal {BUCKET_SEC}-second buckets used for fair comparison.
  Raw data: WITH={len(dfw['timestamp'].unique())} intervals @ ~6.4s,
            WITHOUT={len(dfn['timestamp'].unique())} intervals @ ~5.2s
""")