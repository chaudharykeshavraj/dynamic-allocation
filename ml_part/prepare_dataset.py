import pandas as pd
import numpy as np
import os

# ── Path Setup ────────────────────────────────────────────────
ML_DIR        = os.path.dirname(os.path.abspath(__file__))
BASE_DIR      = os.path.dirname(ML_DIR)

DEVICE_FOLDER = os.path.join(BASE_DIR, 'dataset')
OUTPUT_FOLDER = os.path.join(ML_DIR, 'training')

WINDOW_SIZE   = 3

# ── Data-Driven Thresholds ────────────────────────────────────
# derived from quartile analysis of 134 minutes real traffic data
# 5 devices, 5348 rows total
# each class = exactly 25% of observed traffic

THRESHOLD_IDLE_LOW    = 150       # 25th percentile = 150 bytes/sec
THRESHOLD_LOW_MEDIUM  = 6446      # 50th percentile = 6446 bytes/sec
THRESHOLD_MEDIUM_HIGH = 299445    # 75th percentile = 299445 bytes/sec

# ── Protocol Map ──────────────────────────────────────────────
PROTOCOL_MAP = {
    'YOUTUBE'        : 0,
    'ZOOM'           : 1,
    'INSTAGRAM'      : 2,
    'FACEBOOK'       : 3,
    'WHATSAPP_CALL'  : 4,
    'BITTORRENT'     : 5,
    'HTTPS'          : 6,
    'HTTP'           : 7,
    'STEAM'          : 8,
    'XBOX'           : 9,
    'PLAYSTATION'    : 10,
    'ROBLOX'         : 11,
    'NETFLIX'        : 12,
    'TIKTOK'         : 13,
    'DISCORD'        : 14,
    'GOOGLE_MEET'    : 15,
    'SKYPE'          : 16,
    'VIBER_CALL'     : 17,
    'VIBER_MESSAGE'  : 18,
    'RTP'            : 19,
    'GOOGLE_DRIVE'   : 20,
    'ONEDRIVE'       : 21,
    'UNKNOWN'        : 22,
}

def encode_protocol(protocol_str):
    """Convert protocol string to integer. Unknown = 22."""
    return PROTOCOL_MAP.get(str(protocol_str).upper(), 22)

def get_traffic_class(bytes_per_sec):
    """
    Convert bytes/sec to traffic class using data-driven thresholds.
    Thresholds derived from quartile analysis of real traffic data.
    Gives balanced 25% distribution per class.

    Class 0 = IDLE   → below 150 bytes/sec     (near zero activity)
    Class 1 = LOW    → 150 to 6446 bytes/sec    (light background)
    Class 2 = MEDIUM → 6446 to 299445 bytes/sec (moderate usage)
    Class 3 = HIGH   → above 299445 bytes/sec   (heavy streaming)
    """
    if bytes_per_sec < THRESHOLD_IDLE_LOW:
        return 0   # IDLE
    elif bytes_per_sec < THRESHOLD_LOW_MEDIUM:
        return 1   # LOW
    elif bytes_per_sec < THRESHOLD_MEDIUM_HIGH:
        return 2   # MEDIUM
    else:
        return 3   # HIGH

def compute_features(d1, d2, d3):
    """
    Compute all features from 3 consecutive rows.
    d1 = oldest, d2 = middle, d3 = most recent.
    Same function used in both training and prediction.
    """

    down_t1 = float(d1['down_bytes_per_sec'])
    down_t2 = float(d2['down_bytes_per_sec'])
    down_t3 = float(d3['down_bytes_per_sec'])

    up_t1   = float(d1['up_bytes_per_sec'])
    up_t2   = float(d2['up_bytes_per_sec'])
    up_t3   = float(d3['up_bytes_per_sec'])

    return {

        # raw history — last 3 intervals in bytes/sec
        "down_t1"       : down_t1,
        "down_t2"       : down_t2,
        "down_t3"       : down_t3,
        "up_t1"         : up_t1,
        "up_t2"         : up_t2,
        "up_t3"         : up_t3,

        # traffic class of each interval
        # model learns class transitions better than raw bytes
        "down_class_t1" : get_traffic_class(down_t1),
        "down_class_t2" : get_traffic_class(down_t2),
        "down_class_t3" : get_traffic_class(down_t3),
        "up_class_t1"   : get_traffic_class(up_t1),
        "up_class_t2"   : get_traffic_class(up_t2),
        "up_class_t3"   : get_traffic_class(up_t3),

        # trend — is demand rising or falling
        # positive = rising, negative = falling
        "down_delta1"   : down_t2 - down_t1,   # older change
        "down_delta2"   : down_t3 - down_t2,   # recent change
        "up_delta1"     : up_t2   - up_t1,
        "up_delta2"     : up_t3   - up_t2,

        # average — smoothed baseline
        "avg_down"      : (down_t1 + down_t2 + down_t3) / 3,
        "avg_up"        : (up_t1   + up_t2   + up_t3)   / 3,

        # burstiness — high = bursty, low = smooth streaming
        "burst_down"    : max(down_t1, down_t2, down_t3) - min(down_t1, down_t2, down_t3),
        "burst_up"      : max(up_t1,   up_t2,   up_t3)   - min(up_t1,   up_t2,   up_t3),

        # ratio — near 0 = download heavy, near 1 = balanced call
        "ratio"         : up_t3 / (down_t3 + 1),

        # device info
        "priority"      : int(d3['priority']),
        "protocol"      : encode_protocol(d3['protocol']),
    }

def prepare_device(filepath, output_path):
    """
    Read one device CSV.
    Apply sliding window of size 3.
    Label = traffic class of next interval.
    Save training CSV.
    """

    df = pd.read_csv(filepath)

    if len(df) < WINDOW_SIZE + 1:
        print(f"  Skipping — only {len(df)} rows, need {WINDOW_SIZE + 1}")
        return 0

    rows = []

    for i in range(WINDOW_SIZE, len(df)):

        d1    = df.iloc[i - 3]   # oldest
        d2    = df.iloc[i - 2]   # middle
        d3    = df.iloc[i - 1]   # most recent
        label = df.iloc[i]       # next interval → label

        feature_row = compute_features(d1, d2, d3)

        # classification labels using data-driven thresholds
        feature_row['next_down_class'] = get_traffic_class(
            float(label['down_bytes_per_sec'])
        )
        feature_row['next_up_class'] = get_traffic_class(
            float(label['up_bytes_per_sec'])
        )

        rows.append(feature_row)

    pd.DataFrame(rows).to_csv(output_path, index=False)
    return len(rows)

def prepare_all():

    if not os.path.exists(DEVICE_FOLDER):
        print(f"dataset folder not found: {DEVICE_FOLDER}")
        return

    if not os.path.exists(OUTPUT_FOLDER):
        os.makedirs(OUTPUT_FOLDER)
        print(f"Created: {OUTPUT_FOLDER}")

    device_files = [f for f in os.listdir(DEVICE_FOLDER) if f.endswith('.csv')]

    if len(device_files) == 0:
        print("No CSV files in dataset/")
        return

    total = 0
    for filename in device_files:
        filepath    = os.path.join(DEVICE_FOLDER, filename)
        output_path = os.path.join(OUTPUT_FOLDER, filename)
        print(f"Processing {filename}...")
        rows = prepare_device(filepath, output_path)
        print(f"  {rows} training rows → {output_path}")
        total += rows

    print(f"\nTotal training rows = {total}")

    # show class distribution after new thresholds
    print(f"\n=== Class Distribution With New Thresholds ===")
    all_rows = pd.concat([
        pd.read_csv(os.path.join(OUTPUT_FOLDER, f))
        for f in os.listdir(OUTPUT_FOLDER)
        if f.endswith('.csv')
    ])
    dist = all_rows['next_down_class'].value_counts().sort_index()
    names = {0:'IDLE', 1:'LOW', 2:'MEDIUM', 3:'HIGH'}
    for cls, count in dist.items():
        print(f"  {names[cls]:<8} = {count:5d} ({count/len(all_rows)*100:.1f}%)")

if __name__ == "__main__":
    prepare_all()