import pandas as pd
import pickle
import os

from prepare_dataset import (
    compute_features,
    encode_protocol,
    get_traffic_class,
    WINDOW_SIZE,
    PROTOCOL_MAP,
    THRESHOLD_IDLE_LOW,
    THRESHOLD_LOW_MEDIUM,
    THRESHOLD_MEDIUM_HIGH,
)

# ── Path Setup ────────────────────────────────────────────────
ML_DIR        = os.path.dirname(os.path.abspath(__file__))
BASE_DIR      = os.path.dirname(ML_DIR)

DEVICE_FOLDER = os.path.join(BASE_DIR, 'dataset')
MODEL_FOLDER  = os.path.join(ML_DIR,   'models')

FEATURES = [
    "down_t1", "down_t2", "down_t3",
    "up_t1",   "up_t2",   "up_t3",
    "down_class_t1", "down_class_t2", "down_class_t3",
    "up_class_t1",   "up_class_t2",   "up_class_t3",
    "down_delta1", "down_delta2",
    "up_delta1",   "up_delta2",
    "avg_down",    "avg_up",
    "burst_down",  "burst_up",
    "ratio",
    "priority",
    "protocol",
]

CLASS_NAMES = {0: "IDLE", 1: "LOW", 2: "MEDIUM", 3: "HIGH"}

# ── Data-Driven Seed Bytes ────────────────────────────────────
# representative midpoint of each class range
# based on actual data quartiles
CLASS_TO_SEED_BYTES = {
    0 :    75,          # IDLE   → midpoint of 0 to 150 bytes/sec
    1 :  3298,          # LOW    → midpoint of 150 to 6446 bytes/sec
    2 : 152845,         # MEDIUM → midpoint of 6446 to 299445 bytes/sec
    3 : 600 * 1024,     # HIGH   → 600 KB/s representative heavy usage
}

# protocols that indicate active usage
# if ML predicts IDLE but last protocol was active
# override to LOW to give fair initial bandwidth
ACTIVE_PROTOCOLS = [
    'YOUTUBE', 'NETFLIX', 'TIKTOK', 'INSTAGRAM',
    'RTP', 'ZOOM', 'WHATSAPP_CALL', 'DISCORD',
    'GOOGLE_MEET', 'SKYPE', 'VIBER_CALL',
    'STEAM', 'PUBG', 'SUPERCELL', 'ROBLOX',
    'FACEBOOK', 'TWITTER',
]

# cache loaded models — avoid reloading pkl from disk every call
loaded_models = {}

def load_model(device_name):
    """
    Load models from disk.
    Cache in memory after first load.
    Returns (model_down, model_up) or (None, None).
    """

    if device_name in loaded_models:
        return loaded_models[device_name]

    path_down = os.path.join(MODEL_FOLDER, device_name + '_down.pkl')
    path_up   = os.path.join(MODEL_FOLDER, device_name + '_up.pkl')

    if not os.path.exists(path_down):
        return None, None

    model_down = pickle.load(open(path_down, 'rb'))
    model_up   = pickle.load(open(path_up,   'rb'))

    loaded_models[device_name] = (model_down, model_up)
    print(f"  Loaded model for {device_name}")

    return model_down, model_up

def get_known_ips():
    """
    Return IPs that have both CSV file and trained model.
    """

    known_ips = []

    if not os.path.exists(DEVICE_FOLDER):
        return known_ips

    for filename in os.listdir(DEVICE_FOLDER):
        if not filename.endswith('.csv'):
            continue

        device_name = filename.replace('.csv', '')
        ip          = device_name.replace('_', '.')
        path_down   = os.path.join(MODEL_FOLDER, device_name + '_down.pkl')

        if os.path.exists(path_down):
            known_ips.append(ip)

    return known_ips

def initialize_all_devices(known_ips):
    """
    Called ONCE before main loop starts.

    For each known device:
      1. Load last 3 rows from CSV (most recent behavior)
      2. Compute features using same function as training
      3. Predict traffic class using trained model
      4. Apply protocol override:
            if ML predicts IDLE but last protocol was active app
            upgrade to LOW so device gets fair initial bandwidth
      5. Convert class to seed bytes for allocate()
      6. If ALL devices predict IDLE → use equal fair share
            prevents all devices getting near-zero allocation

    Priority taken from CSV history (nDPI detected)
    NOT from ML class — these are separate concerns
    """

    initial_devices = []

    for ip in known_ips:

        device_name = ip.replace('.', '_')
        filepath    = os.path.join(DEVICE_FOLDER, device_name + '.csv')

        if not os.path.exists(filepath):
            print(f"  {ip} → CSV not found, skipping")
            continue

        df = pd.read_csv(filepath)

        if len(df) < WINDOW_SIZE:
            print(f"  {ip} → only {len(df)} rows, need {WINDOW_SIZE}")
            continue

        # last 3 rows — most recent behavior
        last_3   = df.tail(WINDOW_SIZE)
        d1       = last_3.iloc[0]
        d2       = last_3.iloc[1]
        d3       = last_3.iloc[2]   # most recent

        # protocol and priority from most recent row
        # these come from nDPI — NOT from ML
        protocol = str(d3['protocol'])
        priority = int(d3['priority'])

        # load trained model
        model_down, model_up = load_model(device_name)

        if model_down is None:
            print(f"  {ip} → no model found, skipping")
            continue

        # compute features — exactly same as training
        features             = compute_features(d1, d2, d3)
        features['protocol'] = encode_protocol(protocol)
        feature_df           = pd.DataFrame([features])[FEATURES]

        # predict traffic class for download and upload
        down_class = int(model_down.predict(feature_df)[0])
        up_class   = int(model_up.predict(feature_df)[0])

        # ── Protocol Override ─────────────────────────────────
        # if ML predicts IDLE but last known protocol was active
        # device probably about to resume that activity
        # upgrade to LOW to give adequate initial bandwidth
        if down_class == 0 and protocol.upper() in ACTIVE_PROTOCOLS:
            print(f"  {ip} → IDLE overridden to LOW (last protocol={protocol})")
            down_class = 1   # upgrade IDLE → LOW

        if up_class == 0 and protocol.upper() in ACTIVE_PROTOCOLS:
            up_class = 1

        # convert class to seed demand bytes
        seed_down = CLASS_TO_SEED_BYTES[down_class]
        seed_up   = CLASS_TO_SEED_BYTES[up_class]

        print(f"  {ip} → down={CLASS_NAMES[down_class]} ({seed_down/1024:.1f} KB/s)  "
              f"up={CLASS_NAMES[up_class]} ({seed_up/1024:.1f} KB/s)  "
              f"protocol={protocol}  priority={priority}")

        # build exact same structure as monitor.py returns
        initial_devices.append({
            "ip"                       : ip,
            "down_bytes_per_sec"       : float(seed_down),
            "up_bytes_per_sec"         : float(seed_up),
            "protocol"                 : protocol,
            "priority"                 : priority,
            "allocated_bytes_download" : 0,
            "allocated_bytes_upload"   : 0,
        })

    # ── All Idle Override ─────────────────────────────────────
    # if every device predicted IDLE
    # give everyone equal fair share instead of near-zero
    # prevents all devices being starved at startup
    if len(initial_devices) > 0:
        all_idle = all(
            d['down_bytes_per_sec'] <= CLASS_TO_SEED_BYTES[0] * 1.5
            for d in initial_devices
        )

        if all_idle:
            print(f"\n  All devices predicted IDLE → using equal fair share")
            # use LOW seed for everyone so allocate has something to work with
            for d in initial_devices:
                d['down_bytes_per_sec'] = float(CLASS_TO_SEED_BYTES[1])
                d['up_bytes_per_sec']   = float(CLASS_TO_SEED_BYTES[1])

    return initial_devices


if __name__ == "__main__":

    print("Testing ML initialization...")
    print(f"{'='*65}")
    print(f"Thresholds used:")
    print(f"  IDLE   → below {THRESHOLD_IDLE_LOW} bytes/sec ({THRESHOLD_IDLE_LOW/1024:.2f} KB/s)")
    print(f"  LOW    → {THRESHOLD_IDLE_LOW} to {THRESHOLD_LOW_MEDIUM} bytes/sec ({THRESHOLD_LOW_MEDIUM/1024:.1f} KB/s)")
    print(f"  MEDIUM → {THRESHOLD_LOW_MEDIUM} to {THRESHOLD_MEDIUM_HIGH} bytes/sec ({THRESHOLD_MEDIUM_HIGH/1024:.0f} KB/s)")
    print(f"  HIGH   → above {THRESHOLD_MEDIUM_HIGH} bytes/sec ({THRESHOLD_MEDIUM_HIGH/1024:.0f} KB/s)")
    print(f"{'='*65}\n")

    known_ips = get_known_ips()

    if len(known_ips) == 0:
        print("No known devices. Check dataset/ and ml_part/models/")
    else:
        print(f"Known devices: {known_ips}\n")
        devices = initialize_all_devices(known_ips)

        print(f"\n{'='*65}")
        print(f"{'IP':<20} {'Down KB/s':>10} {'Up KB/s':>10} {'Protocol':<15} {'Pri':>4}")
        print(f"{'-'*65}")
        for d in devices:
            print(f"{d['ip']:<20} "
                  f"{d['down_bytes_per_sec']/1024:>10.1f} "
                  f"{d['up_bytes_per_sec']/1024:>10.1f} "
                  f"{d['protocol']:<15} "
                  f"{d['priority']:>4}")