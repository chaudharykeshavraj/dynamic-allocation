import pandas as pd
import pickle
import os

from prepare_dataset import compute_features, encode_protocol, WINDOW_SIZE, get_traffic_class

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

# class → seed demand bytes/sec
# seed demand drives weighted allocation in allocate engine
# HIGH class gets bigger seed → gets more bandwidth proportionally
# priority stays from nDPI — NOT from ML class
CLASS_TO_SEED_BYTES = {
    0 :   5 * 1024,   # IDLE   →   5 KB/s seed
    1 :  50 * 1024,   # LOW    →  50 KB/s seed
    2 : 200 * 1024,   # MEDIUM → 200 KB/s seed
    3 : 600 * 1024,   # HIGH   → 600 KB/s seed
}

# cache loaded models
loaded_models = {}

def load_model(device_name):
    """Load models from disk. Cache after first load."""

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
    """Return IPs that have both CSV and trained model."""

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
    Called ONCE before main loop.

    For each known device:
      1. Load last 3 rows from CSV for ML features
      2. Load last row for protocol and priority (from nDPI history)
      3. Predict traffic class using trained model
      4. Use class to set seed demand (not priority!)
      5. Build same device structure as monitor.py returns

    priority comes from CSV history (nDPI detected)
    seed demand comes from ML predicted class
    allocate engine distributes total bandwidth fairly
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

        # last 3 rows for ML features
        last_3   = df.tail(WINDOW_SIZE)
        d1       = last_3.iloc[0]
        d2       = last_3.iloc[1]
        d3       = last_3.iloc[2]   # most recent row

        # protocol and priority from most recent row
        # these come from nDPI history — same as monitor.py would give
        protocol = str(d3['protocol'])
        priority = int(d3['priority'])

        # load trained model
        model_down, model_up = load_model(device_name)

        if model_down is None:
            print(f"  {ip} → no model found, skipping")
            continue

        # compute features
        features             = compute_features(d1, d2, d3)
        features['protocol'] = encode_protocol(protocol)
        feature_df           = pd.DataFrame([features])[FEATURES]

        # predict traffic class — download and upload separately
        down_class = int(model_down.predict(feature_df)[0])
        up_class   = int(model_up.predict(feature_df)[0])

        # seed demand from class
        # this is what drives weighted allocation
        # NOT a fixed cap — allocate engine distributes fairly
        seed_down = CLASS_TO_SEED_BYTES[down_class]
        seed_up   = CLASS_TO_SEED_BYTES[up_class]

        print(f"  {ip} → down={CLASS_NAMES[down_class]} ({seed_down//1024} KB/s seed)  up={CLASS_NAMES[up_class]} ({seed_up//1024} KB/s seed)  protocol={protocol}  priority={priority}")

        # build EXACT same structure as monitor.py returns
        # so allocate.py and enforce.py work without any changes
        initial_devices.append({
            "ip"                       : ip,
            "down_bytes_per_sec"       : seed_down,   # ML seed demand
            "up_bytes_per_sec"         : seed_up,     # ML seed demand
            "protocol"                 : protocol,    # from nDPI history
            "priority"                 : priority,    # from nDPI history
            "allocated_bytes_download" : 0,
            "allocated_bytes_upload"   : 0,
        })

    return initial_devices


if __name__ == "__main__":

    print("Testing ML initialization...")
    print(f"{'='*65}")

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
            print(f"{d['ip']:<20} {d['down_bytes_per_sec']//1024:>10} {d['up_bytes_per_sec']//1024:>10} {d['protocol']:<15} {d['priority']:>4}")