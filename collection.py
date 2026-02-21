import csv
import os

# file where ALL devices data is saved together every interval
EVERY_DATA_FILE = 'every_data.csv'

# folder where each device gets its OWN individual csv file
DEVICE_FOLDER   = 'dataset'

def collect(all_devices):

    # create dataset folder if it does not exist yet
    # this runs only once on first call
    if not os.path.exists(DEVICE_FOLDER):
        os.makedirs(DEVICE_FOLDER)
        print(f"Created folder: {DEVICE_FOLDER}")

    for device in all_devices:

        # extract values from device dictionary
        ip       = device['ip']               # e.g. "192.168.1.101"
        down     = device['down_bytes_per_sec']  # bytes/sec downloaded this interval
        up       = device['up_bytes_per_sec']    # bytes/sec uploaded this interval
        priority = device['priority']            # 1 to 5
        protocol = device['protocol']            # e.g. "YOUTUBE", "ZOOM"

        # one row to save for this device this interval
        row = [down, up, priority, protocol]

        # ── EVERY DATA FILE ───────────────────────────────────
        # check if file already exists BEFORE opening it
        # because once we open with 'a', file gets created
        # so we check existence first to know if header is needed
        every_data_exists = os.path.exists(EVERY_DATA_FILE)

        # open in append mode so we never overwrite old data
        with open(EVERY_DATA_FILE, 'a', newline='') as f:
            writer = csv.writer(f)

            # write header only on very first row (when file is new)
            # after that header is already there, skip it
            if not every_data_exists:
                writer.writerow(['ip', 'down_bytes_per_sec', 'up_bytes_per_sec', 'priority', 'protocol'])

            # write this device's data for this interval
            # ip is included here so we know which device each row belongs to
            writer.writerow([ip, down, up, priority, protocol])

        # ── INDIVIDUAL DEVICE FILE ────────────────────────────
        # convert ip to filename safe string
        # dots not allowed in some systems and confusing in filenames
        # 192.168.1.101 → 192_168_1_101.csv
        filename        = ip.replace('.', '_') + '.csv'

        # full path to this device's file inside dataset folder
        # e.g. dataset/192_168_1_101.csv
        device_filepath = os.path.join(DEVICE_FOLDER, filename)

        # same logic — check existence before opening
        device_exists   = os.path.exists(device_filepath)

        # open in append mode
        with open(device_filepath, 'a', newline='') as f:
            writer = csv.writer(f)

            # write header only when file is brand new for this device
            # individual file does NOT need ip column
            # because the filename itself tells us the ip
            if not device_exists:
                writer.writerow(['down_bytes_per_sec', 'up_bytes_per_sec', 'priority', 'protocol'])

            # write this interval's data for this device
            writer.writerow(row)

    print(f"Collected data for {len(all_devices)} device(s)")
