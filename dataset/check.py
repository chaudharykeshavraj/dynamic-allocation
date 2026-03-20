import pandas as pd
import os

# dataset folder is where this script lives
DATASET_FOLDER = os.path.dirname(os.path.abspath(__file__))

device_files = [f for f in os.listdir(DATASET_FOLDER) if f.endswith('.csv')]

if len(device_files) == 0:
    print("No device CSV files found.")
else:
    for filename in device_files:
        filepath = os.path.join(DATASET_FOLDER, filename)
        df       = pd.read_csv(filepath)

        print(f"\n{'='*55}")
        print(f"Device: {filename.replace('.csv','').replace('_','.')}")
        print(f"{'='*55}")
        print(f"Total rows      : {len(df)}")
        print(f"Data collected  : {len(df) * 5 / 60:.1f} minutes")

        print(f"\nDownload (bytes/sec):")
        print(f"  mean  = {df['down_bytes_per_sec'].mean():,.0f}")
        print(f"  std   = {df['down_bytes_per_sec'].std():,.0f}")
        print(f"  min   = {df['down_bytes_per_sec'].min():,.0f}")
        print(f"  max   = {df['down_bytes_per_sec'].max():,.0f}")

        print(f"\nUpload (bytes/sec):")
        print(f"  mean  = {df['up_bytes_per_sec'].mean():,.0f}")
        print(f"  std   = {df['up_bytes_per_sec'].std():,.0f}")
        print(f"  min   = {df['up_bytes_per_sec'].min():,.0f}")
        print(f"  max   = {df['up_bytes_per_sec'].max():,.0f}")

        print(f"\nProtocol distribution:")
        for protocol, count in df['protocol'].value_counts().items():
            pct = count / len(df) * 100
            print(f"  {protocol:<20} {count:>5} rows  ({pct:.1f}%)")