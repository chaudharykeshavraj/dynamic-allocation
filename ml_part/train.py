
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE
import pickle
import os

# ── Path Setup ────────────────────────────────────────────────
ML_DIR          = os.path.dirname(os.path.abspath(__file__))
TRAINING_FOLDER = os.path.join(ML_DIR, 'training')
MODEL_FOLDER    = os.path.join(ML_DIR, 'models')

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

CLASS_NAMES = {
    0 : "IDLE",
    1 : "LOW",
    2 : "MEDIUM",
    3 : "HIGH",
}

def train_device(filepath, device_name):
    """
    Train download and upload classifiers for one device.
    Uses SMOTE to balance class distribution.
    RandomForest handles noisy bursty traffic well.
    Saves model_down and model_up as pkl files.
    """

    df = pd.read_csv(filepath)

    if len(df) < 10:
        print(f"  Skipping — only {len(df)} rows")
        return

    X      = df[FEATURES]
    y_down = df['next_down_class']
    y_up   = df['next_up_class']

    # 80% train, 20% test
    X_train, X_test, yd_train, yd_test = train_test_split(
        X, y_down, test_size=0.2, random_state=42
    )
    _, _, yu_train, yu_test = train_test_split(
        X, y_up, test_size=0.2, random_state=42
    )

    # SMOTE balances class distribution in training set
    # creates synthetic samples for minority classes
    # only applied to training — never test set
    try:
        sm                             = SMOTE(random_state=42, k_neighbors=3)
        X_train_down, yd_train_bal     = sm.fit_resample(X_train, yd_train)
        print(f"  SMOTE download — balanced")
    except Exception as e:
        print(f"  SMOTE download skipped ({e})")
        X_train_down, yd_train_bal     = X_train, yd_train

    try:
        sm                             = SMOTE(random_state=42, k_neighbors=3)
        X_train_up,   yu_train_bal     = sm.fit_resample(X_train, yu_train)
        print(f"  SMOTE upload   — balanced")
    except Exception as e:
        print(f"  SMOTE upload skipped ({e})")
        X_train_up,   yu_train_bal     = X_train, yu_train

    # download classifier
    model_down = RandomForestClassifier(
        n_estimators = 200,
        max_depth    = 10,
        class_weight = 'balanced',
        random_state = 42,
        n_jobs       = -1
    )
    model_down.fit(X_train_down, yd_train_bal)

    # upload classifier
    model_up = RandomForestClassifier(
        n_estimators = 200,
        max_depth    = 10,
        class_weight = 'balanced',
        random_state = 42,
        n_jobs       = -1
    )
    model_up.fit(X_train_up, yu_train_bal)

    # evaluate on original unbalanced test set
    down_pred = model_down.predict(X_test)
    up_pred   = model_up.predict(X_test)

    down_acc  = accuracy_score(yd_test, down_pred)
    up_acc    = accuracy_score(yu_test, up_pred)

    print(f"  Download accuracy = {down_acc*100:.1f}%")
    print(f"  Upload   accuracy = {up_acc*100:.1f}%")

    # use only classes present in test set
    # avoids error when some classes missing in small test sets
    down_labels = sorted(yd_test.unique())
    up_labels   = sorted(yu_test.unique())

    print(f"\n  Download class report:")
    print(classification_report(
        yd_test, down_pred,
        labels       = down_labels,
        target_names = [CLASS_NAMES[i] for i in down_labels],
        zero_division = 0
    ))

    print(f"  Upload class report:")
    print(classification_report(
        yu_test, up_pred,
        labels       = up_labels,
        target_names = [CLASS_NAMES[i] for i in up_labels],
        zero_division = 0
    ))

    # save both models
    pickle.dump(model_down, open(os.path.join(MODEL_FOLDER, device_name + '_down.pkl'), 'wb'))
    pickle.dump(model_up,   open(os.path.join(MODEL_FOLDER, device_name + '_up.pkl'),   'wb'))
    print(f"  Saved {device_name}_down.pkl  {device_name}_up.pkl")

def train_all():
    """Train one model per device from training folder."""

    if not os.path.exists(TRAINING_FOLDER):
        print("Training folder not found. Run prepare_dataset.py first.")
        return

    if not os.path.exists(MODEL_FOLDER):
        os.makedirs(MODEL_FOLDER)
        print(f"Created: {MODEL_FOLDER}")

    training_files = [f for f in os.listdir(TRAINING_FOLDER) if f.endswith('.csv')]

    if len(training_files) == 0:
        print("No training files. Run prepare_dataset.py first.")
        return

    for filename in training_files:
        device_name = filename.replace('.csv', '')
        filepath    = os.path.join(TRAINING_FOLDER, filename)
        print(f"\nTraining {device_name}...")
        train_device(filepath, device_name)

    print(f"\nAll models saved to {MODEL_FOLDER}")

def show_summary():
    """Load trained models and show accuracy summary table."""

    if not os.path.exists(TRAINING_FOLDER):
        print("No training folder found.")
        return

    training_files = [f for f in os.listdir(TRAINING_FOLDER) if f.endswith('.csv')]

    print(f"\n{'='*55}")
    print(f"  Accuracy Summary")
    print(f"{'='*55}")
    print(f"  {'Device':<25} {'Down Acc':>10} {'Up Acc':>10}")
    print(f"  {'-'*53}")

    for filename in training_files:

        device_name = filename.replace('.csv', '')
        filepath    = os.path.join(TRAINING_FOLDER, filename)
        df          = pd.read_csv(filepath)

        if len(df) < 10:
            continue

        path_down = os.path.join(MODEL_FOLDER, device_name + '_down.pkl')
        path_up   = os.path.join(MODEL_FOLDER, device_name + '_up.pkl')

        if not os.path.exists(path_down):
            print(f"  {device_name:<25} model not found")
            continue

        model_down = pickle.load(open(path_down, 'rb'))
        model_up   = pickle.load(open(path_up,   'rb'))

        X      = df[FEATURES]
        y_down = df['next_down_class']
        y_up   = df['next_up_class']

        _, X_test, _, yd_test = train_test_split(
            X, y_down, test_size=0.2, random_state=42
        )
        _, _,      _, yu_test = train_test_split(
            X, y_up, test_size=0.2, random_state=42
        )

        down_acc = accuracy_score(yd_test, model_down.predict(X_test))
        up_acc   = accuracy_score(yu_test, model_up.predict(X_test))

        print(f"  {device_name:<25} {down_acc*100:>9.1f}% {up_acc*100:>9.1f}%")

    print(f"  {'-'*53}")
    print(f"  Accuracy closer to 100% = better")
    print(f"{'='*55}")

if __name__ == "__main__":

    print("Step 1 — Training all devices...")
    train_all()

    print("\nStep 2 — Accuracy summary...")
    show_summary()