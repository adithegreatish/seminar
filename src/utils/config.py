"""
Configuration and constants for the Robust and Explainable NIDS project.
"""

from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
OUTPUTS_DIR = BASE_DIR / "outputs"
AUDIT_OUTPUT_DIR = OUTPUTS_DIR / "audit"
MODELS_OUTPUT_DIR = OUTPUTS_DIR / "models"
METRICS_OUTPUT_DIR = OUTPUTS_DIR / "metrics"
SHAP_OUTPUT_DIR = OUTPUTS_DIR / "shap"
ADVERSARIAL_OUTPUT_DIR = OUTPUTS_DIR / "adversarial"
STABILITY_OUTPUT_DIR = OUTPUTS_DIR / "stability"

# Datasets
PRIMARY_DATASET_ZIP = RAW_DATA_DIR / "NF-CSE-CIC-IDS2018.parquet.zip"
PRIMARY_DATASET_PARQUET = RAW_DATA_DIR / "NF-CSE-CIC-IDS2018.parquet"

# Feature definitions
PORT_FEATURES = ["L4_SRC_PORT", "L4_DST_PORT"]
BASELINE_FEATURES = [
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
]
ALL_FEATURES = PORT_FEATURES + BASELINE_FEATURES
TARGET_BINARY = "Label"
TARGET_MULTICLASS = "Attack"

# Global Random State
RANDOM_SEED = 42

# Sampling Configuration
DEFAULT_SAMPLE_SIZE = 200_000
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

