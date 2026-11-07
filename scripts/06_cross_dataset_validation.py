"""
Execution script for Phase 8: Cross-Dataset Validation on UNSW-NB15.
Defines schema mapping, independent preprocessing, evaluation protocol, and model evaluation.
"""

import sys
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.utils.config import DATA_DIR, RAW_DATA_DIR, OUTPUTS_DIR, RANDOM_SEED
from src.utils.logger import setup_logger
from src.evaluation.metrics import compute_binary_metrics

logger = setup_logger("script_06_unsw")

# Semantic Alignment Map between NF-CSE-CIC-IDS2018 and UNSW-NB15
SEMANTIC_FEATURE_MAP = {
    "NF-CSE-CIC-IDS2018": [
        "IN_BYTES",
        "OUT_BYTES",
        "IN_PKTS",
        "OUT_PKTS",
        "FLOW_DURATION_MILLISECONDS",
        "PROTOCOL"
    ],
    "UNSW-NB15": [
        "sbytes",  # Source to destination transaction bytes
        "dbytes",  # Destination to source transaction bytes
        "spkts",   # Source to destination packet count
        "dpkts",   # Destination to source packet count
        "dur",     # Record total duration (in seconds, *1000 for ms)
        "proto"    # Transaction protocol (tcp, udp, etc.)
    ]
}

def find_unsw_dataset() -> Path | None:
    """Searches for UNSW-NB15 dataset files in data/raw."""
    candidates = [
        RAW_DATA_DIR / "UNSW_NB15_testing-set.csv",
        RAW_DATA_DIR / "UNSW_NB15_training-set.csv",
        RAW_DATA_DIR / "UNSW-NB15.csv",
        RAW_DATA_DIR / "UNSW-NB15.parquet"
    ]
    for c in candidates:
        if c.exists() and c.stat().st_size > 0:
            return c
    return None

def main():
    logger.info("=== Starting Phase 8: Cross-Dataset Validation Protocol ===")
    out_dir = OUTPUTS_DIR / "cross_dataset"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    unsw_path = find_unsw_dataset()
    
    # Generate the Alignment Protocol Report
    protocol_report_path = out_dir / "unsw_nb15_evaluation_protocol.md"
    generate_protocol_document(protocol_report_path)
    logger.info(f"Saved dataset alignment protocol to {protocol_report_path}")
    
    if unsw_path is None:
        logger.warning(
            "UNSW-NB15 dataset file not detected in data/raw/.\n"
            "To execute live UNSW-NB15 cross-dataset benchmark:\n"
            "1. Download 'UNSW_NB15_testing-set.csv' from the official UNSW-NB15 repository.\n"
            f"2. Place the file at: {RAW_DATA_DIR / 'UNSW_NB15_testing-set.csv'}\n"
            "3. Re-run this script.\n"
            "Detailed semantic alignment mapping and methodology have been documented in 'outputs/cross_dataset/unsw_nb15_evaluation_protocol.md'."
        )
        return
        
    logger.info(f"UNSW-NB15 dataset detected at {unsw_path}. Processing benchmark...")
    # Load and process UNSW-NB15
    if unsw_path.suffix == ".parquet":
        df = pd.read_parquet(unsw_path)
    else:
        df = pd.read_csv(unsw_path)
        
    logger.info(f"Loaded UNSW-NB15 shape: {df.shape}")
    
    # Standardize column names
    target_col = "label" if "label" in df.columns else "Label"
    attack_col = "attack_cat" if "attack_cat" in df.columns else "Attack"
    
    # Feature selection: using common aligned flow features
    df["flow_duration_ms"] = df["dur"] * 1000.0 if "dur" in df.columns else 0.0
    
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "ospf": 89}
    df["proto_code"] = df["proto"].str.lower().map(proto_map).fillna(0).astype(int) if "proto" in df.columns else 6
    
    features = ["sbytes", "dbytes", "spkts", "dpkts", "flow_duration_ms", "proto_code"]
    available_feats = [f for f in features if f in df.columns]
    
    X = df[available_feats].fillna(0)
    y = df[target_col].astype(int)
    
    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=RANDOM_SEED
    )
    
    logger.info(f"Training benchmark models on UNSW-NB15 (Train={len(X_train):,}, Test={len(X_test):,})...")
    
    models = {
        "Decision Tree": DecisionTreeClassifier(max_depth=12, class_weight="balanced", random_state=RANDOM_SEED),
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=16, class_weight="balanced", n_jobs=-1, random_state=RANDOM_SEED),
        "XGBoost": XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, random_state=RANDOM_SEED, n_jobs=-1)
    }
    
    unsw_results = []
    for name, model in models.items():
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        m = compute_binary_metrics(y_true=y_test.values, y_pred=preds, model_name=name, split_name="unsw_test")
        unsw_results.append(m)
        logger.info(f"UNSW-NB15 [{name}] Test Acc: {m['accuracy']:.4f} | Macro-F1: {m['macro_f1']:.4f} | Attack Recall: {m['attack_recall']:.4f}")
        
    df_unsw_res = pd.DataFrame(unsw_results)
    df_unsw_res.to_csv(out_dir / "unsw_nb15_benchmark_results.csv", index=False)
    logger.info(f"Saved UNSW-NB15 benchmark results to {out_dir / 'unsw_nb15_benchmark_results.csv'}")

def generate_protocol_document(output_path: Path):
    md = []
    md.append("# Phase 8 Protocol: Cross-Dataset Validation on UNSW-NB15\n")
    md.append("**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  ")
    md.append("**Lead Researcher:** Aditya Ambare (Roll: TIA26)  ")
    md.append("**Status:** Formal Evaluation Protocol Defined\n")
    md.append("---\n")
    
    md.append("## 1. Cross-Dataset Methodological Rationale\n")
    md.append("In machine learning-based NIDS, cross-dataset validation prevents models from overfitting to environment-specific flow artifacts present in a single testbed (such as synthetic topology quirks in CSE-CIC-IDS2018). UNSW-NB15 provides an independent synthetic-real hybrid benchmark created using the IXIA PerfectStorm tool at the Cyber Range Lab of UNSW Canberra.\n")
    
    md.append("## 2. Feature Schema Alignment Protocol\n")
    md.append("| Semantic Flow Concept | Primary Dataset (`NF-CSE-CIC-IDS2018`) | Validation Dataset (`UNSW-NB15`) | Alignment Transformation |\n")
    md.append("|---|---|---|---|\n")
    md.append("| Inbound Byte Volume | `IN_BYTES` | `sbytes` | Direct mapping (Byte count) |")
    md.append("| Outbound Byte Volume | `OUT_BYTES` | `dbytes` | Direct mapping (Byte count) |")
    md.append("| Inbound Packet Count | `IN_PKTS` | `spkts` | Direct mapping (Packet count) |")
    md.append("| Outbound Packet Count | `OUT_PKTS` | `dpkts` | Direct mapping (Packet count) |")
    md.append("| Flow Duration | `FLOW_DURATION_MILLISECONDS` | `dur` | Unit conversion: $\text{dur} \times 1000$ (seconds to ms) |")
    md.append("| Protocol Identifier | `PROTOCOL` (IANA integer) | `proto` (string code) | Categorical map: `tcp` $\\to 6$, `udp` $\\to 17$, `icmp` $\\to 1$ |")
    md.append("| Binary Ground Truth | `Label` (0=Benign, 1=Attack) | `label` (0=Normal, 1=Attack) | Direct identity mapping |\n")
    
    md.append("## 3. Methodological Guardrails Against Naive Generalization\n")
    md.append("> [!IMPORTANT]\n")
    md.append("> **Direct Cross-Testing Caution:** Training on NF-CSE-CIC-IDS2018 and evaluating directly on raw UNSW-NB15 without domain adaptation is invalid due to significant covariate shift (different MTU configurations, packet capture buffering, and background traffic baselines). Instead, the rigorous methodology:\n")
    md.append("> 1. Evaluates each dataset using identical feature engineering and tree architectures.\n")
    md.append("> 2. Validates whether the adversarial robustness hierarchy (XGBoost vs RF vs DT) and explanation stability findings remain consistent across independent benchmark architectures.\n")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

if __name__ == "__main__":
    main()

