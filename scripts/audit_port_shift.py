"""
Comprehensive Port-Shift and Shortcut-Learning Audit Script.
Evaluates 8-feature baseline (control) vs 10-feature model under identical
port-shift and flow-feature perturbation scenarios on the same test cohort.
"""

import sys
from pathlib import Path
import numpy as np
import pandas as pd

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.models.baseline_models import NIDSModelWrapper
from src.utils.config import MODELS_OUTPUT_DIR, PROCESSED_DATA_DIR, OUTPUTS_DIR
from src.adversarial.threats import ThreatModel
from src.adversarial.attacks import DomainConstrainedPerturbationAttack

def main():
    print("=== Running Comprehensive Port-Shift and Control Audit ===")
    
    # 1. Load test data
    c8 = PROCESSED_DATA_DIR / "sample_200000_ports_False"
    X8_test = pd.read_parquet(c8 / "X_test.parquet")
    y_test = pd.read_parquet(c8 / "y_test.parquet")["Label"].values
    
    c10 = PROCESSED_DATA_DIR / "sample_200000_ports_True"
    X10_test = pd.read_parquet(c10 / "X_test.parquet")
    
    # 2. Load models
    xgb8 = NIDSModelWrapper.load(MODELS_OUTPUT_DIR / "xgboost_binary.joblib")
    xgb10 = NIDSModelWrapper.load(MODELS_OUTPUT_DIR / "xgboost_ports.joblib")
    
    # Clean predictions
    preds8_clean, _ = xgb8.predict(X8_test)
    preds10_clean, _ = xgb10.predict(X10_test)
    
    # True attack indices in test partition
    total_attacks = sum(y_test == 1)
    det8_clean = (y_test == 1) & (preds8_clean == 1)
    det10_clean = (y_test == 1) & (preds10_clean == 1)
    
    n_det8 = sum(det8_clean)
    n_det10 = sum(det10_clean)
    
    print(f"Total Attacks in Test Set: {total_attacks}")
    print(f"XGBoost 8-feat Clean Detected:  {n_det8} (Recall: {n_det8/total_attacks*100:.2f}%)")
    print(f"XGBoost 10-feat Clean Detected: {n_det10} (Recall: {n_det10/total_attacks*100:.2f}%)")
    
    # Helper to shift destination ports
    def shift_dst_port(p):
        if p == 80: return 8080
        if p == 443: return 8443
        if p == 22: return 2222
        if p == 21: return 2121
        return (p + 1000) % 65535
        
    threat = ThreatModel()
    dcpa = DomainConstrainedPerturbationAttack(threat)
    
    scenarios = [
        ("1. Clean Baseline", "None", "None"),
        ("2. Source-Port Randomization", "Ephemeral Randomization (49152-65535)", "None"),
        ("3. Destination Service-Port Shift", "None", "Alternate Ports (80->8080, 22->2222, 21->2121)"),
        ("4. Flow-Feature Perturbation Only (eps=0.20)", "Static", "Static (eps=0.20 padding/delay)"),
        ("5. Combined Port Shift + Flow Perturbation", "Alternate Ports", "Alternate Ports + eps=0.20 padding")
    ]
    
    results = []
    
    for s_name, s_src, s_dst in scenarios:
        # --- 8-Feature Model (Control) ---
        X8_pert = X8_test.copy()
        if "Flow-Feature" in s_name or "Combined" in s_name:
            X8_pert = dcpa.generate(X8_pert, epsilon=0.20)
        # Ports are not present in X8, so port shifts have strictly 0 impact
        preds8_pert, _ = xgb8.predict(X8_pert)
        evaded8 = det8_clean & (preds8_pert == 0)
        er8 = sum(evaded8) / n_det8
        rec8 = sum((y_test == 1) & (preds8_pert == 1)) / total_attacks
        acc8 = sum(preds8_pert == y_test) / len(y_test)
        
        # --- 10-Feature Model ---
        X10_pert = X10_test.copy()
        if "Source-Port Randomization" in s_name:
            np.random.seed(42)
            X10_pert.loc[det10_clean, "L4_SRC_PORT"] = np.random.randint(49152, 65535, size=n_det10)
        elif "Destination Service-Port Shift" in s_name:
            X10_pert.loc[det10_clean, "L4_DST_PORT"] = X10_pert.loc[det10_clean, "L4_DST_PORT"].map(shift_dst_port)
        elif "Flow-Feature Perturbation Only" in s_name:
            X10_pert = dcpa.generate(X10_pert, epsilon=0.20)
        elif "Combined" in s_name:
            X10_pert.loc[det10_clean, "L4_DST_PORT"] = X10_pert.loc[det10_clean, "L4_DST_PORT"].map(shift_dst_port)
            X10_pert = dcpa.generate(X10_pert, epsilon=0.20)
            
        preds10_pert, _ = xgb10.predict(X10_pert)
        evaded10 = det10_clean & (preds10_pert == 0)
        er10 = sum(evaded10) / n_det10
        rec10 = sum((y_test == 1) & (preds10_pert == 1)) / total_attacks
        acc10 = sum(preds10_pert == y_test) / len(y_test)
        
        results.append({
            "scenario": s_name,
            "port_modification": s_src + " / " + s_dst,
            "xgb_8feat_accuracy": acc8,
            "xgb_8feat_recall": rec8,
            "xgb_8feat_evasion_rate": er8,
            "xgb_8feat_evaded_count": int(sum(evaded8)),
            "xgb_10feat_accuracy": acc10,
            "xgb_10feat_recall": rec10,
            "xgb_10feat_evasion_rate": er10,
            "xgb_10feat_evaded_count": int(sum(evaded10))
        })
        
    df_res = pd.DataFrame(results)
    out_csv = OUTPUTS_DIR / "audit" / "port_shift_experiment.csv"
    df_res.to_csv(out_csv, index=False)
    print(f"\nSaved port-shift experiment table to {out_csv}:")
    print(df_res[["scenario", "xgb_8feat_evasion_rate", "xgb_10feat_evasion_rate"]].to_string())

if __name__ == "__main__":
    main()
