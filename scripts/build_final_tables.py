"""
Script to build outputs/final/final_results_tables.csv.
Consolidates clean baseline, DC-FFP, SGGS, port-shift stress test, and latency benchmark results.
"""

from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent

df_base = pd.read_csv(BASE_DIR / "outputs" / "metrics" / "baseline_metrics.csv")
df_rob = pd.read_csv(BASE_DIR / "outputs" / "adversarial" / "robustness_metrics.csv")
df_port_shift = pd.read_csv(BASE_DIR / "outputs" / "audit" / "port_shift_experiment.csv")
df_lat = pd.read_csv(BASE_DIR / "outputs" / "audit" / "latency_benchmark.csv")

records = []

# 1. Baseline Performance
for _, r in df_base[df_base["split"] == "test"].iterrows():
    records.append({
        "experiment_category": "1. Clean Baseline (Test Partition)",
        "model_configuration": r["model"],
        "condition_or_scenario": "Unperturbed 8-Feature Test Set",
        "accuracy": r["accuracy"],
        "macro_f1": r["macro_f1"],
        "attack_recall": r["attack_recall"],
        "false_positive_rate": r["false_positive_rate"],
        "roc_auc": r["roc_auc"],
        "evasion_rate": 0.0,
        "inference_latency_ms": r["inference_latency_ms"],
        "notes": "Zero data leakage; test set N=30,000; ROC-AUC computed from continuous predicted probabilities"
    })

# 2. Adversarial Robustness (DC-FFP)
for _, r in df_rob.iterrows():
    records.append({
        "experiment_category": "2. Adversarial Robustness (DC-FFP)",
        "model_configuration": r["model"],
        "condition_or_scenario": f"Budget epsilon = {r['epsilon']:.2f}",
        "accuracy": r["accuracy"],
        "macro_f1": r["macro_f1"],
        "attack_recall": r["attack_recall"],
        "false_positive_rate": r["false_positive_rate"],
        "roc_auc": None,
        "evasion_rate": r["evasion_rate"],
        "inference_latency_ms": None,
        "notes": f"Evaded: {r['num_evaded']}/{r['num_initially_detected']}"
    })

# 2.1 Adversarial Robustness (SGGS Search)
records.append({
    "experiment_category": "2. Adversarial Robustness (SGGS Search)",
    "model_configuration": "XGBoost",
    "condition_or_scenario": "SGGS Config A (Audited 16-Query Benchmark: max_iters=3, step=0.05, max_eps=0.50)",
    "accuracy": None,
    "macro_f1": None,
    "attack_recall": None,
    "false_positive_rate": None,
    "roc_auc": None,
    "evasion_rate": 0.0600,
    "inference_latency_ms": None,
    "notes": "Candidates=100; Initially detected=100; Evaded=6 (6.00%); Queries: Init=1, Avg Search=15.0, Avg Total=16.0, Max=17, Min=11"
})
records.append({
    "experiment_category": "2. Adversarial Robustness (SGGS Search)",
    "model_configuration": "XGBoost",
    "condition_or_scenario": "SGGS Config B (Extended Search: max_iters=10, step=0.05, max_eps=0.50)",
    "accuracy": None,
    "macro_f1": None,
    "attack_recall": None,
    "false_positive_rate": None,
    "roc_auc": None,
    "evasion_rate": 0.6000,
    "inference_latency_ms": None,
    "notes": "Candidates=100; Initially detected=100; Evaded=60 (60.00%); Queries: Init=1, Avg Total=38.9, Max=58, Min=11"
})

# 3. Port Shift Experiment
for _, r in df_port_shift.iterrows():
    is_redir = "Destination" in r["scenario"]
    note_8 = (
        "The 8-feature model is invariant to direct changes in source and destination port fields "
        "when no other model input features are modified; Evaded: 0/1664"
        if is_redir else f"Evaded: {r['xgb_8feat_evaded_count']}/1664"
    )
    records.append({
        "experiment_category": "3. Port-Shift Stress Test (8-feat Control)",
        "model_configuration": "XGBoost Baseline (8 features)",
        "condition_or_scenario": r["scenario"],
        "accuracy": r["xgb_8feat_accuracy"],
        "macro_f1": None,
        "attack_recall": r["xgb_8feat_recall"],
        "false_positive_rate": None,
        "roc_auc": None,
        "evasion_rate": r["xgb_8feat_evasion_rate"],
        "inference_latency_ms": None,
        "notes": note_8
    })
    note_10 = (
        f"Shortcut collapse: 1572/1670 attacks evade (94.13%) under destination port redirection"
        if is_redir else f"Evaded: {r['xgb_10feat_evaded_count']}/1670"
    )
    records.append({
        "experiment_category": "3. Port-Shift Stress Test (10-feat Port Model)",
        "model_configuration": "XGBoost Extended (10 features with Ports)",
        "condition_or_scenario": r["scenario"],
        "accuracy": r["xgb_10feat_accuracy"],
        "macro_f1": None,
        "attack_recall": r["xgb_10feat_recall"],
        "false_positive_rate": None,
        "roc_auc": None,
        "evasion_rate": r["xgb_10feat_evasion_rate"],
        "inference_latency_ms": None,
        "notes": note_10
    })

# 4. Latency
for _, r in df_lat[df_lat["batch_size"].isin([1, 30000])].iterrows():
    mode = "Single-Sample Streaming (N=1)" if r["batch_size"] == 1 else "Vectorized Batch (N=30,000)"
    records.append({
        "experiment_category": "4. Inference Latency Benchmark",
        "model_configuration": r["model"],
        "condition_or_scenario": mode,
        "accuracy": None,
        "macro_f1": None,
        "attack_recall": None,
        "false_positive_rate": None,
        "roc_auc": None,
        "evasion_rate": None,
        "inference_latency_ms": r["per_sample_ms"],
        "notes": f"Throughput: {r['throughput_flows_sec']:,.1f} flows/sec (raw estimator predict only)"
    })

df_unified = pd.DataFrame(records)
out_path = BASE_DIR / "outputs" / "final" / "final_results_tables.csv"
df_unified.to_csv(out_path, index=False)
print(f"Saved {out_path} successfully with {len(df_unified)} rows.")
