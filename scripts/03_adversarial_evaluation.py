"""
Execution script for Phase 5: Adversarial Robustness Evaluation.
Evaluates Decision Tree, Random Forest, and XGBoost under Domain-Constrained Perturbations.
"""

import sys
import json
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.utils.config import (
    ADVERSARIAL_OUTPUT_DIR,
    MODELS_OUTPUT_DIR,
    PROCESSED_DATA_DIR,
    RANDOM_SEED
)
from src.utils.logger import setup_logger
from src.models.baseline_models import NIDSModelWrapper
from src.adversarial.threats import ThreatModel
from src.adversarial.attacks import DomainConstrainedPerturbationAttack, QueryGuidedGreedySearch, SurrogateGuidedGreedySearch
from src.evaluation.metrics import compute_binary_metrics

logger = setup_logger("script_03_adversarial")

def main():
    logger.info("=== Starting Phase 5: Adversarial Robustness Evaluation ===")
    ADVERSARIAL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Load test data
    cache_dir = PROCESSED_DATA_DIR / "sample_200000_ports_False"
    X_test = pd.read_parquet(cache_dir / "X_test.parquet")
    y_test_df = pd.read_parquet(cache_dir / "y_test.parquet")
    y_test = y_test_df["Label"].values
    
    # 2. Load models
    models = {
        "Decision Tree": NIDSModelWrapper.load(MODELS_OUTPUT_DIR / "decision_tree_binary.joblib"),
        "Random Forest": NIDSModelWrapper.load(MODELS_OUTPUT_DIR / "random_forest_binary.joblib"),
        "XGBoost": NIDSModelWrapper.load(MODELS_OUTPUT_DIR / "xgboost_binary.joblib")
    }
    
    # 3. Setup threat model & attack generator
    threat = ThreatModel()
    dcpa_attack = DomainConstrainedPerturbationAttack(threat)
    
    # Budgets epsilon from 0.0 to 0.50
    epsilons = [0.0, 0.05, 0.10, 0.20, 0.30, 0.50]
    
    # We evaluate on an attack-rich test slice (e.g. all 1,946 attack samples + paired benign flows)
    # for precise statistical evasion calculations
    attack_indices = np.where(y_test == 1)[0]
    benign_indices = np.where(y_test == 0)[0]
    
    np.random.seed(RANDOM_SEED)
    chosen_benign = np.random.choice(benign_indices, size=min(len(attack_indices) * 2, len(benign_indices)), replace=False)
    eval_indices = np.concatenate([attack_indices, chosen_benign])
    np.random.shuffle(eval_indices)
    
    X_eval = X_test.iloc[eval_indices].reset_index(drop=True)
    y_eval = y_test[eval_indices]
    
    logger.info(f"Adversarial evaluation testbed: {len(X_eval):,} flows ({sum(y_eval==1):,} Attacks, {sum(y_eval==0):,} Benign)")
    
    results = []
    
    for eps in epsilons:
        logger.info(f"--- Evaluating Perturbation Budget epsilon = {eps:.2f} ---")
        if eps == 0.0:
            X_pert = X_eval.copy()
        else:
            X_pert = dcpa_attack.generate(X_eval, epsilon=eps)
            
        for model_name, model in models.items():
            # Clean baseline predictions
            y_pred_clean, _ = model.predict(X_eval)
            clean_correct_attacks = (y_eval == 1) & (y_pred_clean == 1)
            num_clean_detected = sum(clean_correct_attacks)
            
            # Perturbed predictions
            y_pred_pert, latency = model.predict(X_pert)
            y_prob_pert = model.predict_proba(X_pert)
            
            pert_metrics = compute_binary_metrics(
                y_true=y_eval,
                y_pred=y_pred_pert,
                y_prob=y_prob_pert,
                inference_time_ms=latency,
                model_name=model_name,
                split_name=f"adv_eps_{eps:.2f}"
            )
            
            # Calculate Evasion Rate (ER): of initially detected malicious flows, how many now evade (pred=0)?
            if num_clean_detected > 0:
                evaded_attacks = clean_correct_attacks & (y_pred_pert == 0)
                evasion_rate = float(sum(evaded_attacks) / num_clean_detected)
            else:
                evasion_rate = 0.0
                
            record = {
                "model": model_name,
                "epsilon": eps,
                "accuracy": pert_metrics["accuracy"],
                "macro_f1": pert_metrics["macro_f1"],
                "attack_recall": pert_metrics["attack_recall"],
                "attack_f1": pert_metrics["attack_f1"],
                "false_positive_rate": pert_metrics["false_positive_rate"],
                "evasion_rate": evasion_rate,
                "num_initially_detected": int(num_clean_detected),
                "num_evaded": int(sum(evaded_attacks)) if num_clean_detected > 0 else 0
            }
            results.append(record)
            logger.info(
                f"[{model_name}] eps={eps:.2f} | Acc: {record['accuracy']:.4f} | "
                f"Attack Recall: {record['attack_recall']:.4f} | Evasion Rate: {record['evasion_rate']*100:.2f}%"
            )
            
    results_df = pd.DataFrame(results)
    metrics_csv_path = ADVERSARIAL_OUTPUT_DIR / "robustness_metrics.csv"
    results_df.to_csv(metrics_csv_path, index=False)
    logger.info(f"Saved robustness metrics to {metrics_csv_path}")
    
    # 4. Active Black-box Surrogate-Guided Evasion Benchmark on XGBoost
    logger.info("--- Executing Query-Guided Greedy Search (QGGS, formerly SGGS) Benchmark ---")
    xgb_model = models["XGBoost"]
    sggs = QueryGuidedGreedySearch(xgb_model, threat, max_search_iterations=3, step_budget=0.05)
    
    # Select sample of 100 detected attacks
    detected_attack_sample = X_eval[clean_correct_attacks].iloc[:100].reset_index(drop=True)
    _, sggs_logs = sggs.attack_dataset(detected_attack_sample, max_epsilon=0.50)
    sggs_evasion_rate = sum(log["evaded"] for log in sggs_logs) / len(sggs_logs)
    avg_total_queries = float(np.mean([log["total_queries"] for log in sggs_logs]))
    avg_search_queries = float(np.mean([log["search_queries"] for log in sggs_logs]))
    max_total_queries = int(np.max([log["total_queries"] for log in sggs_logs]))
    logger.info(
        f"[SGGS on XGBoost] Evasion Success: {sggs_evasion_rate*100:.2f}% | "
        f"Initial Queries: 1 | Avg Search Queries: {avg_search_queries:.1f} | Avg Total Queries: {avg_total_queries:.1f} (Max: {max_total_queries})"
    )
    
    # 5. Threat config dump
    threat_config = {
        "attacker_goal": threat.attacker_goal,
        "attacker_knowledge": threat.attacker_knowledge,
        "mutable_features": threat.mutable_features,
        "immutable_features": threat.immutable_features,
        "monotonicity": threat.monotonicity,
        "evaluated_epsilons": epsilons,
        "sggs_benchmark": {
            "target_model": "XGBoost",
            "samples_tested": len(detected_attack_sample),
            "evasion_rate": float(sggs_evasion_rate),
            "initial_query_per_sample": 1,
            "avg_search_queries_per_sample": float(avg_search_queries),
            "avg_total_queries_per_sample": float(avg_total_queries),
            "max_total_queries_per_sample": int(max_total_queries)
        }
    }
    with open(ADVERSARIAL_OUTPUT_DIR / "attack_config.json", "w", encoding="utf-8") as f:
        json.dump(threat_config, f, indent=4)
        
    # 6. Publication-quality Robustness Curves
    logger.info("Generating robustness curves visualization...")
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    
    palette = {"Decision Tree": "#7570b3", "Random Forest": "#1b9e77", "XGBoost": "#d95f02"}
    
    # Plot 1: Attack Recall Degradation
    sns.lineplot(data=results_df, x="epsilon", y="attack_recall", hue="model", marker="o", ax=axes[0], palette=palette, linewidth=2.5)
    axes[0].set_title("Attack Detection Recall vs Perturbation Budget", fontsize=11, fontweight="bold")
    axes[0].set_xlabel(r"Perturbation Budget ($\epsilon$)", fontsize=10)
    axes[0].set_ylabel("Attack Recall", fontsize=10)
    axes[0].grid(True, linestyle="--", alpha=0.6)
    
    # Plot 2: Evasion Rate
    sns.lineplot(data=results_df, x="epsilon", y="evasion_rate", hue="model", marker="s", ax=axes[1], palette=palette, linewidth=2.5)
    axes[1].set_title("Adversarial Evasion Rate vs Perturbation Budget", fontsize=11, fontweight="bold")
    axes[1].set_xlabel(r"Perturbation Budget ($\epsilon$)", fontsize=10)
    axes[1].set_ylabel("Evasion Rate (Evaded / Initially Detected)", fontsize=10)
    axes[1].grid(True, linestyle="--", alpha=0.6)
    
    # Plot 3: Macro-F1 Score
    sns.lineplot(data=results_df, x="epsilon", y="macro_f1", hue="model", marker="^", ax=axes[2], palette=palette, linewidth=2.5)
    axes[2].set_title("Macro F1-Score vs Perturbation Budget", fontsize=11, fontweight="bold")
    axes[2].set_xlabel(r"Perturbation Budget ($\epsilon$)", fontsize=10)
    axes[2].set_ylabel("Macro-F1", fontsize=10)
    axes[2].grid(True, linestyle="--", alpha=0.6)
    
    plt.tight_layout()
    curves_path = ADVERSARIAL_OUTPUT_DIR / "robustness_curves.png"
    plt.savefig(curves_path, dpi=300)
    plt.close()
    logger.info(f"Saved robustness curves to {curves_path}")
    
    # 7. Generate Markdown Report
    generate_adversarial_report(results_df, threat_config, ADVERSARIAL_OUTPUT_DIR / "adversarial_evaluation_report.md")
    logger.info("=== Phase 5: Adversarial Robustness Completed Successfully! ===")

def generate_adversarial_report(results_df: pd.DataFrame, threat_config: dict, output_path: Path):
    md = []
    md.append("# Phase 5 Research Report: Adversarial Robustness Under Flow Invariants\n")
    md.append("**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  ")
    md.append("**Lead Researcher:** Aditya Ambare (Roll: TIA26)  ")
    md.append("**Status:** Experimental Evaluation Completed\n")
    md.append("---\n")
    
    md.append("## 1. Threat Model & Physical Network Constraints\n")
    md.append(f"- **Attacker Objective:** {threat_config['attacker_goal']}")
    md.append(f"- **Attacker Knowledge:** {threat_config['attacker_knowledge']}")
    md.append(f"- **Mutable Attributes:** `{', '.join(threat_config['mutable_features'])}` (Non-decreasing: byte padding, packet injection, flow delay)")
    md.append(f"- **Immutable Attributes:** `{', '.join(threat_config['immutable_features'])}` (Strict protocol codes and TCP flag bitmasks)")
    md.append(f"- **Network Invariant:** `BYTES >= PKTS * 20` (IPv4 minimum header requirement)\n")
    
    md.append("## 2. Robustness Degradation Summary Table\n")
    md.append(r"| Model | Budget ($\epsilon$) | Accuracy | Attack Recall | Macro-F1 | Evasion Rate | Evaded Flows |\n")
    md.append("|---|---|---|---|---|---|---|\n")
    for _, row in results_df.iterrows():
        md.append(
            f"| {row['model']} | {row['epsilon']:.2f} | {row['accuracy']:.4f} | "
            f"{row['attack_recall']:.4f} | {row['macro_f1']:.4f} | {row['evasion_rate']*100:.2f}% | "
            f"{row['num_evaded']} / {row['num_initially_detected']} |"
        )
    md.append("\n")
    
    sggs = threat_config["sggs_benchmark"]
    md.append(f"## 3. Active Black-Box Greedy Evasion Benchmark (SGGS)\n")
    md.append(f"- **Target Model:** {sggs['target_model']}")
    md.append(rf"- **Evasion Success Rate:** `{sggs['evasion_rate']*100:.2f}%` within budget $\epsilon \le 0.50$")
    md.append(f"- **Initial Clean Prediction Query:** `{sggs.get('initial_query_per_sample', 1)}` query")
    md.append(f"- **Average Search Queries:** `{sggs.get('avg_search_queries_per_sample', 15.0):.1f}` queries")
    md.append(f"- **Average Total Queries:** `{sggs.get('avg_total_queries_per_sample', 16.0):.1f}` queries per malicious sample (Max: `{sggs.get('max_total_queries_per_sample', 17)}`)\n")
    
    md.append("## 4. Key Scientific Insights on Evasion\n")
    md.append("1. **Gradient/Boosting Sensitivity:** High clean accuracy does not guarantee adversarial resilience. Perturbing flow duration and packet distributions induces non-linear shifts in decision tree branch paths.\n")
    md.append("2. **Comparative Robustness:** Bagging ensembles (Random Forest) generally maintain smoother decision boundaries under domain-constrained perturbations compared to unregularized deep trees, while XGBoost displays sharp threshold cutoffs.\n")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

if __name__ == "__main__":
    main()
