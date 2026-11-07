"""
Execution script for Phase 6: Explanation Stability Analysis.
Quantifies SHAP attribution drift under adversarial perturbations on paired network flows.
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
    STABILITY_OUTPUT_DIR,
    MODELS_OUTPUT_DIR,
    PROCESSED_DATA_DIR,
    RANDOM_SEED
)
from src.utils.logger import setup_logger
from src.models.baseline_models import NIDSModelWrapper
from src.explainability.shap_explainer import NIDSShapExplainer
from src.adversarial.threats import ThreatModel
from src.adversarial.attacks import DomainConstrainedPerturbationAttack
from src.evaluation.stability import compute_attribution_stability

logger = setup_logger("script_04_stability")

def main():
    logger.info("=== Starting Phase 6: Explanation Stability Analysis ===")
    STABILITY_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Load test data
    cache_dir = PROCESSED_DATA_DIR / "sample_200000_ports_False"
    X_test = pd.read_parquet(cache_dir / "X_test.parquet")
    y_test_df = pd.read_parquet(cache_dir / "y_test.parquet")
    y_test = y_test_df["Label"].values
    
    # 2. Load trained XGBoost binary model
    xgb_model = NIDSModelWrapper.load(MODELS_OUTPUT_DIR / "xgboost_binary.joblib")
    
    # 3. Select paired attack samples correctly detected initially
    y_pred_clean, _ = xgb_model.predict(X_test)
    detected_attack_indices = np.where((y_test == 1) & (y_pred_clean == 1))[0]
    
    # Take a representative paired cohort (e.g. 500 samples)
    np.random.seed(RANDOM_SEED)
    sample_size = min(500, len(detected_attack_indices))
    selected_indices = np.random.choice(detected_attack_indices, size=sample_size, replace=False)
    
    X_clean_attacks = X_test.iloc[selected_indices].reset_index(drop=True)
    
    # 4. Generate perturbed pairs at epsilon = 0.20
    eval_epsilon = 0.20
    threat = ThreatModel()
    dcpa = DomainConstrainedPerturbationAttack(threat)
    X_pert_attacks = dcpa.generate(X_clean_attacks, epsilon=eval_epsilon)
    
    logger.info(f"Computing paired SHAP explanations for {sample_size} attacks at epsilon={eval_epsilon}...")
    
    # Predictions on clean and perturbed pairs
    preds_clean, _ = xgb_model.predict(X_clean_attacks)
    preds_pert, _ = xgb_model.predict(X_pert_attacks)
    evasion_count = sum((preds_clean == 1) & (preds_pert == 0))
    logger.info(f"Paired evaluation: {evasion_count}/{sample_size} attacks successfully evaded ({evasion_count/sample_size*100:.2f}%)")
    
    # 5. Compute SHAP attributions for clean and perturbed pairs
    explainer = NIDSShapExplainer(xgb_model)
    phi_clean, _ = explainer.compute_shap_values(X_clean_attacks)
    phi_pert, _ = explainer.compute_shap_values(X_pert_attacks)
    
    # 6. Calculate Attribution Stability Metrics
    df_metrics, metrics_obj = compute_attribution_stability(
        phi_clean=phi_clean,
        phi_pert=phi_pert,
        preds_clean=preds_clean,
        preds_pert=preds_pert,
        k=3
    )
    
    # Save CSV outputs
    df_metrics[["sample_id", "l1_drift", "norm_l2_drift"]].to_csv(STABILITY_OUTPUT_DIR / "shap_drift.csv", index=False)
    df_metrics[["sample_id", "top_3_overlap"]].to_csv(STABILITY_OUTPUT_DIR / "topk_overlap.csv", index=False)
    df_metrics[["sample_id", "spearman_rank_corr"]].to_csv(STABILITY_OUTPUT_DIR / "rank_correlation.csv", index=False)
    df_metrics.to_csv(STABILITY_OUTPUT_DIR / "quadrant_analysis.csv", index=False)
    logger.info(f"Saved tabular stability metrics to {STABILITY_OUTPUT_DIR}")
    
    # 7. Multi-panel Visualization
    logger.info("Generating publication-quality explanation stability visualization...")
    fig, axes = plt.subplots(2, 2, figsize=(14, 11))
    
    # Panel A: L1 Attribution Drift Distribution
    sns.histplot(df_metrics["l1_drift"], bins=25, kde=True, ax=axes[0, 0], color="#2b5c8f")
    axes[0, 0].set_title(rf"A. SHAP Attribution $L_1$ Drift Distribution ($\epsilon={eval_epsilon}$)", fontsize=11, fontweight="bold")
    axes[0, 0].set_xlabel("Mean Absolute Attribution Drift ($L_1$)", fontsize=10)
    axes[0, 0].axvline(np.mean(df_metrics["l1_drift"]), color="red", linestyle="--", label=f"Mean: {np.mean(df_metrics['l1_drift']):.3f}")
    axes[0, 0].legend()
    
    # Panel B: Top-3 Feature Overlap
    overlap_counts = df_metrics["top_3_overlap"].value_counts(normalize=True).sort_index()
    sns.barplot(x=overlap_counts.index, y=overlap_counts.values * 100, ax=axes[0, 1], palette="crest")
    axes[0, 1].set_title("B. Top-3 Feature Importance Set Overlap", fontsize=11, fontweight="bold")
    axes[0, 1].set_xlabel("Top-3 Overlap Ratio (Jaccard)", fontsize=10)
    axes[0, 1].set_ylabel("Percentage of Samples (%)", fontsize=10)
    for p in axes[0, 1].patches:
        height = p.get_height()
        axes[0, 1].annotate(f"{height:.1f}%", (p.get_x() + p.get_width() / 2., height),
                            ha='center', va='bottom', fontsize=9, xytext=(0, 3), textcoords='offset points')
                            
    # Panel C: Spearman Rank Correlation Distribution
    sns.histplot(df_metrics["spearman_rank_corr"], bins=20, kde=True, ax=axes[1, 0], color="#7570b3")
    axes[1, 0].set_title(r"C. Feature Attribution Rank Correlation (Spearman $\rho_s$)", fontsize=11, fontweight="bold")
    axes[1, 0].set_xlabel(r"Spearman Correlation ($\phi_{clean}$ vs $\phi_{pert}$)", fontsize=10)
    axes[1, 0].axvline(np.mean(df_metrics["spearman_rank_corr"]), color="red", linestyle="--",
                       label=f"Mean: {np.mean(df_metrics['spearman_rank_corr']):.3f}")
    axes[1, 0].legend()
    
    # Panel D: Four-Quadrant Analysis (Prediction vs Explanation)
    quad_counts = df_metrics["quadrant"].value_counts()
    quad_labels = [q.split(":")[0] for q in quad_counts.index]
    sns.barplot(x=quad_labels, y=quad_counts.values, ax=axes[1, 1], palette="Set2")
    axes[1, 1].set_title("D. Prediction Change vs Explanation Drift Quadrants", fontsize=11, fontweight="bold")
    axes[1, 1].set_ylabel("Flow Count", fontsize=10)
    axes[1, 1].set_xlabel("Quadrant (Q1: Stable, Q2: Fragile, Q3: Shifted, Q4: Deceptive)", fontsize=9)
    for p in axes[1, 1].patches:
        height = p.get_height()
        axes[1, 1].annotate(f"{height:,.0f} ({height/len(df_metrics)*100:.1f}%)",
                            (p.get_x() + p.get_width() / 2., height),
                            ha='center', va='bottom', fontsize=9, xytext=(0, 3), textcoords='offset points')
                            
    plt.tight_layout()
    fig_path = STABILITY_OUTPUT_DIR / "explanation_stability.png"
    plt.savefig(fig_path, dpi=300)
    plt.close()
    logger.info(f"Saved explanation stability plots to {fig_path}")
    
    # 8. Generate Research Report
    generate_stability_report(df_metrics, eval_epsilon, STABILITY_OUTPUT_DIR / "explanation_stability_report.md")
    logger.info("=== Phase 6: Explanation Stability Completed Successfully! ===")

def generate_stability_report(df_metrics: pd.DataFrame, epsilon: float, output_path: Path):
    md = []
    md.append("# Phase 6 Research Report: Explanation Stability Under Adversarial Perturbations\n")
    md.append("**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  ")
    md.append("**Lead Researcher:** Aditya Ambare (Roll: TIA26)  ")
    md.append("**Status:** Experimental Evaluation Completed\n")
    md.append("---\n")
    
    md.append("## 1. Executive Summary: The Link Between Robustness and Explainability\n")
    md.append(rf"To assess explanation stability, paired SHAP values $\phi(x)$ and $\phi(x')$ were computed for malicious network flows subjected to domain-constrained perturbation at budget $\epsilon = {epsilon:.2f}$.\n")
    
    mean_l1 = np.mean(df_metrics["l1_drift"])
    median_l1 = np.median(df_metrics["l1_drift"])
    mean_norm = np.mean(df_metrics["norm_l2_drift"])
    mean_top3 = np.mean(df_metrics["top_3_overlap"])
    mean_spearman = np.mean(df_metrics["spearman_rank_corr"])
    evasion_pct = np.mean(df_metrics["pred_changed"]) * 100
    
    md.append("## 2. Quantitative Stability Metrics\n")
    md.append("| Metric | Mean | Median | Standard Deviation | Research Interpretation |\n")
    md.append("|---|---|---|---|---|\n")
    md.append(f"| **$L_1$ Attribution Drift** | {mean_l1:.4f} | {median_l1:.4f} | {np.std(df_metrics['l1_drift']):.4f} | Average absolute change in feature log-odds attributions |")
    md.append(f"| **Normalized $L_2$ Drift** | {mean_norm:.4f} | {np.median(df_metrics['norm_l2_drift']):.4f} | {np.std(df_metrics['norm_l2_drift']):.4f} | Relative magnitude change relative to clean explanation norm |")
    md.append(f"| **Top-3 Feature Overlap** | {mean_top3:.4f} | {np.median(df_metrics['top_3_overlap']):.4f} | {np.std(df_metrics['top_3_overlap']):.4f} | Fraction of top 3 most influential features retained |")
    md.append(f"| **Spearman Rank Correlation ($\rho_s$)** | {mean_spearman:.4f} | {np.median(df_metrics['spearman_rank_corr']):.4f} | {np.std(df_metrics['spearman_rank_corr']):.4f} | Consistency of relative feature ranking order |")
    md.append(f"| **Perturbation Evasion Rate** | {evasion_pct:.2f}% | - | - | Percentage of attacks successfully evading detection |")
    md.append("\n")
    
    md.append("## 3. Four-Quadrant Behavioral Analysis (Prediction vs. Explanation)\n")
    quad_counts = df_metrics["quadrant"].value_counts()
    for q_name, cnt in quad_counts.items():
        pct = (cnt / len(df_metrics)) * 100
        md.append(f"- **{q_name}:** `{cnt}` samples ({pct:.1f}%)")
    md.append("\n")
    
    md.append("### Quadrant Definitions:\n")
    md.append("- **Quadrant I (Stable Detection):** Prediction remains Attack, and SHAP feature ranking remains stable. The system maintains dependable security and explanation fidelity.")
    md.append("- **Quadrant II (Fragile Explanation):** Prediction remains Attack, but SHAP feature attributions shift dramatically. The prediction is correct, but the rationale is unstable under flow variation.")
    md.append("- **Quadrant III (Reflective Shift):** Prediction flips to Benign (evasion succeeded), and SHAP attribution shifts accordingly, capturing the altered decision pathway.")
    md.append("- **Quadrant IV (Deceptive Stability):** Prediction flips to Benign (evasion succeeded), but top feature attributions appear superficially similar to clean profiles, misleading human analysts.\n")
    
    md.append("## 4. Scientific Caveats: Limitations of SHAP as a Security Indicator\n")
    md.append("> [!WARNING]\n")
    md.append("> A stable SHAP explanation **does not guarantee security correctness**. If an adversary crafts a perturbation that causes a model to misclassify an attack while preserving feature attribution rank order (Quadrant IV), relying solely on explanation stability as a trust metric would create a dangerous false sense of security. Robustness must be evaluated jointly across decision boundaries and attribution spaces.\n")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

if __name__ == "__main__":
    main()
