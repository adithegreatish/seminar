"""
Explanation Stability Analysis Module.
Quantifies SHAP attribution drift under adversarial perturbations.
"""

from dataclasses import dataclass
import numpy as np
import pandas as pd
from scipy.stats import spearmanr

@dataclass
class StabilityMetrics:
    """Detailed explanation stability metrics across samples."""
    l1_drift: np.ndarray
    normalized_l2_drift: np.ndarray
    topk_overlap: np.ndarray
    rank_correlations: np.ndarray
    prediction_changed: np.ndarray
    clean_predictions: np.ndarray
    pert_predictions: np.ndarray
    quadrants: list[str]

def compute_attribution_stability(
    phi_clean: np.ndarray,
    phi_pert: np.ndarray,
    preds_clean: np.ndarray,
    preds_pert: np.ndarray,
    k: int = 3,
    eps_zero: float = 1e-6
) -> tuple[pd.DataFrame, StabilityMetrics]:
    """
    Computes paired attribution metrics:
    1. L1 Drift: mean absolute difference across features
    2. Normalized L2 Drift: ||phi - phi'||_2 / (||phi||_2 + eps)
    3. Top-k Feature Overlap: |TopK(clean) ∩ TopK(pert)| / k
    4. Spearman Rank Correlation: correlation of feature attribution rankings
    5. Four-quadrant classification (Prediction Stability vs Explanation Stability)
    """
    n_samples, n_features = phi_clean.shape
    
    # 1. L1 Attribution Drift
    l1_drift = np.mean(np.abs(phi_clean - phi_pert), axis=1)
    
    # 2. Normalized L2 Drift
    diff_norm = np.linalg.norm(phi_clean - phi_pert, axis=1)
    clean_norm = np.linalg.norm(phi_clean, axis=1)
    norm_l2_drift = diff_norm / (clean_norm + eps_zero)
    
    # 3. Top-k Overlap & 4. Spearman Rank Correlation
    topk_overlap = np.zeros(n_samples)
    spearman_corrs = np.zeros(n_samples)
    
    for i in range(n_samples):
        # Top-k based on absolute SHAP importance
        topk_c = set(np.argsort(np.abs(phi_clean[i]))[-k:])
        topk_p = set(np.argsort(np.abs(phi_pert[i]))[-k:])
        topk_overlap[i] = len(topk_c.intersection(topk_p)) / k
        
        # Spearman correlation across features
        # If std is 0 (constant attributions), correlation is undefined; treat as 1.0 if identical or 0.0
        if np.std(phi_clean[i]) > 1e-9 and np.std(phi_pert[i]) > 1e-9:
            corr, _ = spearmanr(phi_clean[i], phi_pert[i])
            spearman_corrs[i] = 0.0 if np.isnan(corr) else corr
        else:
            spearman_corrs[i] = 1.0 if np.allclose(phi_clean[i], phi_pert[i]) else 0.0
            
    # 5. Prediction-Change vs Explanation-Change Quadrants
    pred_changed = (preds_clean != preds_pert)
    median_l1 = np.median(l1_drift)
    
    quadrants = []
    for i in range(n_samples):
        p_ch = pred_changed[i]
        exp_drift = (l1_drift[i] >= median_l1)
        
        if not p_ch and not exp_drift:
            quadrants.append("Q1: Prediction Stable, Explanation Stable")
        elif not p_ch and exp_drift:
            quadrants.append("Q2: Prediction Stable, Explanation Fragile")
        elif p_ch and exp_drift:
            quadrants.append("Q3: Prediction Flipped, Explanation Shifted")
        else:
            quadrants.append("Q4: Prediction Flipped, Explanation Deceptive")
            
    df_metrics = pd.DataFrame({
        "sample_id": np.arange(n_samples),
        "clean_pred": preds_clean,
        "pert_pred": preds_pert,
        "pred_changed": pred_changed,
        "l1_drift": l1_drift,
        "norm_l2_drift": norm_l2_drift,
        f"top_{k}_overlap": topk_overlap,
        "spearman_rank_corr": spearman_corrs,
        "quadrant": quadrants
    })
    
    metrics_obj = StabilityMetrics(
        l1_drift=l1_drift,
        normalized_l2_drift=norm_l2_drift,
        topk_overlap=topk_overlap,
        rank_correlations=spearman_corrs,
        prediction_changed=pred_changed,
        clean_predictions=preds_clean,
        pert_predictions=preds_pert,
        quadrants=quadrants
    )
    
    return df_metrics, metrics_obj

