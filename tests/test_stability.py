"""
Tests for Phase 6: Explanation stability metrics and quadrant categorization.
"""

import pytest
import numpy as np
import pandas as pd
from src.evaluation.stability import compute_attribution_stability

def test_compute_attribution_stability_metrics():
    # Identical explanations (zero drift)
    phi_clean = np.array([
        [0.5, 0.2, -0.1, 0.0],
        [0.1, -0.4, 0.3, 0.8]
    ])
    phi_pert = np.array([
        [0.5, 0.2, -0.1, 0.0],  # Exactly identical
        [0.0, 0.0, 0.0, 0.1]    # Drifted
    ])
    preds_clean = np.array([1, 1])
    preds_pert = np.array([1, 0])  # Sample 0 stable, sample 1 flipped
    
    df, metrics = compute_attribution_stability(
        phi_clean, phi_pert, preds_clean, preds_pert, k=2
    )
    
    # Sample 0 checks
    assert df["l1_drift"].iloc[0] == 0.0
    assert df["norm_l2_drift"].iloc[0] == 0.0
    assert df["top_2_overlap"].iloc[0] == 1.0
    assert df["spearman_rank_corr"].iloc[0] == 1.0
    assert not df["pred_changed"].iloc[0]
    assert "Q1" in df["quadrant"].iloc[0]
    
    # Sample 1 checks
    assert df["l1_drift"].iloc[1] > 0.0
    assert df["pred_changed"].iloc[1]
    assert "Q3" in df["quadrant"].iloc[1] or "Q4" in df["quadrant"].iloc[1]

