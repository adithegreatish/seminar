"""
Tests for Differentiable MLP and Gradient Attacks (FGSM & PGD).
"""

import pytest
import numpy as np
import pandas as pd
from src.adversarial.neural_baseline import DifferentiableMLP, GradientFlowAttacker
from src.adversarial.threats import ThreatModel

def test_mlp_forward_and_gradient():
    np.random.seed(42)
    X = np.random.randn(20, 8)
    y = np.random.choice([0, 1], size=20)
    
    mlp = DifferentiableMLP(input_dim=8, hidden_dim=16)
    mlp.fit(X, y, epochs=5)
    
    # Check predictions
    probs = mlp.predict_proba(X)
    assert len(probs) == 20
    assert (probs >= 0.0).all() and (probs <= 1.0).all()
    
    # Check gradient shape
    X_norm = (X - mlp.x_mean) / mlp.x_std
    grad = mlp.compute_input_gradient(X_norm, y)
    assert grad.shape == X.shape
    assert not np.isnan(grad).any()

def test_fgsm_and_pgd_attacks():
    threat = ThreatModel()
    cols = [
        "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES",
        "IN_PKTS", "OUT_PKTS", "TCP_FLAGS", "FLOW_DURATION_MILLISECONDS"
    ]
    data = {
        "PROTOCOL": [6, 6],
        "L7_PROTO": [0.0, 0.0],
        "IN_BYTES": [500, 1000],
        "OUT_BYTES": [300, 800],
        "IN_PKTS": [5, 10],
        "OUT_PKTS": [3, 6],
        "TCP_FLAGS": [2, 18],
        "FLOW_DURATION_MILLISECONDS": [2000, 5000]
    }
    df = pd.DataFrame(data)
    
    mlp = DifferentiableMLP(input_dim=8, hidden_dim=16)
    mlp.fit(df.values, np.array([1, 1]), epochs=5)
    
    attacker = GradientFlowAttacker(mlp, threat)
    
    # Run FGSM
    df_fgsm = attacker.fgsm_attack(df, epsilon=0.10)
    assert df_fgsm["PROTOCOL"].iloc[0] == 6
    assert (df_fgsm["IN_BYTES"] >= df["IN_BYTES"]).all()
    
    # Run PGD
    df_pgd = attacker.pgd_attack(df, epsilon=0.10, steps=3)
    assert df_pgd["PROTOCOL"].iloc[0] == 6
    assert (df_pgd["IN_BYTES"] >= df["IN_BYTES"]).all()

