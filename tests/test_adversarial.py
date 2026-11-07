"""
Tests for Phase 5: Adversarial threat model, domain invariants, and attacks.
"""

import pytest
import numpy as np
import pandas as pd
from src.adversarial.threats import ThreatModel, enforce_domain_constraints
from src.adversarial.attacks import DomainConstrainedPerturbationAttack

def test_enforce_domain_constraints():
    X_clean = pd.DataFrame({
        "PROTOCOL": [6, 17],
        "TCP_FLAGS": [2, 18],
        "L7_PROTO": [0.0, 50.0],
        "IN_BYTES": [100, 200],
        "OUT_BYTES": [50, 100],
        "IN_PKTS": [2, 5],
        "OUT_PKTS": [1, 2],
        "FLOW_DURATION_MILLISECONDS": [1000, 2000]
    })
    
    # Try invalid perturbation (e.g. negative values, altered protocol, reduced bytes)
    X_perturbed_invalid = pd.DataFrame({
        "PROTOCOL": [99, 12],            # Invalid / changed
        "TCP_FLAGS": [255, 0],           # Changed flags
        "L7_PROTO": [999.0, -10.0],      # Changed
        "IN_BYTES": [10, 50],            # Decreased below clean!
        "OUT_BYTES": [-50, 20],          # Negative!
        "IN_PKTS": [0.5, 10],            # Float packet count!
        "OUT_PKTS": [-1, 2],             # Negative packet!
        "FLOW_DURATION_MILLISECONDS": [-100, 5000]
    })
    
    X_enforced = enforce_domain_constraints(X_perturbed_invalid, X_clean)
    
    # Invariant 1: Protocol, TCP_FLAGS, L7_PROTO must match clean exactly
    assert list(X_enforced["PROTOCOL"]) == list(X_clean["PROTOCOL"])
    assert list(X_enforced["TCP_FLAGS"]) == list(X_clean["TCP_FLAGS"])
    assert list(X_enforced["L7_PROTO"]) == list(X_clean["L7_PROTO"])
    
    # Invariant 2: Monotonicity (values must not be less than clean)
    assert (X_enforced["IN_BYTES"] >= X_clean["IN_BYTES"]).all()
    assert (X_enforced["FLOW_DURATION_MILLISECONDS"] >= X_clean["FLOW_DURATION_MILLISECONDS"]).all()
    
    # Invariant 3: Packet counts must be integers >= 1
    assert (X_enforced["IN_PKTS"] >= 1).all()
    assert np.issubdtype(X_enforced["IN_PKTS"].dtype, np.integer)
    
    # Invariant 4: Bytes >= Packets * 20
    assert (X_enforced["IN_BYTES"] >= X_enforced["IN_PKTS"] * 20).all()

def test_dcpa_attack_generation():
    X_clean = pd.DataFrame({
        "PROTOCOL": [6],
        "TCP_FLAGS": [2],
        "L7_PROTO": [0.0],
        "IN_BYTES": [100],
        "OUT_BYTES": [100],
        "IN_PKTS": [2],
        "OUT_PKTS": [2],
        "FLOW_DURATION_MILLISECONDS": [1000]
    })
    threat = ThreatModel()
    dcpa = DomainConstrainedPerturbationAttack(threat)
    
    X_pert = dcpa.generate(X_clean, epsilon=0.20)
    assert X_pert["PROTOCOL"].iloc[0] == 6
    assert X_pert["IN_BYTES"].iloc[0] >= 120
    assert X_pert["FLOW_DURATION_MILLISECONDS"].iloc[0] == 1200

def test_dcpa_zero_epsilon_returns_identical():
    """Verify that epsilon = 0.0 returns the clean input exactly without modification."""
    X_clean = pd.DataFrame({
        "PROTOCOL": [6, 17, 6],
        "TCP_FLAGS": [2, 0, 18],
        "L7_PROTO": [0.0, 50.0, 0.0],
        "IN_BYTES": [100, 200, 480],
        "OUT_BYTES": [50, 100, 240],
        "IN_PKTS": [2, 5, 10],
        "OUT_PKTS": [1, 2, 8],
        "FLOW_DURATION_MILLISECONDS": [1000, 2000, 5000]
    })
    threat = ThreatModel()
    dcpa = DomainConstrainedPerturbationAttack(threat)
    
    X_pert_zero = dcpa.generate(X_clean, epsilon=0.0)
    assert np.array_equal(X_clean.values, X_pert_zero.values), "Epsilon 0 must return original clean input exactly!"


