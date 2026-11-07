"""
Domain-Constrained Threat Model and Network Flow Invariants for NIDS.
"""

from dataclasses import dataclass, field
import numpy as np
import pandas as pd

@dataclass
class ThreatModel:
    """
    Formal threat model specification for tabular network flow evasion.
    """
    attacker_goal: str = "Evasion (Target: Benign classification / Label=0)"
    attacker_knowledge: str = "Grey-box / Surrogate-guided (Access to feature importance and query outputs)"
    
    # Features an adversary can realistically manipulate during flow transmission:
    # 1. IN_BYTES: Add dummy payload / padding bytes to inbound packets
    # 2. OUT_BYTES: Add dummy payload / padding bytes to outbound packets
    # 3. IN_PKTS: Split payload across extra packets or inject keepalive packets
    # 4. OUT_PKTS: Inject dummy acknowledgement/reset packets
    # 5. FLOW_DURATION_MILLISECONDS: Delay packet inter-arrival times
    mutable_features: list[str] = field(default_factory=lambda: [
        "IN_BYTES",
        "OUT_BYTES",
        "IN_PKTS",
        "OUT_PKTS",
        "FLOW_DURATION_MILLISECONDS"
    ])
    
    # Immutable features during an established session:
    # PROTOCOL (TCP=6, UDP=17) cannot be changed without breaking session parsing
    # TCP_FLAGS cannot take arbitrary continuous values (must remain valid bitmasks)
    # L7_PROTO is determined by the application protocol parser
    immutable_features: list[str] = field(default_factory=lambda: [
        "PROTOCOL",
        "L7_PROTO",
        "TCP_FLAGS"
    ])
    
    # Directional constraint: Adversaries can ADD bytes, packets, and duration, but cannot subtract them
    # (i.e. packets already sent cannot be un-sent)
    monotonicity: str = "non-decreasing (delta >= 0)"
    
    # Minimum packet size invariant: 20 bytes for IPv4 header
    min_bytes_per_pkt: int = 20

def enforce_domain_constraints(X_perturbed: pd.DataFrame, X_clean: pd.DataFrame) -> pd.DataFrame:
    """
    Applies network domain physics and validity constraints to perturbed flow records:
    1. Monotonicity: Perturbed mutable values must be >= clean values (no negative packet/byte deletions).
    2. Non-negativity: All numerical attributes must be >= 0.
    3. Packet Integrality: Packet counts must be integers.
    4. Packet-to-Byte Consistency: Total bytes must be at least 20 bytes per packet.
    5. Immutability: PROTOCOL, L7_PROTO, TCP_FLAGS must remain exactly identical to clean records.
    """
    X_fixed = X_perturbed.copy()
    
    # 1. Immutable features restoration
    for col in ["PROTOCOL", "L7_PROTO", "TCP_FLAGS"]:
        if col in X_fixed.columns and col in X_clean.columns:
            X_fixed[col] = X_clean[col].values
            
    # 2. Monotonicity and Non-negativity on mutable features
    mutable_cols = ["IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS", "FLOW_DURATION_MILLISECONDS"]
    for col in mutable_cols:
        if col in X_fixed.columns and col in X_clean.columns:
            # Must not be less than clean value
            X_fixed[col] = np.maximum(X_fixed[col], X_clean[col])
            # Must be non-negative
            X_fixed[col] = np.maximum(X_fixed[col], 0)
            
    # 3. Packet integrality
    if "IN_PKTS" in X_fixed.columns:
        X_fixed["IN_PKTS"] = np.round(X_fixed["IN_PKTS"]).astype(int)
        X_fixed["IN_PKTS"] = np.maximum(X_fixed["IN_PKTS"], 1) # At least 1 packet in a flow
    if "OUT_PKTS" in X_fixed.columns:
        X_fixed["OUT_PKTS"] = np.round(X_fixed["OUT_PKTS"]).astype(int)
        X_fixed["OUT_PKTS"] = np.maximum(X_fixed["OUT_PKTS"], 0)
        
    # 4. Physical consistency: Bytes >= Packets * 20
    if "IN_BYTES" in X_fixed.columns and "IN_PKTS" in X_fixed.columns:
        X_fixed["IN_BYTES"] = np.maximum(X_fixed["IN_BYTES"], X_fixed["IN_PKTS"] * 20)
    if "OUT_BYTES" in X_fixed.columns and "OUT_PKTS" in X_fixed.columns:
        # If OUT_PKTS > 0, OUT_BYTES must be at least OUT_PKTS * 20
        out_min = np.where(X_fixed["OUT_PKTS"] > 0, X_fixed["OUT_PKTS"] * 20, 0)
        X_fixed["OUT_BYTES"] = np.maximum(X_fixed["OUT_BYTES"], out_min)
        
    return X_fixed

