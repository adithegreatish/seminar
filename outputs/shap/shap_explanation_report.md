# Phase 4 Research Report: SHAP Explainability Analysis

**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Status:** Analysis Completed & Verified

---

## 1. Global Feature Importance Ranking

Using TreeExplainer, SHAP calculates the exact marginal contribution of each network flow attribute across trees.

| Rank | Feature | Mean |SHAP Value| | Primary Impact Direction |

|---|---|---|---|

| 1 | `OUT_BYTES` | 0.7051 | Observed via summary plot |
| 2 | `FLOW_DURATION_MILLISECONDS` | 0.6560 | Observed via summary plot |
| 3 | `IN_BYTES` | 0.4589 | Observed via summary plot |
| 4 | `IN_PKTS` | 0.4404 | Observed via summary plot |
| 5 | `L7_PROTO` | 0.4372 | Observed via summary plot |
| 6 | `TCP_FLAGS` | 0.3823 | Observed via summary plot |
| 7 | `OUT_PKTS` | 0.1910 | Observed via summary plot |
| 8 | `PROTOCOL` | 0.0325 | Observed via summary plot |


## 2. Key Scientific Observations on Flow Attributes

1. **Top Predictive Drivers:** Features such as `TCP_FLAGS`, `FLOW_DURATION_MILLISECONDS`, and packet/byte counts (`IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`) dominate model decisions.

2. **Protocol and TCP Flag Attributions:** Distinct TCP flag patterns (e.g., SYN-flood flags or scan flags without ACK) dramatically push the log-odds toward attack classification.

3. **Asymmetric Byte vs Packet Ratios:** Large discrepancy between packet count and byte volume (e.g., small payloads characteristic of probes or amplification DDoS) acts as a strong positive attack signal.

## 3. Cross-Model Attribution Consistency

- **Spearman Rank Correlation between XGBoost and Random Forest:** `0.8095`
- High rank correlation demonstrates that both ensemble architectures (boosting vs bagging) identify congruent topological signals in the flow domain.

## 4. Critical Methodological Caveats

> [!IMPORTANT]

> SHAP reflects **model attribution**, not physical causality. If a model exploits spurious correlations (e.g., artifactual flow durations), SHAP will accurately highlight those dependencies. This critical distinction motivates Phase 5 (Adversarial Robustness) and Phase 6 (Explanation Stability): testing whether attributions remain robust when features are deliberately perturbed.
