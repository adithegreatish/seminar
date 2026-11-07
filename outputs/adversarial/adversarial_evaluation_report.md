# Phase 5 Research Report: Adversarial Robustness Under Flow Invariants

**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Status:** Experimental Evaluation Completed

---

## 1. Threat Model & Physical Network Constraints

- **Attacker Objective:** Evasion (Target: Benign classification / Label=0)
- **Attacker Knowledge:** Grey-box / Surrogate-guided (Access to feature importance and query outputs)
- **Mutable Attributes:** `IN_BYTES, OUT_BYTES, IN_PKTS, OUT_PKTS, FLOW_DURATION_MILLISECONDS` (Non-decreasing: byte padding, packet injection, flow delay)
- **Immutable Attributes:** `PROTOCOL, L7_PROTO, TCP_FLAGS` (Strict protocol codes and TCP flag bitmasks)
- **Network Invariant:** `BYTES >= PKTS * 20` (IPv4 minimum header requirement)

## 2. Robustness Degradation Summary Table

| Model | Budget ($\epsilon$) | Accuracy | Attack Recall | Macro-F1 | Evasion Rate | Evaded Flows |\n
|---|---|---|---|---|---|---|

| Decision Tree | 0.00 | 0.9376 | 0.8597 | 0.9281 | 0.00% | 0 / 1673 |
| Random Forest | 0.00 | 0.9421 | 0.8577 | 0.9329 | 0.00% | 0 / 1669 |
| XGBoost | 0.00 | 0.9450 | 0.8551 | 0.9360 | 0.00% | 0 / 1664 |
| Decision Tree | 0.05 | 0.8825 | 0.7842 | 0.8650 | 10.34% | 173 / 1673 |
| Random Forest | 0.05 | 0.9130 | 0.7580 | 0.8956 | 11.62% | 194 / 1669 |
| XGBoost | 0.05 | 0.9385 | 0.8520 | 0.9287 | 0.66% | 11 / 1664 |
| Decision Tree | 0.10 | 0.8681 | 0.7621 | 0.8485 | 13.39% | 224 / 1673 |
| Random Forest | 0.10 | 0.9070 | 0.7390 | 0.8877 | 13.90% | 232 / 1669 |
| XGBoost | 0.10 | 0.9239 | 0.8191 | 0.9113 | 4.45% | 74 / 1664 |
| Decision Tree | 0.20 | 0.8433 | 0.6937 | 0.8167 | 21.40% | 358 / 1673 |
| Random Forest | 0.20 | 0.8684 | 0.6146 | 0.8334 | 28.46% | 475 / 1669 |
| XGBoost | 0.20 | 0.8695 | 0.6701 | 0.8411 | 21.94% | 365 / 1664 |
| Decision Tree | 0.30 | 0.8493 | 0.6871 | 0.8220 | 21.76% | 364 / 1673 |
| Random Forest | 0.30 | 0.8582 | 0.5904 | 0.8191 | 31.34% | 523 / 1669 |
| XGBoost | 0.30 | 0.8582 | 0.6583 | 0.8279 | 23.32% | 388 / 1664 |
| Decision Tree | 0.50 | 0.8051 | 0.5807 | 0.7638 | 34.43% | 576 / 1673 |
| Random Forest | 0.50 | 0.8246 | 0.5118 | 0.7711 | 40.50% | 676 / 1669 |
| XGBoost | 0.50 | 0.8299 | 0.5689 | 0.7866 | 33.83% | 563 / 1664 |


## 3. Active Black-Box Greedy Evasion Benchmark (SGGS)

- **Target Model:** XGBoost
- **Evasion Success Rate:** `6.00%` within budget $\epsilon \le 0.50$
- **Initial Clean Prediction Query:** `1` query
- **Average Search Queries:** `14.9` queries
- **Average Total Queries:** `15.9` queries per malicious sample (Max: `16`)

## 4. Key Scientific Insights on Evasion

1. **Gradient/Boosting Sensitivity:** High clean accuracy does not guarantee adversarial resilience. Perturbing flow duration and packet distributions induces non-linear shifts in decision tree branch paths.

2. **Comparative Robustness:** Bagging ensembles (Random Forest) generally maintain smoother decision boundaries under domain-constrained perturbations compared to unregularized deep trees, while XGBoost displays sharp threshold cutoffs.
