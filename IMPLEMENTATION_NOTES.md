# Implementation Notes & Experimental Log
**Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Researcher:** Aditya Ambare (Roll: TIA26)  
**Academic Program:** Third Year B.E. Information Technology Technical Seminar  
**Date Completed:** 2026-11-07  

---

## 1. Executive Summary & Research Scope
This research investigates the dual paradigm of **Explainable AI (XAI)** and **Adversarial Robustness** in Machine Learning-based Network Intrusion Detection Systems (NIDS). The goal is to evaluate whether predictions and SHAP feature attributions remain dependable when inputs are subjected to domain-constrained adversarial perturbations under physical network invariants.

---

## 2. Existing Repository Audit & Baseline Findings

### 2.1 Repository Artifacts Inspected
- `Random_Forest.ipynb`: 31 cells, containing exploratory code, path errors, stale variables (`y_binary_train`, `y_train` NameErrors), and late-stage sampled experiments.
- `XG_Boost.ipynb`: 4 cells, executing binary and multiclass XGBoost classifiers on a 500,000-row sample.

### 2.2 Existing Notebook Reported Results (Unverified Reference Baseline)
*Note: These figures are extracted directly from existing notebook outputs and are not independently verified results.*
- **XGBoost Binary:**
  - Accuracy: ~98.18%
  - Macro F1: ~0.9248
  - Training Time: ~5.04 s
  - Inference Latency: ~0.0006 ms/sample
- **Random Forest Multiclass:**
  - Accuracy: ~85.97%
  - Macro F1: ~0.6270
  - Weighted F1: ~0.9116
- **XGBoost Multiclass:**
  - Severe recall degradation on dominant Benign class (~0.58) caused by uncalibrated `sample_weight="balanced"` on extreme imbalance.
  - Overall accuracy degraded to ~60%.

### 2.3 Identified Methodological Defects in Original Notebooks
1. **Data Leakage in Preprocessing:** `X = X.fillna(X.median())` was computed on the entire sample before train/test splitting.
2. **Missing Validation Partition:** Splits were purely 80/20 train/test; hyperparameter tuning and model selection were performed directly against the test set.
3. **Severe Class Imbalance Mishandling:** Extreme minority attack classes (e.g., classes with <10 samples) distorted balanced weights, resulting in poor benign recall in multiclass settings.
4. **Unjustified Feature Exclusion:** `L4_SRC_PORT` and `L4_DST_PORT` were discarded arbitrarily without an ablation study.
5. **No Adversarial or Explainability Analysis:** Neither notebook evaluated feature attributions (SHAP) or tested resilience under adversarial flow perturbations.

---

## 3. Dataset Verification: NF-CSE-CIC-IDS2018

### 3.1 Dataset Integrity & Schema
- **File:** `data/raw/NF-CSE-CIC-IDS2018.parquet` (extracted from `NF-CSE-CIC-IDS2018.parquet.zip`)
- **Total Records:** 5,918,803 rows
- **Columns (12 total):**
  1. `L4_SRC_PORT` (int32) - Source transport layer port
  2. `L4_DST_PORT` (int32) - Destination transport layer port
  3. `PROTOCOL` (int8) - IP protocol code (e.g., 6=TCP, 17=UDP, 1=ICMP)
  4. `L7_PROTO` (float) - Application layer protocol identifier
  5. `IN_BYTES` (int32) - Incoming byte count
  6. `OUT_BYTES` (int32) - Outgoing byte count
  7. `IN_PKTS` (int32) - Incoming packet count
  8. `OUT_PKTS` (int32) - Outgoing packet count
  9. `TCP_FLAGS` (int16) - Cumulative TCP control flags bitmask
  10. `FLOW_DURATION_MILLISECONDS` (int32) - Flow duration in ms
  11. `Label` (int8) - Binary label (0: Benign, 1: Attack)
  12. `Attack` (string) - Multiclass attack taxonomy
- **Exact Duplicate Rows:** 0 (0.00%)
- **Missing / Infinite Values:** 0 across all columns.
- **Binary Distribution:**
  - Benign (0): 5,534,773 (93.51%)
  - Attack (1): 384,030 (6.49%)
- **Extreme Rare Attack Categories Identified (<250 flows in full dataset):**
  - `SQL Injection`: 36 flows
  - `Brute Force -XSS`: 101 flows
  - `Brute Force -Web`: 173 flows
  - `DDOS attack-HOIC`: 230 flows

---

## 4. Work Completed vs. Pending Log

| Phase | Description | Status | Evidence / Artifact |
|---|---|---|---|
| Phase 0 | Workspace Inspection & Environment Setup | COMPLETED | Python 3.12 `.venv` configured with UV; `requirements.txt` locked |
| Phase 1 | Dataset Audit & Integrity Verification | COMPLETED | `scripts/00_audit_dataset.py`, `outputs/audit/dataset_audit.json`, `dataset_audit.md`, `class_distribution.png` |
| Phase 2 | Clean Preprocessing & Stratified Splitting | COMPLETED | `src/preprocessing/pipeline.py`, `data/processed/`, zero data leakage |
| Phase 3 | ML Baselines (DT, RF, XGBoost) - Binary & Multiclass | COMPLETED | `scripts/01_train_baselines.py`, `outputs/models/`, `outputs/metrics/baseline_metrics.csv` |
| Phase 4 | SHAP Explainability Analysis | COMPLETED | `scripts/02_explain_shap.py`, `outputs/shap/shap_global_importance.csv`, beeswarm & bar plots |
| Phase 5 | Domain-Constrained Adversarial Robustness | COMPLETED | `scripts/03_adversarial_evaluation.py`, `outputs/adversarial/robustness_curves.png`, `robustness_metrics.csv` |
| Phase 6 | Explanation Stability Analysis | COMPLETED | `scripts/04_explanation_stability.py`, `outputs/stability/explanation_stability.png`, `quadrant_analysis.csv` |
| Phase 7 | Comparative Evaluation & Port Ablation Study | COMPLETED | `scripts/05_compare_experiments.py`, `outputs/metrics/model_comparison_table.csv`, `port_ablation_results.csv` |
| Phase 8 | UNSW-NB15 Cross-Dataset Validation Protocol | COMPLETED | `scripts/06_cross_dataset_validation.py`, `outputs/cross_dataset/unsw_nb15_evaluation_protocol.md` |
| Phase 9 | Interactive Streamlit Research Dashboard | COMPLETED | `dashboard/app.py` |
| Test Suite | Automated Unit Tests (11 test cases) | COMPLETED | `tests/`, 11/11 tests passing (100%) |

---

## 5. Experimental Results Summary (Newly Generated & Independently Verified)

### 5.1 Binary ML Baselines ($N=30,000$ Test Set, 8 Features)
- **Decision Tree:** Accuracy = 97.13%, Macro-F1 = 0.8901, Attack Recall = 0.8597, FPR = 0.0209, ROC-AUC = 0.9506.
- **Random Forest:** Accuracy = 97.79%, Macro-F1 = 0.9113, Attack Recall = 0.8577, FPR = 0.0137, ROC-AUC = 0.9574.
- **XGBoost (Top Model Selected by Val Macro-F1 = 0.9171):**
  - Accuracy = **98.16%**
  - Macro-F1 = **0.9238**
  - Attack Recall = **0.8551**
  - FPR = **0.0097**
  - ROC-AUC = **0.9621**
  - Training Time = **0.36 s**
  - Inference Latency = **0.00025 ms/sample** (batch) / **0.63 ms/sample** (single-stream)

### 5.2 Multiclass Baselines ($N=30,000$ Test Set, 15 Attack Classes)
- **Random Forest:** Accuracy = 73.34%, Macro-F1 = 0.5838, Weighted-F1 = 0.8312.
- **XGBoost:** Accuracy = 65.27%, Macro-F1 = 0.5694, Weighted-F1 = 0.7724.
- **Decision Tree:** Accuracy = 61.10%, Macro-F1 = 0.5432, Weighted-F1 = 0.7389.
*Finding:* Weighted-F1 masks minority collapse; classes with support $\le 5$ (e.g. `Brute Force -Web`, `SQL Injection`) fail under standard sampling, proving the necessity of macro-evaluation.

### 5.3 Global SHAP Feature Importance (XGBoost)
1. `OUT_BYTES`: Mean |SHAP| = **0.7051**
2. `FLOW_DURATION_MILLISECONDS`: Mean |SHAP| = **0.6560**
3. `IN_BYTES`: Mean |SHAP| = **0.4589**
4. `IN_PKTS`: Mean |SHAP| = **0.4404**
5. `L7_PROTO`: Mean |SHAP| = **0.4372**
6. `TCP_FLAGS`: Mean |SHAP| = **0.3823**
7. `OUT_PKTS`: Mean |SHAP| = **0.1910**
8. `PROTOCOL`: Mean |SHAP| = **0.0325**
- **Spearman Rank Correlation between XGBoost and Random Forest:** **0.8095** ($p = 0.0149$), demonstrating strong structural attribution consistency between boosting and bagging ensembles.

### 5.4 Adversarial Robustness Under Domain Invariants
- **Evasion Rate at $\epsilon=0.05$:** XGBoost = 0.66%, Random Forest = 11.62%, Decision Tree = 10.34%.
- **Evasion Rate at $\epsilon=0.10$:** XGBoost = 4.45%, Random Forest = 13.90%, Decision Tree = 13.39%.
- **Evasion Rate at $\epsilon=0.20$:** XGBoost = **21.94%**, Random Forest = **28.46%**, Decision Tree = **21.40%**.
- **Evasion Rate at $\epsilon=0.50$:** XGBoost = **33.83%**, Random Forest = **40.50%**, Decision Tree = **34.43%**.
- **Query-Guided Greedy Search (QGGS) on XGBoost:** *(formerly referenced as SGGS in preliminary notes)*
  - Config A (3-iteration benchmark): Evasion = **6.00%** (6/100; average 15.9 total queries, maximum 16).
  - Config B (10-iteration extended search): Evasion = **60.00%** (60/100; average 27.6 total queries, maximum 46).

### 5.5 Explanation Stability Metrics ($\epsilon=0.20$, Paired $N=500$ Attacks)
- **Mean $L_1$ Attribution Drift:** 0.3484 (Median = 0.2833)
- **Normalized $L_2$ Drift:** 0.4452
- **Top-3 Feature Overlap:** 83.27%
- **Spearman Feature Rank Correlation:** 0.7364
- **Four-Quadrant Categorization ($\tau_{val} = 0.2739$):**
  - **Q1 (Prediction Stable, Explanation Stable):** 231 flows (46.2%)
  - **Q2 (Prediction Stable, Explanation Fragile):** 155 flows (31.0%)
  - **Q3 (Prediction Flipped, Explanation Shifted):** 112 flows (22.4%)
  - **Q4 (Prediction Flipped, Explanation Deceptive):** 2 flows (0.4%)
*Crucial Security Caveat:* Quadrant IV demonstrates that an attack can evade detection while its top SHAP feature ranking remains deceptively similar to a clean attack profile.

### 5.6 Port Feature Ablation Study & Shortcut Discovery
- Including `L4_SRC_PORT` and `L4_DST_PORT`:
  - Clean Accuracy increases from **98.16%** to **98.90%**.
  - Macro-F1 increases from **0.9238** to **0.9521**.
  - False Positive Rate decreases from **0.0097** to **0.0019**.
  - Feature Importance: `L4_DST_PORT` alone accounts for **24.30% of total split gain**.
  - **Tabular Destination-Port Feature-Shift Stress Test:** Produced 1,572 evasions among 1,670 initially detected attacks (**94.13% evasion rate**). Explicitly, no live network traffic redirection or packet-level attack was executed.
  - In contrast, the 8-feature baseline is invariant to direct changes in source and destination port fields when no other model input features are modified (0 / 1,664 missed).

---

## 6. Reproducibility Manifest
- **Dataset Hash (SHA-256):** `94a974b20bb611c0f4f9d21c97a5a8a113d9ea1ce2860d4da55bfa025687796f`
- **Environment:** Windows 11 / Python 3.12.10
- **Random Seed:** 42
- **Test Suite:** 14 / 14 tests passing (`tests/test_audit.py`, `tests/test_preprocessing.py`, `tests/test_models.py`, `tests/test_adversarial.py`, `tests/test_neural_baseline.py`, `tests/test_stability.py`).
