# Independent Reproducibility & Audit Guide

**Project Title:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll Number: TIA26)  
**Academic Target:** Third Year B.E. Information Technology Technical Seminar  
**Repository Target:** `https://github.com/Rohit-git-glitch/Seminar-`  
**Execution Environment:** Local CPython 3.12 (Windows / Linux / macOS compatible)  
**Date:** November 2026  

---

## 1. Quick-Start Master Verification (1-Step Audit)

To independently verify the entire implementation, dataset integrity, serialized model binaries, pytest unit test suite, and saved experimental artifacts in a single command, execute from the repository root:

```powershell
python scripts/verify_all.py
```

### Expected Console Output:
```text
======================================================================
  ROBUST & EXPLAINABLE NIDS: REPRODUCIBILITY VERIFICATION
======================================================================
Researcher: Aditya Ambare (Roll: TIA26)
Project Directory: C:\Users\adity\Downloads\seminar\Implementation

======================================================================
  1. RAW & PROCESSED DATA INTEGRITY
======================================================================
  [PASS] Raw Dataset Parquet: NF-CSE-CIC-IDS2018.parquet (222,094,360 bytes)
  [PASS] Cached X_train (140k): X_train.parquet (2,680,872 bytes)
  [PASS] Cached X_val (30k): X_val.parquet (613,995 bytes)
  [PASS] Cached X_test (30k): X_test.parquet (613,989 bytes)
  [PASS] Cached y_test (30k): y_test.parquet (111,739 bytes)

======================================================================
  2. AUTOMATED UNIT TEST SUITE (pytest)
======================================================================
  [PASS] All unit tests passed cleanly:
         tests/test_adversarial.py ...
         tests/test_audit.py ...
         tests/test_models.py ...
         tests/test_neural_baseline.py ...
         tests/test_preprocessing.py ...
         tests/test_stability.py ...
         13 passed in 10.41s

======================================================================
  3. SERIALIZED MODEL BINARIES
======================================================================
  [PASS] Decision Tree Binary: decision_tree_binary.joblib (178,145 bytes)
  [PASS] Random Forest Binary: random_forest_binary.joblib (14,463,770 bytes)
  [PASS] XGBoost Binary: xgboost_binary.joblib (1,493,767 bytes)
  [PASS] XGBoost 10-Features (Ports): xgboost_ports.joblib (1,515,640 bytes)
  [PASS] XGBoost Multiclass: xgboost_multiclass.joblib (1,677,390 bytes)

======================================================================
  FINAL VERIFICATION VERDICT
======================================================================
  >>> SUCCESS: 100% OF REPRODUCIBILITY CHECKS PASSED SUCCESSFULLY! <<<
  The research implementation is complete, verified, and seminar-ready.
```

---

## 2. Environment Setup & Dependency Installation

### 2.1 Python Environment
- Recommended Python version: **3.10, 3.11, or 3.12**.
- Create and activate a clean virtual environment:

```bash
# Using standard Python venv
python -m venv .venv

# On Windows PowerShell:
.venv\Scripts\Activate.ps1

# On Linux / macOS:
source .venv/bin/activate
```

### 2.2 Installing Dependencies
Install all required production dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

*Key package versions verified during research:*
- `numpy >= 2.0.0` (Verified with NumPy 2.2.6)
- `pyarrow >= 18.0.0`
- `pandas >= 2.2.0`
- `scikit-learn >= 1.5.0`
- `xgboost >= 2.1.0` (Includes compatibility patch for UBJSON bracket handling)
- `shap >= 0.46.0`
- `streamlit >= 1.35.0`
- `pytest >= 8.0.0`

---

## 3. Dataset Integrity & Local Placement

### 3.1 Dataset Location
The primary dataset is the standardized NetFlow v9 conversion of CSE-CIC-IDS2018:
- **Expected Relative Path:** `data/raw/NF-CSE-CIC-IDS2018.parquet`
- **Compressed Archive:** `data/raw/NF-CSE-CIC-IDS2018.parquet.zip`

### 3.2 Cryptographic Hash Verification
To ensure data provenance and confirm the file is identical to the audited dataset:

| Attribute | Audited Dataset Property |
| :--- | :--- |
| **Filename** | `NF-CSE-CIC-IDS2018.parquet` |
| **File Size** | 222,094,360 bytes (211.8 MB) |
| **SHA-256 Checksum** | `94a974b20bb611c0f4f9d21c97a5a8a113d9ea1ce2860d4da55bfa025687796f` |
| **Total Rows** | 5,918,803 flows |
| **Total Columns** | 12 features (10 flow/port attributes + Label + Attack) |
| **Class Distribution** | Benign: 5,534,773 (93.51%), Attack: 384,030 (6.49%) |

---

## 4. Full Pipeline Sequential Reproduction

For examiners or reviewers who wish to re-execute every experimental phase from scratch, execute the following numbered scripts in sequential order:

```bash
# Step 0: Ingest and audit raw dataset integrity (5.9M flows)
python scripts/00_audit_dataset.py

# Step 1: Execute zero-leakage splitting and train baseline models
python scripts/01_train_baselines.py

# Step 2: Compute TreeExplainer SHAP values and feature attribution plots
python scripts/02_explain_shap.py

# Step 3: Run DC-FFP adversarial evaluation and SGGS query benchmark
python scripts/03_adversarial_evaluation.py

# Step 4: Run paired 500-sample explanation stability and 4-quadrant analysis
python scripts/04_explanation_stability.py

# Step 5: Generate comparative trade-off charts and master comparison tables
python scripts/05_compare_experiments.py

# Step 6: Verify UNSW-NB15 cross-dataset semantic alignment protocol
python scripts/06_cross_dataset_validation.py

# Step 7: Execute port-shift stress test (8-feat control vs 10-feat model)
python scripts/audit_port_shift.py

# Step 8: Build final consolidated 40-row results CSV table
python scripts/build_final_tables.py
```

---

## 5. Running the Automated Pytest Suite

To independently verify code health, zero data leakage, and adversarial constraints:

```bash
pytest tests/ -v
```

### Verified Test Cases:
1. `tests/test_audit.py`: Validates schema types, binary label values (`0` and `1`), and attack mappings.
2. `tests/test_preprocessing.py`: Validates zero leakage (scalers fit only on train), stratified split ratios, and cached array alignment.
3. `tests/test_models.py`: Validates model fitting, predict probabilities, joblib serialization, and metric outputs.
4. `tests/test_adversarial.py`: Validates monotonic non-decreasing perturbation ($\Delta \ge 0$), packet integrality, and RFC 791 physical invariant bounds.
5. `tests/test_neural_baseline.py`: Validates PyTorch MLP baseline forward pass, loss computation, input gradients, and FGSM/PGD step logic.
6. `tests/test_stability.py`: Validates $L_1$ attribution drift calculation, normalized $L_2$ drift, Spearman rank correlation, and four-quadrant categorization logic.

---

## 6. Interactive Research Demonstration (Streamlit Dashboard)

An interactive, multi-tab Streamlit dashboard is provided for live committee demonstrations:

```bash
streamlit run dashboard/app.py
```

### Dashboard Tabs Available:
1. **Overview & Dataset Audit:** Inspect class distribution, 5.9M flow summary statistics, and protocol breakdowns.
2. **Model Performance & Comparison:** View clean confusion matrices, ROC curves, and performance tables for DT, RF, and XGBoost.
3. **SHAP Explainability:** Explore global summary beeswarm plots, mean feature importance, and interactive waterfall plots for individual flows.
4. **Adversarial Robustness:** Interactive slider to adjust perturbation budget $\epsilon \in [0.0, 0.50]$ and observe real-time evasion curves.
5. **Explanation Stability:** Explore the Four-Quadrant scatter plot, attribution drift histograms, and inspect individual Q1–Q4 samples.
6. **Feature Ablation & Port Shift:** Live comparison of the 8-feature baseline vs. 10-feature model under service port redirection.

---

## 7. Artifact Manifest & Directory Structure

```
Implementation/
├── data/
│   ├── raw/
│   │   └── NF-CSE-CIC-IDS2018.parquet    # Audited primary dataset
│   └── processed/
│       └── sample_200000_ports_False/     # Zero-leakage cached partitions
├── dashboard/
│   └── app.py                             # Interactive Streamlit application
├── outputs/
│   ├── audit/                             # Phase 9 audit reports & logs
│   ├── final/                             # Seminar-ready final deliverables
│   │   ├── final_methodology.md           # Formal academic methodology
│   │   ├── final_results_tables.csv       # Consolidated 40-row metrics table
│   │   ├── limitations_and_future_work.md # Comprehensive academic limitations
│   │   ├── seminar_defense_points.md      # Viva voce cheat sheet
│   │   └── reproducibility_summary.md     # This independent verification guide
│   ├── metrics/                           # CSV metric files & trade-off charts
│   ├── models/                            # Serialized joblib model binaries
│   ├── shap/                              # SHAP plots and attribution tables
│   ├── adversarial/                       # DC-FFP robustness curves & tables
│   └── stability/                         # 4-quadrant stability scatter plots
├── scripts/                               # Numbered reproducible pipeline scripts
├── src/                                   # Clean modular Python package
└── tests/                                 # Pytest automated test suite
```

*All results presented in Aditya Ambare's seminar dissertation are 100% locally reproducible from these files.*

