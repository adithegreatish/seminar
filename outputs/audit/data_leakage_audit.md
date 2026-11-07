# Data Splitting, Stratification & Leakage Audit

**Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Auditor:** Independent Research Auditor & Cybersecurity Methodology Reviewer  
**Audit Date:** November 2026  
**Audit Status:** PASSED (Zero Data Leakage Confirmed)  

---

## 1. Executive Summary
This audit rigorously evaluates the data ingestion, sampling, partitioning, and feature preprocessing pipeline implemented in `src/preprocessing/pipeline.py` against academic data leakage standards. 

---

## 2. Partition Verification & Proportions

The pipeline draws a reproducible stratified sample of $N=200,000$ records from the full 5,918,803-row dataset using global seed `RANDOM_SEED = 42`. The sample is partitioned into a three-way split:

| Partition | Design Ratio | Actual Count | Attack Count (Label=1) | Attack Proportion | Partition Overlap |
|---|---|---|---|---|---|
| **Training Set** | 70.0% | **140,000** | 9,084 | **6.4886%** | 0 records |
| **Validation Set** | 15.0% | **30,000** | 1,947 | **6.4900%** | 0 records |
| **Test Set** | 15.0% | **30,000** | 1,946 | **6.4867%** | 0 records |
| **Total** | 100.0% | **200,000** | 12,977 | **6.4885%** | 0 records |

### Verification Findings:
1. **Index Disjointness:** An exhaustive pairwise set intersection check confirmed:
   $$\text{Index}(\text{Train}) \cap \text{Index}(\text{Val}) = \emptyset$$
   $$\text{Index}(\text{Train}) \cap \text{Index}(\text{Test}) = \emptyset$$
   $$\text{Index}(\text{Val}) \cap \text{Index}(\text{Test}) = \emptyset$$
   No sample exists in more than one partition.
2. **Stratification Fidelity:** The natural class imbalance of the full dataset (6.4883% attack flows) is preserved across all three partitions to four decimal places ($\approx 6.49\%$).

---

## 3. Data Leakage Assessment: Preprocessing Pipeline

### 3.1 Defect in Reference GitHub Notebooks
In the reference repository (`Random_Forest.ipynb` and `XG_Boost.ipynb`), the following operation was executed prior to splitting:
```python
# DEFECTIVE ORIGINAL CODE (DATA LEAKAGE)
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(X.median()) # Global median computed across train + test!
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20)
```
Computing the median imputation statistics over the entire dataset leaks distribution parameters from the test set into the training feature space.

### 3.2 Audit of New Modular Implementation
In `src/preprocessing/pipeline.py`, the `NIDSPreprocessor` class enforces strict state separation:
1. `NIDSPreprocessor.fit()` is invoked **strictly on `X_train_raw`**:
   - `self.imputer.fit(X_clean)` calculates feature medians using only the 140,000 training instances.
   - If feature scaling is enabled (`StandardScaler`), $\mu_{train}$ and $\sigma_{train}$ are calculated strictly from training rows.
2. `NIDSPreprocessor.transform()` applies the frozen training parameters to `X_val_raw` and `X_test_raw` without updating any learned state.
3. Unit test `tests/test_preprocessing.py::test_nids_preprocessor_no_leakage` programmatically validates that missing values in the test set are imputed using training medians rather than test distributions.

---

## 4. Methodological Audit: Model Selection & Test Set Isolation

1. **Hyperparameter Selection Isolation:**
   - In `scripts/01_train_baselines.py`, Decision Tree, Random Forest, and XGBoost were evaluated against the 15% **Validation set** ($N=30,000$).
   - The primary selection criterion was **Validation Macro-F1** (XGBoost: 0.9171 vs Random Forest: 0.9056 vs Decision Tree: 0.8840).
   - The test set ($N=30,000$) remained untouched and was evaluated only once following model selection.
2. **Adversarial Testbed Isolation:**
   - All adversarial robustness evaluations (`scripts/03_adversarial_evaluation.py`) and explanation stability calculations (`scripts/04_explanation_stability.py`) were conducted strictly using malicious samples extracted from the **held-out test set** ($N=30,000$).
   - Zero training or validation samples were used in adversarial generation.

---

## 5. Critical Methodological Limitation: Random Row Splitting in NIDS

While the 70/15/15 random stratified split satisfies standard ML benchmarking guidelines, cybersecurity research methodology identifies inherent limitations when applying random row splitting to network flow data:

1. **Temporal & Campaign Correlation:**
   - In testbeds like CSE-CIC-IDS2018, attacks were executed in structured temporal campaigns (e.g., specific hours dedicated to DoS LOIC, SSH brute force, or infiltration).
   - Random uniform row splitting samples flows from throughout the entire capture duration. Consequently, flows belonging to the same attack session or campaign may appear in both the training and test sets.
2. **IP Address & Topology Memorization:**
   - When models are trained on flows containing static IP/port relationships, trees can memorize attack topology (e.g., target server IP or port) rather than generalizable malicious flow behaviors.
3. **Recommendation for Future In-Depth Research:**
   - For post-seminar research extensions, temporal block splitting (e.g., training on Day 1-3, testing on Day 4-5) or cross-network evaluation (evaluating across different network subnets) should be explored to test temporal out-of-distribution generalization.

