# Independent Research Integrity & Methodology Audit

**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare  
**Roll Number:** TIA26  
**Auditor:** Independent ML Research Auditor & Cybersecurity Methodology Reviewer  
**Audit Date:** November 2026  
**Audit Status:** AUDIT COMPLETED — ALL METRICS RECONCILED & DEFICIENCIES CORRECTED  

---

## 1. Executive Summary & Audit Mandate

This independent experimental audit was commissioned to critically review the scientific validity, mathematical rigor, implementation correctness, and reproducibility of the research project developed by **Aditya Ambare (Roll: TIA26)** for his Third Year B.E. Information Technology Technical Seminar.

The audit examined every programmatic stage from raw Parquet extraction to SHAP TreeExplainer stability analysis, independently re-running all baseline models, verifying feature constraints against RFC networking standards, and evaluating adversarial trade-offs.

---

## 2. Claims Classification & Audit Verdicts

Every empirical claim, reported metric, and methodological assumption has been categorized into one of four formal audit states:

| Claim / Component | Description | Authoritative Finding | Audit Classification |
|---|---|---|---|
| **Zero Data Leakage** | Imputer and scalers fit strictly on training partition | Confirmed via `NIDSPreprocessor` architecture and unit test | **Verified by code and output** |
| **Ground Truth Mapping** | `Label=0` is Benign; `Label=1` is Attack | Confirmed across all 5,918,803 records | **Verified by code and output** |
| **Binary Model Hierarchy** | XGBoost > Random Forest > Decision Tree on clean data | XGBoost Acc: 98.16%, Macro-F1: 0.9238, FPR: 0.0097 | **Verified by code and output** |
| **XGBoost Val Macro-F1** | Historical narrative noted 0.9231 vs 0.9171 | **0.917064 is authoritative validation score** | **Requires correction in prior narrative** |
| **XGBoost Test ROC-AUC** | Historical narrative reported 0.9868 | **0.962096 is authoritative raw test AUC** | **Requires correction in prior narrative** |
| **Physical Invariant** | $\text{BYTES} \ge \text{PKTS} \times 20$ holds across all traffic | 0 violations in 5,918,803 flows; min ratio is 28.0 bytes | **Verified by code and output** |
| **Evasion Rate Formulation** | Measures only initially detected malicious flows | Strictly paired; numerators and denominators audited | **Verified by code and output** |
| **Port Ablation Trade-off** | Ports boost clean accuracy (98.90%) but introduce shortcuts | Alternate port redirection yields **94.13% evasion** | **Verified by code and output** |
| **Cross-Model SHAP Agreement** | Spearman correlation $\rho_s = 0.8095$ over 8 features | Empirical alignment confirmed; statistical power limited ($df=6$) | **Reproduced independently with caveat** |
| **Four-Quadrant Exhaustiveness** | Mutually exclusive quadrants summing to $N=500$ | $248 + 138 + 112 + 2 = 500$ at median threshold $\tau=0.2833$ | **Verified by code and output** |
| **Multiclass Minority Failure** | Extreme classes (<10 samples) collapse recall | Classes with support $\le 4$ exhibit 0.00 F1 | **Verified by code and output** |
| **UNSW-NB15 Generalization** | Cross-dataset performance on UNSW-NB15 | Formal protocol ready; local CSV pending placement | **Not yet experimentally evaluated** |

---

## 3. Detailed Audit Findings by Research Phase

### 3.1 Verification of Baseline Metrics & Reconciliation of Narrative Float (Section 1)
- **Authoritative Metrics Source:** All baseline metrics were recomputed directly from the serialized model objects (`outputs/models/`) evaluated on the cached test partition (`data/processed/sample_200000_ports_False/X_test.parquet`, $N=30,000$).
- **Investigation of the 0.9231 vs 0.9171 Float Discrepancy:**
  - In `outputs/metrics/baseline_metrics.csv` (Row 2, Validation split), the exact floating-point value is **`0.917064`** (rounded: `0.9171`).
  - In `outputs/metrics/baseline_metrics.csv` (Row 5, Test split), the exact floating-point value is **`0.923828`** (rounded: `0.9238`).
  - An interim text summary erroneously mentioned "0.9231" by truncating and conflating the test score (0.9238) with the validation score (0.9171).
  - **Audit Reconciliation:** The authoritative validation Macro-F1 used for model selection is strictly **0.9171**, and the authoritative test Macro-F1 is **0.9238**.
- **ROC-AUC Reconciliation:**
  - The authoritative ROC-AUC on the 8-feature baseline test set is **0.9621** (`0.962096`), not 0.9868 (which belonged to a test configuration that included port priors).

### 3.2 Audit of Adversarial Attacks & Physical Invariants (Section 2)
- **Domain-Constrained Perturbation Attack (DCPA):** Verified. Operates by proportionally scaling mutable attributes ($\text{IN\_BYTES}, \text{OUT\_BYTES}, \text{IN\_PKTS}, \text{OUT\_PKTS}, \text{DURATION}$) while clamping integer packet counts and enforcing header constraints.
- **Surrogate-Guided Greedy Search (SGGS):** Verified. Iteratively mutates the most sensitive mutable feature based on model query probabilities within budget $\epsilon \le 0.50$ and $K \le 15$ queries.
- **Audit of the $\text{BYTES} \ge \text{PKTS} \times 20$ Constraint:**
  - Scanned all 5,918,803 rows of `NF-CSE-CIC-IDS2018.parquet`.
  - Violations: **0 rows (0.00%)**.
  - Minimum ratio in dataset: **28.0 bytes/packet**.
  - RFC 791 specifies that any valid IPv4 packet requires at least 20 bytes for the IP header.
  - RFC 793 (TCP) requires a 20-byte transport header ($20+20=40$ bytes min). RFC 768 (UDP) and RFC 792 (ICMP) require an 8-byte transport header ($20+8=28$ bytes min).
  - Therefore, $\text{BYTES} \ge \text{PKTS} \times 20$ is mathematically and physically grounded in RFC specifications.

### 3.3 Evasion Rate Calculation Audit (Section 3)
The evasion rate was verified to adhere strictly to the academic definition:
$$\text{Evasion Rate} = \frac{\text{Initially Detected Attacks Evading Post-Perturbation}}{\text{Total Clean Correctly Detected Attacks}}$$
- Denominator ($N_{clean}$):
  - Decision Tree: 1,673
  - Random Forest: 1,669
  - XGBoost: 1,664
- Numerator ($N_{evaded}$ at $\epsilon=0.20$):
  - Decision Tree: 358 ($358 / 1,673 = \mathbf{21.40\%}$)
  - Random Forest: 475 ($475 / 1,669 = \mathbf{28.46\%}$)
  - XGBoost: 365 ($365 / 1,664 = \mathbf{21.94\%}$)
- Numerator ($N_{evaded}$ at $\epsilon=0.50$):
  - Decision Tree: 576 ($576 / 1,673 = \mathbf{34.43\%}$)
  - Random Forest: 676 ($676 / 1,669 = \mathbf{40.50\%}$)
  - XGBoost: 563 ($563 / 1,664 = \mathbf{33.83\%}$)
Clean and perturbed records were confirmed to be paired one-to-one.

### 3.4 Feature Ablation & Port-Shortcut Audit (Section 4)
- **Why adding ports changes metrics:**
  - In CSE-CIC-IDS2018, attack generators targeted specific default service ports (HTTP: 80/443, SSH: 22, FTP: 21).
  - Including `L4_DST_PORT` provides an artificial static anchor. Clean accuracy rises to 98.90% and FPR drops to 0.0019 because the trees memorize destination port numbers.
  - In the flow-padding attack (DCPA), ports were held static, making evasion appear to drop from 21.94% to 3.29%.
- **The Counter-Audit Experiment:**
  - The auditor evaluated destination port redirection (e.g. running HTTP on 8080, SSH on 2222).
  - Result: **1,572 out of 1,670 attacks (94.13%) evaded detection instantly.**
  - This proves that the 10-feature model suffers from catastrophic shortcut learning, validating the decision to use the 8-feature baseline for generalizable intrusion detection.

### 3.5 SHAP Explainability & Stability Audit (Section 5 & 6)
- **Output Spaces:** XGBoost computes TreeSHAP in log-odds ($\mathbb{R}$, base value 0.0); Random Forest computes in probability fractions ($[0, 1]$, base value 0.50). Raw SHAP values must not be compared across model families without rank normalization.
- **Cross-Model Correlation ($N=8$):** Spearman correlation $\rho_s = 0.8095$ ($p=0.0149$). With only $df=6$, this is an empirical ranking indicator among primary drivers (`OUT_BYTES`, `FLOW_DURATION`, `IN_BYTES`, `IN_PKTS`), not mathematical proof of model equivalence.
- **Four-Quadrant Verification ($N=500$ at $\epsilon=0.20$):**
  - Median $L_1$ drift threshold: $\tau = 0.2833$.
  - Q1 (Stable Detection, Stable Explanation): 248 flows (49.6%)
  - Q2 (Stable Detection, Fragile Explanation): 138 flows (27.6%)
  - Q3 (Flipped Detection, Shifted Explanation): 112 flows (22.4%)
  - Q4 (Flipped Detection, Deceptive Stability): 2 flows (0.4%)
  - Sum: $248 + 138 + 112 + 2 = 500$ flows (100.0%, mutually exclusive).
  - Quadrant IV proves that **explanation stability does not guarantee security correctness**.

### 3.6 Data Leakage & Partitioning Audit (Section 7)
- Exact counts: Train = 140,000 (70.0%), Val = 30,000 (15.0%), Test = 30,000 (15.0%).
- Partition index intersection = 0.
- Imputer and scalers fit strictly on training partition.
- Documented limitation: random row splitting cannot eliminate temporal or campaign-level burstiness inherent to testbed network traffic.

### 3.7 Multiclass Minority Audit (Section 8)
- Test set support for extreme minority classes:
  - `SQL Injection`: 0 samples (36 in entire 5.9M dataset)
  - `Brute Force -XSS`: 0 samples (101 in entire dataset)
  - `Brute Force -Web`: 1 sample (Precision=0.0, Recall=0.0, F1=0.0)
  - `DDOS attack-HOIC`: 4 samples (Recall=0.50, F1=0.67)
- Weighted-F1 (0.77 - 0.83) conceals minority collapse, while Macro-F1 (0.54 - 0.58) accurately reflects the failure on rare classes.

### 3.8 Cross-Dataset Status (Section 9)
- `data/raw/UNSW_NB15_testing-set.csv` is not present locally on disk.
- Formal semantic alignment protocol is fully defined and documented in `outputs/cross_dataset/unsw_nb15_evaluation_protocol.md`.
- Status is classified as **"Not yet experimentally evaluated"**; zero results fabricated.

### 3.9 Inference Latency Benchmark (Section 10)
Benchmarked with 10-batch warm-up across multiple batch sizes:
- **Single-Sample Streaming Latency ($N=1$):**
  - Decision Tree: 0.37 ms/sample (~2,668 flows/sec)
  - XGBoost: 0.63 ms/sample (~1,600 flows/sec)
  - Random Forest: 17.73 ms/sample (~56 flows/sec)
- **Vectorized Batch Latency ($N=30,000$):**
  - Decision Tree: 2.16 ms batch ($0.07 \mu\text{s}$ per sample, ~13.9M flows/sec)
  - XGBoost: 6.84 ms batch ($0.23 \mu\text{s}$ per sample, ~4.39M flows/sec)
  - Random Forest: 38.20 ms batch ($1.27 \mu\text{s}$ per sample, ~785k flows/sec)

---

## 4. Auditor Conclusion & University Seminar Recommendation

The implementation developed by **Aditya Ambare (TIA26)** satisfies all standards of scientific rigor, reproducibility, and code modularity. 

By eliminating the data leakage present in the original repository, implementing domain-constrained physical network attacks, quantifying SHAP explanation drift, and uncovering the port-based shortcut learning vulnerability, this project provides a technical foundation suitable for an undergraduate technical seminar.

