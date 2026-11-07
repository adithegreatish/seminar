# Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations

**Academic Level:** Third Year B.E. Information Technology Technical Seminar  
**Researcher:** Aditya Ambare  
**Roll Number:** TIA26  
**Institution:** University Technical Seminar Project  
**Repository Branch:** `main`  

---

## 1. Executive Summary & Research Ideology

Modern Machine Learning-based Network Intrusion Detection Systems (NIDS) routinely report clean test accuracies exceeding 98%. However, in real-world deployment, network flow classifiers operate in an adversarial environment where malicious actors actively modify flow characteristics to evade detection. Furthermore, modern regulatory standards require NIDS systems to be explainable (via Explainable AI / XAI frameworks like SHAP).

This research project formalizes and investigates the critical intersection of:
$$\textbf{Detection Performance} + \textbf{Machine Learning} + \textbf{Explainable AI (SHAP)} + \textbf{Adversarial Robustness} + \textbf{Explanation Stability}$$

The central thesis of this work is that **high classification accuracy on clean benchmark data is an insufficient criterion for dependable security**. We evaluate whether model predictions and their corresponding feature attributions remain reliable and stable when subjected to **domain-constrained adversarial perturbations** that strictly obey physical network protocol invariants.

---

## 2. Research Distinctions & Experimental Attribution

To maintain strict scientific integrity, all findings are segregated into three distinct categories:

1. **Existing Reference Baseline (Reported in GitHub Notebooks):**
   - Unverified notebook exploratory metrics: XGBoost Binary Acc ~98.18%, Macro-F1 ~0.9248; Random Forest Multiclass Acc ~85.97%, Macro-F1 ~0.6270; XGBoost Multiclass Acc ~60.0%.
   - Documented defects in original notebooks: preprocessing data leakage (`fillna` before split), absence of validation set, extreme class imbalance distortion in multiclass weighting, and arbitrary exclusion of transport ports without ablation.
2. **Newly Generated & Independently Verified Results (This Implementation):**
   - **Full Dataset Audit (5,918,803 flows):** Zero duplicate rows, verified 0=Benign (93.51%), 1=Attack (6.49%), identified 4 extreme rare classes with <250 samples (`SQL Injection`, `Brute Force -XSS`, `Brute Force -Web`, `DDOS attack-HOIC`).
   - **Leakage-Free Baselines (200,000 stratified sample, 70/15/15 train/val/test):**
     - Decision Tree: Val Macro-F1 = 0.8840, Test Acc = 97.13%, Test Macro-F1 = 0.8901, FPR = 0.0209, Test ROC-AUC = **0.9506**.
     - Random Forest: Val Macro-F1 = 0.9056, Test Acc = 97.79%, Test Macro-F1 = 0.9113, FPR = 0.0137, Test ROC-AUC = **0.9574**.
     - XGBoost: Val Macro-F1 = 0.9171, Test Acc = **98.16%**, Test Macro-F1 = **0.9238**, FPR = **0.0097**, Test ROC-AUC = **0.9621**. Selected as top binary model.
   - **SHAP Feature Attributions:** Top 3 global drivers: `OUT_BYTES` (0.7051), `FLOW_DURATION_MILLISECONDS` (0.6560), and `IN_BYTES` (0.4589). Cross-model rank correlation between XGBoost and Random Forest is **0.8095** ($p = 0.0149$).
   - **Domain-Constrained Adversarial Evasion (DC-FFP & QGGS):**
     - Under DC-FFP at budget $\epsilon=0.20$, evasion rate reaches **21.94%** for XGBoost (365/1664), **28.46%** for Random Forest (475/1669), and **21.40%** for Decision Tree (358/1673). At $\epsilon=0.50$, recall drops to **51.18% - 58.07%**.
     - Zero-epsilon identity formally validated: `assert np.array_equal(original, perturbed_at_epsilon_zero)` on all 30,000 test flows.
     - Query-Guided Greedy Search (QGGS / SGGS):
       - Config A (Audited 3-iteration benchmark): **6.00% evasion** (6/100; 15.9 average total queries, maximum 16).
       - Config B (Extended 10-iteration search): **60.00% evasion** (60/100; 27.6 average total queries, maximum 46).
   - **Explanation Stability Analysis:** Mean $L_1$ drift is 0.3484; Top-3 feature overlap is 83.27%; Spearman rank correlation is 0.7364. Four-quadrant analysis: Q1 (Stable Detection & Stable Explanation): 46.2% (231); Q2 (Stable Detection, Fragile Explanation): 31.0% (155); Q3 (Flipped Detection, Shifted Explanation): 22.4% (112); Q4 (Flipped Detection, Deceptive Stability): 0.4% (2).
   - **Port Feature Ablation & Shortcut Discovery:** Adding `L4_SRC_PORT` and `L4_DST_PORT` boosts clean accuracy from 98.16% to 98.90%, but introduces a severe port shortcut (24.3% split gain on `L4_DST_PORT`). A tabular destination-port feature-shift stress test produced 1,572 evasions among 1,670 initially detected attacks (**94.13% evasion rate**). Explicitly, no live traffic redirection or packet-level network attack was performed; the 8-feature baseline is invariant to direct port-field manipulation (0/1664 missed).
3. **Proposed Work / Future Extensions:**
   - Transferability evaluation to live UNSW-NB15 hardware captures.
   - Adversarial training incorporating domain-constrained flow bounds.

---

## 3. Dataset Architecture & Threat Model

### 3.1 Primary Dataset: NF-CSE-CIC-IDS2018
- **Source:** NetFlow v9 conversion of CSE-CIC-IDS2018 (University of New Brunswick).
- **Format:** Parquet file (`data/raw/NF-CSE-CIC-IDS2018.parquet`).
- **Dimensions:** 5,918,803 rows $\times$ 12 columns.
- **Attributes:**
  - `L4_SRC_PORT`, `L4_DST_PORT` (Transport layer ports, 0 to 65535)
  - `PROTOCOL` (IP protocol integer: 6=TCP, 17=UDP, 1=ICMP)
  - `L7_PROTO` (Application layer protocol identifier)
  - `IN_BYTES`, `OUT_BYTES` (Transferred byte volume)
  - `IN_PKTS`, `OUT_PKTS` (Transferred packet volume)
  - `TCP_FLAGS` (Bitmask of TCP control flags)
  - `FLOW_DURATION_MILLISECONDS` (Flow duration in milliseconds)
  - `Label` (Binary ground truth: 0=Benign, 1=Attack)
  - `Attack` (15 multiclass categories)

### 3.2 Domain-Constrained Adversarial Threat Model
Unlike images where arbitrary continuous pixel perturbations $\epsilon$ are permissible, network flow records must satisfy strict physical invariants:
1. **Monotonicity (Non-decreasing perturbations):** An attacker can inject dummy packets or padding bytes, or delay transmission ($\Delta \text{BYTES} \ge 0, \Delta \text{PKTS} \ge 0, \Delta \text{DURATION} \ge 0$). Packets cannot be un-sent.
2. **Packet Integrality:** Packet counts must remain non-negative integers ($\ge 1$).
3. **Minimum Packet Size Invariant:** In standard IPv4 networks, header overhead dictates that $\text{BYTES} \ge \text{PKTS} \times 20$.
4. **Protocol & Flag Immutability:** `PROTOCOL` and `TCP_FLAGS` cannot take arbitrary floating-point numbers without corrupting the transport layer state machine.

---

## 4. Project Software Architecture

```
Implementation/
│
├── data/
│   ├── raw/                  # Raw Parquet & ZIP archives (git-ignored)
│   └── processed/            # Leakage-free train/val/test cached partitions
│
├── src/
│   ├── data/                 # Dataset loader and full audit modules
│   ├── preprocessing/        # Leakage-free split & transformation pipeline
│   ├── models/               # Decision Tree, Random Forest, XGBoost wrappers
│   ├── explainability/       # SHAP TreeExplainer & visualization wrappers
│   ├── adversarial/          # Threat models, domain invariants & evasion attacks
│   ├── evaluation/           # Metrics, confusion matrices & stability calculators
│   └── utils/                # Configuration, logging & path management
│
├── scripts/
│   ├── 00_audit_dataset.py           # Phase 1: Full dataset audit (5.9M rows)
│   ├── 01_train_baselines.py         # Phase 3: Binary & multiclass baselines
│   ├── 02_explain_shap.py            # Phase 4: SHAP global & local explainability
│   ├── 03_adversarial_evaluation.py  # Phase 5: Adversarial robustness curves
│   ├── 04_explanation_stability.py   # Phase 6: Attribution drift & 4-quadrant analysis
│   ├── 05_compare_experiments.py     # Phase 7: Master comparison & port ablation
│   └── 06_cross_dataset_validation.py# Phase 8: UNSW-NB15 alignment protocol
│
├── dashboard/
│   └── app.py                # Phase 9: Interactive Streamlit research dashboard
│
├── outputs/
│   ├── audit/                # Audit markdown, JSON, and class distribution plots
│   ├── models/               # Serialized joblib model artifacts
│   ├── metrics/              # Reports, confusion matrices, ablation tables
│   ├── shap/                 # Beeswarm, bar, and local waterfall plots
│   ├── adversarial/          # Robustness curves & evasion configs
│   ├── stability/            # Stability distributions & quadrant plots
│   └── cross_dataset/        # UNSW-NB15 alignment protocol
│
├── tests/                    # 11 automated pytest test suites (100% pass)
├── requirements.txt          # Pinned Python dependencies
├── pytest.ini                # Pytest configuration
├── README.md                 # Complete seminar documentation
├── IMPLEMENTATION_NOTES.md   # Detailed engineering log & findings
└── .gitignore                # Excludes datasets, models, and virtual environments
```

---

## 5. Local Setup and Execution Guide

### 5.1 Prerequisites
- **Operating System:** Windows 10/11 (or Linux/macOS)
- **Python Version:** Python 3.12 (CPython 3.12.10 recommended)
- **Package Manager:** `uv` (recommended for instant installs) or standard `pip`

### 5.2 Windows PowerShell Setup Instructions

1. **Clone the Repository & Navigate to Workspace:**
   ```powershell
   git clone https://github.com/Rohit-git-glitch/Seminar-.git Implementation
   cd Implementation
   ```

2. **Create and Activate Python 3.12 Virtual Environment:**
   ```powershell
   # Using uv (fastest)
   uv venv .venv --python 3.12
   .venv\Scripts\activate
   
   # Or using standard python
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Install Dependencies:**
   ```powershell
   uv pip install -r requirements.txt --python .venv\Scripts\python.exe
   # Or: pip install -r requirements.txt
   ```

4. **Verify Dataset Placement:**
   Ensure `NF-CSE-CIC-IDS2018.parquet.zip` or `NF-CSE-CIC-IDS2018.parquet` is present in `data/raw/`:
   ```powershell
   Test-Path data\raw\NF-CSE-CIC-IDS2018.parquet
   ```

---

## 6. Pipeline Execution Commands

Execute each research phase sequentially using PowerShell:

```powershell
# Phase 1: Dataset Audit (Inspects all 5,918,803 records)
.venv\Scripts\python.exe scripts/00_audit_dataset.py

# Phase 3: Train Machine Learning Baselines (DT, RF, XGBoost)
.venv\Scripts\python.exe scripts/01_train_baselines.py

# Phase 4: Compute SHAP Explainability (Beeswarm, bar, and local waterfall)
.venv\Scripts\python.exe scripts/02_explain_shap.py

# Phase 5: Adversarial Robustness Testing (Domain-constrained flow attacks)
.venv\Scripts\python.exe scripts/03_adversarial_evaluation.py

# Phase 6: Explanation Stability & Attribution Drift Analysis
.venv\Scripts\python.exe scripts/04_explanation_stability.py

# Phase 7: Comparative Synthesis & Port Ablation Study
.venv\Scripts\python.exe scripts/05_compare_experiments.py

# Phase 8: Cross-Dataset Alignment Protocol (UNSW-NB15)
.venv\Scripts\python.exe scripts/06_cross_dataset_validation.py

# Run Automated Test Suite (11 unit tests)
.venv\Scripts\pytest.exe tests/

# Launch Interactive Research Dashboard
.venv\Scripts\streamlit.exe run dashboard/app.py
```

---

## 7. Master Experimental Results

### 7.1 Clean vs Adversarial Baseline Comparison (8 Features, Test Set $N=30,000$)

| Model | Clean Acc | Clean Macro-F1 | Clean Recall | Clean FPR | ROC-AUC | Evasion Rate ($\epsilon=0.20$) | Train Time | Inference Latency |
|---|---|---|---|---|---|---|---|---|
| **Decision Tree** | 97.13% | 0.8901 | 0.8597 | 0.0209 | 0.9506 | 21.40% | 0.24 s | 0.0001 ms |
| **Random Forest** | 97.79% | 0.9113 | 0.8577 | 0.0137 | 0.9574 | 28.46% | 1.39 s | 0.0015 ms |
| **XGBoost (Top)** | **98.16%** | **0.9238** | **0.8551** | **0.0097** | **0.9621** | **21.94%** | 0.36 s | 0.0002 ms |

### 7.2 Port Feature Ablation Study

| Configuration | Features | Clean Acc | Macro-F1 | Attack Recall | FPR | Evasion Rate ($\epsilon=0.20$) |
|---|---|---|---|---|---|---|
| **Random Forest (Baseline)** | 8 features | 97.79% | 0.9113 | 0.8577 | 0.0137 | 28.46% |
| **Random Forest (+Ports)** | 10 features | 98.89% | 0.9519 | 0.8597 | 0.0021 | 1.85% |
| **XGBoost (Baseline)** | 8 features | 98.16% | 0.9238 | 0.8551 | 0.0097 | 21.94% |
| **XGBoost (+Ports)** | 10 features | **98.90%** | **0.9521** | **0.8582** | **0.0019** | 3.29% |

### 7.3 Explanation Stability Under Adversarial Perturbation ($\epsilon=0.20$)

| Stability Metric | Mean | Median | Std Dev | Interpretation |
|---|---|---|---|---|
| **$L_1$ Attribution Drift** | 0.3484 | 0.2833 | 0.2442 | Mean log-odds shift across flow attributes |
| **Normalized $L_2$ Drift** | 0.5456 | 0.5597 | 0.3642 | Relative attribution drift |
| **Top-3 Feature Overlap** | 83.27% | 100.00% | 17.72% | Fraction of top 3 features retained |
| **Spearman Rank Correlation ($\rho_s$)** | 0.7364 | 0.8810 | 0.2427 | High consistency in feature ranking order |

**Four-Quadrant Behavioral Breakdown ($N=500$ paired attack flows):**
- **Quadrant I (Stable Detection & Stable Explanation):** 248 flows (49.6%)
- **Quadrant II (Stable Detection & Fragile Explanation):** 138 flows (27.6%)
- **Quadrant III (Evasion Succeeded & Explanation Shifted):** 112 flows (22.4%)
- **Quadrant IV (Evasion Succeeded & Deceptive Stability):** 2 flows (0.4%)

---

## 8. Known Limitations & Seminar Defense Preparation

1. **Network Flow Aggregation vs Packet-Level Inspection:** NetFlow/IPFIX captures flow-level summaries rather than packet payloads. Adversarial padding shifts flow summary metrics, but deep packet inspection (DPI) could inspect payload signatures if encryption is not used.
2. **Offline Public Benchmarks:** CSE-CIC-IDS2018 contains known synthetic traffic artifacts. Future work should evaluate live streaming captures using hardware taps.
3. **SHAP Stability Limitation:** While SHAP stability helps identify explainability drift, **explanation stability does not guarantee security correctness** (as shown by Quadrant IV deception). Robust defense requires joint verification across decision boundaries and attribution spaces.

---

## 9. Contact & Academic Attribution
- **Researcher:** Aditya Ambare (Roll: TIA26)  
- **Seminar Topic:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
- **Date Completed:** November 2026

