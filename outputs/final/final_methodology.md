# Final Research Methodology Specification

**Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Academic Program:** Third Year B.E. Information Technology Technical Seminar  
**Date:** November 2026  
**Document Status:** Formal Academic Research Specification  

---

## 1. Research Pipeline Architecture

The research framework follows an end-to-end modular pipeline designed to eliminate data leakage, enforce network flow domain invariants, compute exact game-theoretic attributions, and stress-test decision stability:

```
[NF-CSE-CIC-IDS2018 Dataset (5.9M Flows)]
                   │
                   ▼
       [Phase 1: Dataset Audit]
                   │ (Verify schema, 0=Benign, 1=Attack, 0 duplicates)
                   ▼
     [Phase 2: Stratified Partitioning]
       ├── Train Partition: 140,000 (70.0%) ──► Fit Preprocessors (Imputer, Scaler)
       ├── Validation Partition: 30,000 (15.0%) ──► Transform (Model Selection)
       └── Test Partition: 30,000 (15.0%) ──► Transform (Held-out Evaluation)
                   │
                   ▼
     [Phase 3: Baseline Classifier Training]
       ├── Decision Tree (Interpretable Benchmark)
       ├── Random Forest (Bagging Ensemble)
       └── XGBoost (Histogram Gradient Boosting - Top Model)
                   │
                   ▼
     [Phase 4: SHAP Explainability (TreeExplainer)]
       ├── Log-Odds Attributions (XGBoost) vs. Probability Attributions (RF)
       └── Cross-Model Attribution Ranking Comparison
                   │
                   ▼
     [Phase 5: Domain-Constrained Flow-Feature Perturbation (DC-FFP)]
       ├── Physical Network Invariants Enforced (RFC 791 / RFC 793)
       └── Evasion Rate Evaluation over Clean Detected Attacks
                   │
                   ▼
     [Phase 6: Explanation Stability & Attribution Drift]
       ├── Continuous Drift Metrics (L1, Norm-L2, Top-k, Spearman)
       └── Four-Quadrant Analysis (Validation-Calibrated Threshold)
                   │
                   ▼
     [Phase 7: Feature Ablation & Port-Shift Stress Testing]
       └── 8 Baseline Features (Control) vs. 10 Features (Port Shortcut Finding)
```

---

## 2. Dataset Preprocessing & Zero-Leakage Splitting

### 2.1 Dataset Ingestion
- **Dataset:** NF-CSE-CIC-IDS2018 (NetFlow v9 conversion of CSE-CIC-IDS2018).
- **Total Records:** 5,918,803 flows; 12 attributes.
- **Sampling:** A stratified sample of $N=200,000$ flows is drawn using global seed `RANDOM_SEED = 42`.
- **Target Definitions:**
  - Binary: `Label` ($0 = \text{Benign}$, $1 = \text{Attack}$).
  - Multiclass: `Attack` (15 categories).

### 2.2 Leakage-Free Preprocessing State Enforcement
- Learned transformers (`SimpleImputer(strategy='median')`) are fit strictly on the 140,000 training records.
- Validation ($N=30,000$) and Test ($N=30,000$) partitions are transformed using the frozen parameters learned on the training partition.
- Pairwise set intersection verifies zero record or index overlap across partitions:
  $$\text{Index}(\text{Train}) \cap \text{Index}(\text{Val}) = \emptyset, \quad \text{Index}(\text{Train}) \cap \text{Index}(\text{Test}) = \emptyset, \quad \text{Index}(\text{Val}) \cap \text{Index}(\text{Test}) = \emptyset$$

---

## 3. Machine Learning Baselines & Model Selection

Three tree-based model architectures were implemented with identical seed (`RANDOM_SEED = 42`):
1. **Decision Tree:** `DecisionTreeClassifier(max_depth=12, min_samples_split=20, min_samples_leaf=10, class_weight='balanced')`.
2. **Random Forest:** `RandomForestClassifier(n_estimators=100, max_depth=16, min_samples_split=10, min_samples_leaf=5, class_weight='balanced', n_jobs=-1)`.
3. **XGBoost:** `XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8, objective='binary:logistic', eval_metric='logloss', tree_method='hist', n_jobs=-1)`.

**Model Selection Protocol:**
Hyperparameter selection was conducted strictly against the **Validation set** ($N=30,000$) using **Macro-F1**:
$$\text{Macro-F1} = \frac{\text{F1}_{\text{Benign}} + \text{F1}_{\text{Attack}}}{2}$$
XGBoost achieved the highest validation Macro-F1 (**0.9171**) compared to Random Forest (**0.9056**) and Decision Tree (**0.8840**), and was selected as the primary binary classifier. The held-out test partition was evaluated once post-selection.

---

## 4. Domain-Constrained Flow-Feature Perturbation (DC-FFP)

### 4.1 Methodology Definition & Telemetry Scope
DC-FFP operates on aggregated NetFlow flow-record vectors $x \in \mathcal{X}$. It models the observational impact of physical network traffic manipulation (such as dummy payload padding, packet splitting, and transmission pacing) on flow telemetry collectors.

> [!NOTE]
> **Important Academic Distinction:** DC-FFP modifies flow-feature summary metrics in feature space; it does not generate raw pcap byte frames on a physical network interface.

### 4.2 Mathematical Transformation Equations
For each mutable flow feature $j \in \mathcal{M}$:
$$x'_j = x_j \cdot (1 + \epsilon) + \Delta_{min, j}$$

where:
- $\epsilon \in \{0.00, 0.05, 0.10, 0.20, 0.30, 0.50\}$ is the fractional perturbation budget.
- $\Delta_{min, j}$ is a **feature-specific minimum increment**:
  - For discrete integer packet counts (`IN_PKTS`, `OUT_PKTS`): $\Delta_{min, j} = 1.0$ (strictly when $\epsilon > 0$) to guarantee at least one discrete packet addition.
  - For continuous byte counters and flow duration (`IN_BYTES`, `OUT_BYTES`, `FLOW_DURATION_MILLISECONDS`), and for all features when $\epsilon = 0.0$: $\Delta_{min, j} = 0.0$.
  - **Zero-Epsilon Identity:** At $\epsilon = 0.00$, $x'_j = x_j(1 + 0) + 0 = x_j$. Formally verified via `assert np.array_equal(original, perturbed_at_epsilon_zero)` on all 30,000 test flows.

### 4.3 Domain Constraints & Invariant Enforcement
Following perturbation, the record is projected into the valid domain $\mathcal{C}$ via `enforce_domain_constraints()`:
1. **Monotonicity (Non-decreasing perturbation):** An adversary can pad or delay flows, but cannot delete transmitted packets:
   $$x'_j \ge x_j \quad \forall j \in \mathcal{M}$$
2. **Non-negativity:** All flow metrics must remain non-negative:
   $$x'_j \ge 0 \quad \forall j$$
3. **Packet Integrality:**
   $$x'_{\text{IN\_PKTS}} = \max(1, \lfloor x'_{\text{IN\_PKTS}} \rceil), \quad x'_{\text{OUT\_PKTS}} = \max(0, \lfloor x'_{\text{OUT\_PKTS}} \rceil)$$
4. **Physical Telemetry Header Invariant:**
   In NetFlow v9 records, total IP packet bytes (header + payload) are recorded. Based on RFC 791 (IPv4 minimum 20-byte base header):
   $$x'_{\text{IN\_BYTES}} \ge x'_{\text{IN\_PKTS}} \times 20$$
   $$\text{If } x'_{\text{OUT\_PKTS}} > 0 \implies x'_{\text{OUT\_BYTES}} \ge x'_{\text{OUT\_PKTS}} \times 20$$
5. **Protocol & Flag Immutability:**
   Transport protocol codes (`PROTOCOL`), application dissectors (`L7_PROTO`), and RFC 793 control flags (`TCP_FLAGS`) remain strictly identical to the clean record:
   $$x'_k = x_k \quad \forall k \in \mathcal{I} = \{\text{PROTOCOL}, \text{L7\_PROTO}, \text{TCP\_FLAGS}\}$$

---

## 5. Query-Guided Greedy Search (QGGS / SGGS) & Query Accounting

While historically designated as Surrogate-Guided Greedy Search (SGGS) in preliminary research notes, the implemented attack is formally defined as **Query-Guided Greedy Search (QGGS)** because it directly queries the target model's output probabilities $\mathcal{P}(\text{Attack} \mid x)$ without requiring an auxiliary surrogate model.

### 5.1 Formulation & Objective
QGGS simulates a query-limited black-box adversary seeking to evade detection with minimal model queries:
1. **Initial Clean Prediction:** 1 query per sample is executed to verify initial attack detection ($\mathcal{P}(\text{Attack} \mid x) \ge 0.50$). Only true positives are subjected to perturbation.
2. **Iterative Coordinate Descent:** In each iteration $k \in \{1, \dots, I_{\max}\}$, 5 candidate mutations (one per mutable feature $j \in \mathcal{M}$, with $|\mathcal{M}| = 5$) are evaluated with coordinate step budget $\alpha = 0.05$:
   $$j^* = \arg\min_{j \in \mathcal{M}} \mathcal{P}(\text{Attack} \mid \text{Project}(x^{(k-1)} + \alpha x^{(k-1)}_j))$$
   If $\min_{j} \mathcal{P} < \mathcal{P}^{(k-1)}$, the state updates to $x^{(k)} = \text{Project}(x^{(k-1)} + \alpha x^{(k-1)}_{j^*})$. If no candidate mutation decreases the probability, the search terminates early (plateau convergence).

### 5.2 Perturbation Budget Semantics
In QGGS, the parameter $\epsilon_{\max} = 0.50$ represents an **accumulated greedy-step budget** that permits up to $\frac{\epsilon_{\max}}{\alpha} = 10$ sequential coordinate steps (for step size $\alpha = 0.05$). When a single feature is repeatedly updated across successive iterations, changes compound geometrically ($x^{(k)} = x^{(k-1)}(1 + \alpha)$). Thus, $\epsilon_{\max}$ serves as a termination limit on cumulative perturbation rounds rather than a strict linear $L_\infty$ box constraint relative to the clean baseline.

### 5.3 Query Accounting Reconciliation
- Maximum candidate search queries per round: 5 queries ($|\mathcal{M}| = 5$).
- **Configuration A (Audited Low-Query Benchmark - Authoritative Baseline):**
  - Search iteration ceiling: $I_{\max} = 3$ rounds.
  - Search query ceiling: $3 \times 5 = 15$ queries.
  - Total query ceiling per sample: $1\text{ (initial)} + 15\text{ (search)} = \mathbf{16\text{ queries}}$ (strictly enforced; theoretical and observed maximum = 16 queries).
  - Observed metrics ($N=100$ attacks): Evasion rate = **6.00%** (6/100); average search queries = 14.9; average total queries = **15.9** (range: 11–16).
- **Configuration B (Extended Multi-Round Search):**
  - Search iteration ceiling: $I_{\max} = 10$ rounds.
  - Search query ceiling: $10 \times 5 = 50$ queries.
  - Total query ceiling per sample: $1 + 50 = \mathbf{51\text{ queries}}$.
  - Observed metrics ($N=100$ attacks): Evasion rate = **60.00%** (60/100); average search queries = 26.6; average total queries = **27.6** (range: 11–46).
- **Retirement of Historical Typo:** The historical 77% evasion figure recorded in an early Phase 10 narrative draft was an unverified drafting typographical error; no saved experiment or code ever produced 77%. The authoritative benchmark is **6.00%** under Configuration A and **60.00%** under Configuration B.

---

## 6. SHAP Explainability & Explanation Stability Metrics

### 6.1 TreeExplainer Attribution Spaces
- **XGBoost:** Computes TreeSHAP in **log-odds (margin) space** before the logistic sigmoid link. Attributions satisfy additive efficiency w.r.t logit:
  $$\phi_0 + \sum_{j=1}^d \phi_j(x) = \text{logit}(\mathcal{P}(\text{Attack} \mid x))$$
  Base value: $\phi_0 = 0.0$.
- **Random Forest:** Computes TreeSHAP in **probability space** $\in [0, 1]$. Base value: $\phi_0 = 0.50$.
- **Methodological Rule:** Raw SHAP magnitudes cannot be compared across different model families without rank normalization.

### 6.2 Attribution Drift Metrics ($N=500$ Paired Attack Samples at $\epsilon=0.20$)
1. **$L_1$ Attribution Drift:**
   $$L_1(\phi, \phi') = \frac{1}{d} \sum_{j=1}^d |\phi_j(x) - \phi_j(x')|$$
2. **Normalized $L_2$ Drift:**
   $$\text{Norm-}L_2(\phi, \phi') = \frac{\|\phi(x) - \phi(x')\|_2}{\|\phi(x)\|_2 + 10^{-6}}$$
3. **Top-$k$ Feature Overlap (Jaccard at $k=3$):**
   $$J_k(x, x') = \frac{|\text{TopK}(\phi(x)) \cap \text{TopK}(\phi(x'))|}{k}$$
4. **Spearman Feature-Ranking Correlation ($\rho_s$):**
   Evaluates rank preservation across the $d=8$ baseline features.

### 6.3 Four-Quadrant Analysis & Validation Calibration
Model behavior under perturbation is categorized into four mutually exclusive quadrants:
- **Quadrant I (Stable Detection & Stable Explanation):** $\hat{y}_{pert} = 1$, $L_1 < \tau$.
- **Quadrant II (Stable Detection & Fragile Explanation):** $\hat{y}_{pert} = 1$, $L_1 \ge \tau$.
- **Quadrant III (Flipped Detection & Shifted Explanation):** $\hat{y}_{pert} = 0$, $L_1 \ge \tau$.
- **Quadrant IV (Flipped Detection & Deceptive Stability):** $\hat{y}_{pert} = 0$, $L_1 < \tau$.

**Validation Calibration Protocol:**
To avoid using test samples to choose the stability cutoff, threshold $\tau$ was calibrated on a separate validation cohort ($N=500$ from `X_val`):
$$\tau_{val} = \text{median}(L_{1, val}) = \mathbf{0.2739}$$
When applied to the held-out test cohort, the partition yields:
- Q1: 231 flows (46.2%)
- Q2: 155 flows (31.0%)
- Q3: 112 flows (22.4%)
- Q4: 2 flows (0.4%)
Total: 500 flows (100.0%).

---

## 7. Port Feature Ablation & Stress-Testing Protocol

To resolve whether transport ports (`L4_SRC_PORT`, `L4_DST_PORT`) represent genuine features or dataset shortcuts, two model configurations were evaluated:
- **Baseline Model (8 features):** Excludes port numbers; relies strictly on flow geometry.
- **Extended Model (10 features):** Includes `L4_SRC_PORT` and `L4_DST_PORT`.

Both models were evaluated on the same clean test cohort across 5 stress scenarios:
1. Clean baseline.
2. Source-port randomization (ephemeral range 49152–65535).
3. Destination service-port redirection (80 $\to$ 8080, 22 $\to$ 2222, 21 $\to$ 2121, 443 $\to$ 8443).
4. Flow-feature perturbation alone ($\epsilon=0.20$, ports static).
5. Combined destination port redirection + flow-feature perturbation ($\epsilon=0.20$).
The 8-feature model served as an experimental control.

**Methodological Qualification:**
The 8-feature model's zero evasion (0 / 1,664 attacks missed) under direct port modification is a direct mathematical consequence of excluding port fields from its feature vector. This confirms feature invariance to direct tabular port-field changes when other features are unchanged, but must not be conflated with live wire-level network immunity against physical multi-vector attacks.

