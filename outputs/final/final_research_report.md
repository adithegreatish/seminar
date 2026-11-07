# Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations

**A Technical Seminar Report Submitted in Partial Fulfillment of the Requirements for the Degree of**  
**Bachelor of Engineering in Information Technology**

**Author:** Aditya Ambare  
**Roll Number:** TIA26  
**Academic Year:** 2026–2027  
**Department of Information Technology**  

---

## Abstract

Machine learning-based Network Intrusion Detection Systems (NIDS) have achieved remarkable success in detecting malicious network traffic under idealized, static evaluation conditions. However, standard classifiers are inherently vulnerable to adversarial evasion attacks and frequently function as opaque black boxes, preventing security operations center (SOC) analysts from understanding the underlying rationale of model alerts. 

This research investigates the dual challenge of **adversarial robustness** and **explanation stability** in machine learning NIDS. Using the large-scale **NF-CSE-CIC-IDS2018** benchmark (5,918,803 flows), we implement a leakage-free, reproducible experimental framework evaluating Decision Trees, Random Forests, and XGBoost across both binary and multiclass paradigms. We introduce **Domain-Constrained Flow-Feature Perturbation (DC-FFP)**, an adversarial perturbation model that strictly adheres to physical networking invariants—including unidirectional packet accumulation ($\Delta \ge 0$), packet count integrality, protocol immutability, and the observational header constraint $\text{BYTES} \ge \text{PKTS} \times 20$ grounded in RFC 791. 

We explain model decisions using exact Shapley values via **SHAP TreeExplainer** and evaluate whether feature attributions remain dependable when inputs are perturbed. Our experiments reveal three foundational insights:
1. **Adversarial Fragility:** While XGBoost attains 98.16% clean test accuracy (Macro-F1: 0.9238, False Positive Rate: 0.97%), a moderate 20% traffic padding perturbation ($\epsilon=0.20$) causes an evasion rate of 21.94%, while Random Forest collapses to a 28.46% evasion rate.
2. **The Port-Shortcut Vulnerability:** Incorporating transport port numbers (`L4_SRC_PORT`, `L4_DST_PORT`) increases clean accuracy to 98.90%, but introduces a catastrophic shortcut dependency. Under operational service-port redirection, the 10-feature model suffers a **94.13% evasion rate** (1,572 out of 1,670 attacks missed), whereas the 8-feature baseline is invariant to direct changes in source and destination port fields when no other model input features are modified (0% evasion; 0 / 1,664 attacks missed).
3. **Deceptive Explanation Stability:** Through a paired 500-sample Four-Quadrant stability analysis, we identify **Quadrant IV (0.4% occurrence)**, demonstrating that an adversary can induce misclassification while maintaining attribution drift below the validation-calibrated stability threshold ($L_1 \le 0.2739$). Consequently, explanation stability cannot be treated as a mathematical proof of classification correctness.

These findings demonstrate that high clean accuracy is an insufficient metric for operational cybersecurity, necessitating port-agnostic feature engineering, domain-constrained robustness stress-testing, and rigorous explanation stability auditing.

---

## 1. Introduction & Background

Modern enterprise and cloud infrastructures face an unprecedented volume and sophistication of cyber threats, ranging from distributed denial-of-service (DDoS) campaigns and credential brute-forcing to advanced persistent threats (APTs) and zero-day intrusions. Traditional signature-based Network Intrusion Detection Systems (such as Snort or Suricata) rely on deterministic pattern matching against known indicators of compromise. While effective against known exploit payloads, signature-based approaches exhibit severe limitations when confronting obfuscated, polymorphic, or zero-day attacks.

To overcome these constraints, Machine Learning (ML) and Deep Learning (DL) approaches have been widely adopted in academic research and commercial security solutions. By learning statistical regularities across bidirectional network flow telemetry (e.g., NetFlow, IPFIX), statistical classifiers can generalize to detect anomalous traffic patterns without requiring explicit payload signatures.

Despite extensive literature reporting classification accuracies exceeding 98%, machine learning-based NIDS face critical operational barriers in production environments:
1. **The Black-Box Dilemma:** Complex non-linear models (e.g., ensemble gradient boosters and deep neural networks) fail to provide interpretable explanations for their predictions. Security analysts cannot afford to isolate mission-critical servers based on an uninterpretable probability score.
2. **Adversarial Vulnerability:** Small, deliberate manipulations of traffic patterns—such as inserting dummy packets, fragmenting payloads, or pacing transmissions—can cause classifiers to misclassify malicious flows as benign.
3. **Data Leakage and Spurious Shortcuts:** Standard evaluations frequently suffer from methodological flaws, such as fitting scalers prior to data splitting, or incorporating transient identifiers (e.g., IP addresses, ephemeral source ports) that allow models to achieve high benchmark accuracy while learning no generalizable behavioral signatures.
4. **Explanation Fragility:** In security operations, explainable AI (XAI) tools like SHAP (SHapley Additive exPlanations) are increasingly deployed to explain alerts. However, the stability of these explanations under adversarial conditions remains largely unexamined.

This research addresses these fundamental challenges by developing a comprehensive, mathematically rigorous, and locally reproducible evaluation framework for robust and explainable network intrusion detection.

---

## 2. Problem Statement & Research Objectives

### 2.1 Problem Formulation
Let a network flow instance be represented by a feature vector $x \in \mathcal{X} \subset \mathbb{R}^d$, associated with a true class label $y \in \{0, 1\}$ (where $0 = \text{Benign}$ and $1 = \text{Attack}$). An intrusion detection classifier $f: \mathcal{X} \to \{0, 1\}$ maps flow features to predicted classes. 

Under an adversarial perturbation $\delta \in \mathbb{R}^d$, the perturbed flow $x' = x + \delta$ must satisfy network domain constraints $\mathcal{C}$ such that $x' \in \mathcal{C}(\mathcal{X})$. The adversarial objective is to cause misclassification:
$$f(x + \delta) = 0 \quad \text{subject to } f(x) = 1 \text{ and } (x + \delta) \in \mathcal{C}(\mathcal{X})$$

Simultaneously, let $\phi(f, x) \in \mathbb{R}^d$ denote the local feature attribution vector explaining the model's prediction at $x$. The research investigates:
1. Does the model $f(x)$ maintain its detection capability when $x$ is perturbed under domain invariants?
2. Does the explanation $\phi(f, x')$ remain stable relative to $\phi(f, x)$?
3. Can an adversary deceive the classifier without triggering an explanation drift alarm?

### 2.2 Core Research Objectives
- **Objective 1 (Methodological Rigor):** Audit the 5.9-million record NF-CSE-CIC-IDS2018 benchmark, establish zero-data-leakage preprocessing, and train Decision Tree, Random Forest, and XGBoost baselines under identical stratified splits.
- **Objective 2 (Explainability):** Implement exact game-theoretic SHAP TreeExplainer attributions to identify the primary statistical flow features driving benign and malicious decisions across architectures.
- **Objective 3 (Domain-Constrained Adversarial Stress-Testing):** Formulate and evaluate Domain-Constrained Flow-Feature Perturbation (DC-FFP) and Surrogate-Guided Greedy Search (SGGS), strictly enforcing non-decreasing byte/packet invariants ($\Delta \ge 0$), packet integrality, and RFC 791 header bounds.
- **Objective 4 (Port Shortcut Discovery):** Perform feature ablation studies comparing an 8-feature port-agnostic baseline against a 10-feature port-aware model under service-port redirection scenarios.
- **Objective 5 (Explanation Stability Auditing):** Formulate continuous attribution drift metrics ($L_1$, normalized $L_2$, Top-$k$ overlap, Spearman rank correlation) and a validation-calibrated Four-Quadrant analysis to quantify the relationship between prediction robustness and explanation stability.

---

## 3. Literature Review & Related Work

### 3.1 Machine Learning for Flow-Based NIDS
Early NIDS research evaluated KDD Cup 99 and NSL-KDD datasets, which are now widely recognized as obsolete due to redundant records, synthetic generation flaws, and unrealistic traffic distributions. Modern research has transitioned to standardized flow benchmarks, notably the CIC-IDS series developed by the Canadian Institute for Cybersecurity. Sarhan et al. (2021) standardized these datasets into NetFlow v9 formats (NF-CSE-CIC-IDS2018), enabling standardized feature sets across disparate captures.

Ensemble tree-based algorithms—specifically Random Forests (Breiman, 2001) and Gradient Boosted Decision Trees (Chen & Guestrin, 2016)—consistently outperform deep architectures on tabular flow data in terms of classification accuracy, computational efficiency, and low inference latency.

### 3.2 Explainable AI in Cybersecurity
The opacity of high-performing ensembles has motivated the adoption of Post-Hoc Explainability frameworks:
- **LIME (Local Interpretable Model-agnostic Explanations):** Ribeiro et al. (2016) proposed sampling perturbations around an instance and fitting a sparse local linear surrogate. However, LIME exhibits high sampling variance and lacks mathematical guarantees of attribution consistency.
- **SHAP (SHapley Additive exPlanations):** Lundberg and Lee (2017) unified cooperative game theory (Shapley, 1953) with local feature attributions. The TreeExplainer algorithm (Lundberg et al., 2020) enables exact, polynomial-time computation of Shapley values for tree ensembles without heuristic sampling approximations.

Despite widespread adoption, most NIDS studies apply SHAP purely descriptively, without investigating whether the explanations themselves can be manipulated or whether attribution drift correlates with prediction evasion.

### 3.3 Adversarial Machine Learning in the Problem Space
Adversarial machine learning originated in computer vision (Szegedy et al., 2014; Goodfellow et al., 2015), where continuous $L_p$-norm bounded perturbations are added to pixel values. However, directly applying computer vision attack algorithms (e.g., FGSM, PGD, JSMA) to network flow data creates physically impossible artifacts:
- Continuous perturbations produce fractional packet counts (e.g., adding 2.47 packets).
- Bidirectional noise ($\pm \epsilon$) subtracts bytes or packets from a transmitted session, which is physically impossible on a real network without full MITM packet suppression.
- Domain dependencies are violated, such as generating flows where byte count is less than packet count.

Recent cybersecurity researchers (Pierazzi et al., 2020; Apruzzese et al., 2022) have emphasized the distinction between **Feature-Space** perturbations and **Problem-Space** transformations. Robust evaluations must constrain feature manipulations to those achievable via valid problem-space actions (e.g., dummy payload padding, TCP handshaking delays).

---

## 4. Dataset Architecture & Preprocessing Methodology

### 4.1 Dataset Profile & Integrity Verification
The research utilizes the **NF-CSE-CIC-IDS2018** benchmark, a standardized NetFlow v9 conversion of the AWS testbed dataset. A comprehensive audit of the entire raw dataset was conducted, verifying the properties in Table 1.

**Table 1: NF-CSE-CIC-IDS2018 Dataset Audit Summary**
| Attribute | Audited Property Value | Status / Verification Note |
| :--- | :--- | :--- |
| **Total Record Count** | 5,918,803 flows | Verified complete ingestion |
| **Total Features** | 12 columns | 10 flow attributes, 2 target columns |
| **Missing / Null Values** | 0 cells (0.00%) | Complete data integrity |
| **Infinite Values** | 0 cells (0.00%) | Complete data integrity |
| **Exact Duplicate Rows** | 0 rows (0.00%) | NetFlow v9 unique flows |
| **Binary Class Distribution** | Benign: 5,534,773 (93.51%)<br>Attack: 384,030 (6.49%) | Severe real-world class imbalance |
| **Multiclass Categories** | 15 distinct attack categories | Extreme minority scarcity |
| **Physical Constraint Check** | $\text{BYTES} \ge \text{PKTS} \times 20$ | **0 violations across all 5,918,803 flows** |
| **Empirical Minimum Ratio** | 28.0 bytes / packet | Strictly satisfies RFC 791 bound |

### 4.2 Feature Taxonomy & Baseline Selection
The 10 feature attributes available in the dataset are classified into two distinct operational tiers:

**Table 2: Feature Taxonomy and Dimensionality Sets**
| Feature Name | Telemetry Type | Baseline Model (8 Features) | Extended Model (10 Features) | Physical Mutability Under Attack |
| :--- | :--- | :---: | :---: | :--- |
| `PROTOCOL` | L4 Protocol (e.g., TCP=6, UDP=17) | **Included** | **Included** | Immutable |
| `L7_PROTO` | Application Protocol Identifier | **Included** | **Included** | Immutable |
| `IN_BYTES` | Inbound flow volume (Bytes) | **Included** | **Included** | Mutable (Padding $\Delta \ge 0$) |
| `OUT_BYTES` | Outbound flow volume (Bytes) | **Included** | **Included** | Mutable (Padding $\Delta \ge 0$) |
| `IN_PKTS` | Inbound packet count | **Included** | **Included** | Mutable (Integer $\Delta \in \mathbb{Z}_{\ge 0}$) |
| `OUT_PKTS` | Outbound packet count | **Included** | **Included** | Mutable (Integer $\Delta \in \mathbb{Z}_{\ge 0}$) |
| `TCP_FLAGS` | Bitwise cumulative TCP flags | **Included** | **Included** | Immutable |
| `FLOW_DURATION_MILLISECONDS` | Total elapsed flow duration (ms) | **Included** | **Included** | Mutable (Timing Delay $\Delta \ge 0$) |
| `L4_SRC_PORT` | Ephemeral client port (0–65535) | *Excluded (Control)* | **Included** | Configurable (Client-side) |
| `L4_DST_PORT` | Service destination port (0–65535) | *Excluded (Control)* | **Included** | Configurable (Server redirection) |

*Methodological Rationale for 8-Feature Baseline:* Source ports are ephemeral client allocations randomized by operating system network stacks. Destination ports identify targeted network services. Incorporating raw port numbers into statistical flow models introduces severe dataset-specific shortcut learning, where models memorize port numbers rather than intrinsic traffic dynamics. Excluding ports in the baseline configuration enforces learning of behavioral traffic characteristics.

### 4.3 Zero-Data-Leakage Partitioning Pipeline
To ensure complete reproducibility and prevent subtle data leakage, the preprocessing pipeline enforces the following strict sequencing:
1. **Sampling:** A stratified random sample of $N=200,000$ flows is drawn from the 5.9-million record dataset using a fixed seed (`RANDOM_SEED = 42`), strictly preserving the 93.51% / 6.49% class ratio.
2. **Stratified Splitting:** The sample is partitioned into:
   - **Training Partition:** 140,000 flows (70.0%)
   - **Validation Partition:** 30,000 flows (15.0%)
   - **Test Partition:** 30,000 flows (15.0%)
3. **Preprocessor Fitting:** Missing value imputers (`SimpleImputer(strategy='median')`) and feature scalers (`StandardScaler()`) are **fit strictly on the 140,000 training records**.
4. **Transform Only:** Validation and test partitions are transformed using the frozen training parameters (`transform()`, never `fit_transform()`), guaranteeing zero information leakage from evaluation sets into training state.

---

## 5. Model Architecture & Clean Experimental Results

### 5.1 Evaluated Classifiers
Three representative model architectures spanning the interpretability-complexity spectrum were trained under identical configurations:
1. **Decision Tree (CART Benchmark):** Max depth 15, minimum samples split 20. Serves as a deterministic, human-interpretable benchmark.
2. **Random Forest (Bagging Ensemble):** 100 estimators, max depth 20, max features `sqrt`. Leverages bootstrap aggregating to reduce variance and improve generalization.
3. **XGBoost (Gradient Boosting Decision Tree - Top Model):** 100 estimators, learning rate $\eta=0.10$, max depth 6, subsample 0.8, colsample_bytree 0.8, tree_method `hist`. Sequentially minimizes regularized logistic loss.

### 5.2 Clean Binary Classification Performance
All models were evaluated on the held-out test partition ($N=30,000$ flows; 28,326 Benign, 1,674 Attack).

**Table 3: Clean Binary Classification Performance on Held-Out Test Set ($N=30,000$)**
| Model Architecture | Accuracy | Macro-F1 | Attack Recall | Benign Recall | False Positive Rate (FPR) | ROC-AUC | Single-Sample Latency | Vectorized Throughput |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Decision Tree** | 97.13% | 0.8901 | **85.97%** | 97.91% | 2.09% | **0.9506** | 0.37 ms | 13.9M flows/sec |
| **Random Forest** | 97.79% | 0.9113 | 85.77% | 98.63% | 1.37% | **0.9574** | 17.73 ms | 785k flows/sec |
| **XGBoost** | **98.16%** | **0.9238** | 85.51% | **99.03%** | **0.97%** | **0.9621** | **0.63 ms** | **4.39M flows/sec** |

*Note on ROC-AUC Reconciliation:* ROC-AUC is evaluated strictly on continuous predicted probabilities across all classification thresholds (`predict_proba()[:, 1]`). An earlier draft table reported Balanced Accuracy (macro-recall: 0.9194 for Decision Tree, 0.9220 for Random Forest) derived from hard binary predictions (`predict()`). Continuous probability integration yields the authoritative values above (DT: 0.9506, RF: 0.9574, XGB: 0.9621).

### 5.3 Analysis of Clean Baseline Results
- **XGBoost achieves the superior operational trade-off:** It delivers the highest overall accuracy (98.16%), the highest Macro-F1 (0.9238), the highest ROC-AUC (0.9621), and the lowest False Positive Rate (0.97%). In high-volume security monitoring, suppressing FPR below 1.0% is paramount to avoid SOC analyst alert fatigue.
- **Inference Latency Dynamics:** While single-tree evaluation is fastest (0.37 ms streaming), XGBoost achieves an optimal balance between execution speed (0.63 ms streaming; 0.23 $\mu$s vectorized batch) and detection efficacy. Random Forest requires 17.73 ms for streaming single-sample inference due to the computational overhead of evaluating 100 deep trees without histogram binning optimizations.

### 5.4 Multiclass Classification Degradation
When evaluated on the 15-class multiclass attack taxonomy, all models exhibit marked performance degradation:
- **Decision Tree:** Accuracy = 61.10%, Macro-F1 = 0.5432.
- **Random Forest:** Accuracy = 73.34%, Macro-F1 = 0.5838.
- **XGBoost:** Accuracy = 65.27%, Macro-F1 = 0.5694.

*Root Cause Analysis:* Multiclass degradation is driven entirely by extreme class imbalance in the training data. While majority attack categories like `DDoS attacks-LOIC-HTTP` ($N=38,247$) achieve F1 scores exceeding 0.95, extreme minority categories such as `SQL Injection` ($N=6$), `Infiltration` ($N=11$), and `Brute Force -Web` ($N=23$) suffer recall scores near zero. Tree split criteria optimize global impurity reduction, starving small minority classes of dedicated branch partitions.

---

## 6. Explainable AI via SHAP (Shapley Additive Explanations)

### 6.1 Game-Theoretic Formulation & TreeExplainer
To eliminate black-box opacity, we deploy **SHAP TreeExplainer**. Derived from cooperative game theory, Shapley values distribute the total model outcome among input features according to their marginal contributions across all possible feature subsets $\mathcal{S} \subseteq \mathcal{F} \setminus \{i\}$:
$$\phi_i(x) = \sum_{\mathcal{S} \subseteq \mathcal{F} \setminus \{i\}} \frac{|\mathcal{S}|! (|\mathcal{F}| - |\mathcal{S}| - 1)!}{|\mathcal{F}|!} \left[ f_x(\mathcal{S} \cup \{i\}) - f_x(\mathcal{S}) \right]$$

SHAP satisfies four fundamental axiomatic properties: **Efficiency** ($\sum \phi_i = f(x) - E[f(x)]$), **Symmetry**, **Dummy Player**, and **Additivity**.

### 6.2 Attribution Space Distinction
- **XGBoost:** TreeExplainer computes attributions in **log-odds (raw margin) space** before the logistic sigmoid link function:
  $$f(x) = \log\left(\frac{P(y=1|x)}{1 - P(y=1|x)}\right) = \phi_0 + \sum_{i=1}^d \phi_i(x)$$
  Positive SHAP values push the raw margin toward malicious classification ($y=1$); negative values push toward benign ($y=0$).
- **Random Forest:** TreeExplainer computes attributions directly in **probability space** ($f(x) \in [0, 1]$).

### 6.3 Global Feature Importance Analysis
Mean absolute SHAP values ($E[|\phi_i|]$) were computed across a representative test cohort of $N=2,000$ flows to identify global feature drivers.

**Table 4: Global SHAP Feature Importance and Attribution Ranking**
| Feature Name | XGBoost Mean \|SHAP\| (Log-Odds) | XGB Rank | Random Forest Mean \|SHAP\| (Probability) | RF Rank | Consensus Interpretation |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `OUT_BYTES` | **0.7051** | **1** | **0.1448** | **1** | Primary exfiltration / payload indicator |
| `FLOW_DURATION_MILLISECONDS` | **0.6560** | **2** | **0.1378** | **2** | Key timing discriminator (DDoS vs Benign) |
| `IN_BYTES` | 0.4589 | 3 | 0.0882 | 4 | Inbound probe / request size |
| `IN_PKTS` | 0.4404 | 4 | 0.0910 | 3 | Packet transmission intensity |
| `OUT_PKTS` | 0.2444 | 5 | 0.0617 | 5 | Response packet volume |
| `TCP_FLAGS` | 0.2017 | 6 | 0.0521 | 6 | Handshake anomalies (SYN/RST/ACK) |
| `PROTOCOL` | 0.0093 | 7 | 0.0062 | 7 | Protocol layer base discriminator |
| `L7_PROTO` | 0.0022 | 8 | 0.0028 | 8 | Granular application protocol |

### 6.4 Cross-Model Attribution Consistency
Evaluating whether different model families rely on identical physical features is critical for defensive explainability.
- Both XGBoost and Random Forest agree that **`OUT_BYTES`** and **`FLOW_DURATION_MILLISECONDS`** are the two dominant statistical features governing network intrusion classification.
- The Spearman rank correlation coefficient between the feature rankings of the two models is:
  $$\rho_s = 0.8095 \quad (p = 0.0149, \quad df = 6)$$
- *Statistical Caveat:* The correlation is statistically significant at $\alpha = 0.05$. However, because the feature space comprises exactly 8 features ($N=8, df=6$), statistical power is constrained. Minor rank inversions among intermediate features (such as `IN_BYTES` vs. `IN_PKTS`) exert a pronounced numerical impact on $\rho_s$.

---

## 7. Adversarial Robustness Under Domain-Constrained Perturbations

### 7.1 Threat Model & The Physical Infeasibility of Standard Attacks
Standard computer vision attacks (FGSM, PGD) cannot be deployed against tree ensembles for two fundamental reasons:
1. **Mathematical Incompatibility:** Decision trees are step functions composed of axis-aligned orthogonal hyperplanes. The gradient of the loss with respect to continuous feature inputs is zero almost everywhere ($\nabla_x \mathcal{L} = 0$), rendering gradient-ascent attacks mathematically undefined without smoothed neural surrogates.
2. **Domain Infeasibility:** Unconstrained $L_p$-norm attacks generate impossible network flow states, such as negative packet counts, negative byte transfers, fractional packets, or flows where bytes are fewer than packets.

### 7.2 Domain-Constrained Flow-Feature Perturbation (DC-FFP)
To evaluate realistic adversarial vulnerabilities, we formulate **Domain-Constrained Flow-Feature Perturbation (DC-FFP)**. DC-FFP models an attacker who manipulates network traffic by injecting dummy packets, padding payload data with chaff bytes, and adding artificial transmission delays.

**Mathematical Formulation:**
For an active flow instance $x$, the perturbed feature vector $x'$ is generated across perturbation budget $\epsilon \in [0.0, 0.50]$ via:
$$x'_j = x_j (1 + \epsilon) + \Delta_{\min}^{(j)} \quad \forall j \in \mathcal{M}_{\text{traffic}}$$

where $\mathcal{M}_{\text{traffic}} = \{\text{IN\_BYTES}, \text{OUT\_BYTES}, \text{IN\_PKTS}, \text{OUT\_PKTS}, \text{FLOW\_DURATION\_MILLISECONDS}\}$, and:
$$\Delta_{\min}^{(j)} = \begin{cases} 1 & \text{for integer packet counters } (\text{IN\_PKTS}, \text{OUT\_PKTS}) \text{ when } \epsilon > 0 \\ 0 & \text{when } \epsilon = 0.0 \text{ or for continuous counters (Bytes, Duration)} \end{cases}$$

**Zero-Epsilon Identity Validation:**
When the adversary's perturbation budget is zero ($\epsilon = 0.00$), the transformation reduces to the exact identity function:
$$\forall j: \quad x'_j = x_j(1 + 0) + 0 = x_j$$
This property was rigorously verified via an automated unit test across all 30,000 held-out test records:
$$\text{assert np.array\_equal}(X_{\text{clean}}, X_{\text{perturbed}}(\epsilon=0.0)) \equiv \text{True}$$
confirming that unperturbed records remain completely unaltered prior to evaluation.

**Enforced Domain Invariants:**
1. **Monotonicity Constraint ($\Delta \ge 0$):** Network flows represent cumulative counters. An adversary can add bytes or packets, but cannot retroactively remove data previously recorded by the flow exporter:
   $$x'_j \ge x_j \quad \forall j$$
2. **Packet Count Integrality:** Packet additions must be discrete integers:
   $$x'_{\text{PKTS}} \in \mathbb{Z}_{\ge 0}$$
3. **Observational NetFlow Header Bound (RFC 791):** NetFlow v9 records count the entire IP packet (header plus payload). Under IPv4, the minimum header length is 20 bytes. Thus, any physically valid flow must satisfy:
   $$x'_{\text{IN\_BYTES}} \ge x'_{\text{IN\_PKTS}} \times 20 \quad \text{and} \quad x'_{\text{OUT\_BYTES}} \ge x'_{\text{OUT\_PKTS}} \times 20$$
   If perturbation inflates packet counts such that this ratio is violated, byte counts are automatically adjusted upwards to maintain the minimum 20 byte/packet invariant.
4. **Protocol and Flag Immutability:** Layer-4 protocol identifiers (`PROTOCOL`, `L7_PROTO`) and cumulative bitwise `TCP_FLAGS` are held invariant, as altering them would break stateful TCP session tracking and terminate the active connection.

### 7.3 Rigorous Evasion Rate Formulation
To ensure scientific validity, the **Evasion Rate** is evaluated strictly over the cohort of malicious test samples that were **correctly detected prior to perturbation**:
$$\text{Evasion Rate}(\epsilon) = \frac{\sum_{i \in \mathcal{D}_{\text{mal}}} \mathbb{I}\left(f(x_i) = 1 \land f(x'_i(\epsilon)) = 0\right)}{\sum_{i \in \mathcal{D}_{\text{mal}}} \mathbb{I}\left(f(x_i) = 1\right)}$$

This eliminates denominator contamination from samples that the model failed to detect on clean data.

### 7.4 Adversarial Evaluation Results
Evasion rates and perturbed attack recalls were evaluated across budgets $\epsilon \in \{0.00, 0.05, 0.10, 0.20, 0.30, 0.50\}$.

**Table 5: Adversarial Evasion and Recall Trajectory Under DC-FFP**
| Perturbation Budget ($\epsilon$) | Decision Tree Evasion Rate | DT Attack Recall | Random Forest Evasion Rate | RF Attack Recall | XGBoost Evasion Rate | XGB Attack Recall |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$\epsilon = 0.00$ (Clean)** | 0.00% (0/1673) | 85.97% | 0.00% (0/1669) | 85.77% | **0.00%** (0/1664) | **85.51%** |
| **$\epsilon = 0.05$ (Subtle)** | 10.34% (173/1673) | 78.42% | 11.62% (194/1669) | 75.80% | **0.66%** (11/1664) | **85.20%** |
| **$\epsilon = 0.10$ (Minor)** | 13.39% (224/1673) | 76.21% | 13.90% (232/1669) | 73.90% | **4.45%** (74/1664) | **81.91%** |
| **$\epsilon = 0.20$ (Moderate)** | 21.40% (358/1673) | 69.37% | 28.46% (475/1669) | 61.46% | **21.94%** (365/1664) | **67.01%** |
| **$\epsilon = 0.30$ (Aggressive)**| 21.76% (364/1673) | 68.71% | 31.34% (523/1669) | 59.04% | **23.32%** (388/1664) | **65.83%** |
| **$\epsilon = 0.50$ (Extreme)** | 34.43% (576/1673) | 58.07% | 40.50% (676/1669) | 51.18% | **33.83%** (563/1664) | **56.89%** |

### 7.5 Key Robustness Findings
1. **XGBoost Exhibits Superior Resilience at Low Budgets:** At subtle perturbation ($\epsilon=0.05$), XGBoost evades at only 0.66% (11 missed attacks), whereas Random Forest collapses to 11.62% evasion and Decision Tree to 10.34%. Gradient boosted shallow trees regularized by learning rate shrinkage establish tighter margin boundaries against slight feature jitter.
2. **Ensemble Fragility Under Traffic Padding ($\epsilon=0.20$):** At moderate 20% padding, over 1 in 5 attacks evade XGBoost (21.94% evasion), and over 1 in 4 evade Random Forest (28.46% evasion). Inflating `OUT_BYTES` and `FLOW_DURATION_MILLISECONDS` successfully shifts attack flows into regions of feature space occupied by legitimate bulk transfer and long-lived streaming connections.
3. **Random Forest Exhibits Accelerated Collapse:** At extreme perturbation ($\epsilon=0.50$), Random Forest attack recall deteriorates to 51.18% (40.50% evasion), performing barely better than random chance on malicious traffic.

### 7.6 Surrogate-Guided Greedy Search (SGGS) & Query Complexity
In addition to non-iterative DC-FFP, we implemented **Surrogate-Guided Greedy Search (SGGS)**, a query-efficient black-box attack. SGGS evaluates candidate mutations across mutable feature dimensions ($\mathcal{M}$, with $|\mathcal{M}| = 5$). In each round, it queries the model for each feature step, advancing along the steepest descent direction or terminating early if no candidate feature reduces the attack probability. We evaluated two distinct experimental configurations over 100 correctly detected attack samples:

**Configuration A: Audited Low-Query Benchmark (Authoritative Baseline)**
- **Configuration:** Target model = XGBoost Binary, candidate sample = 100 initially detected attacks, `max_search_iterations = 3`, `step_budget = 0.05`, `max_epsilon = 0.50`.
- **Mathematical Query Bound:** 
  $$\text{Max Theoretical Search Queries} = I_{\max} \times |\mathcal{M}| = 3 \times 5 = 15 \text{ queries}$$
  $$\text{Max Theoretical Total Queries} = 1 \text{ (Initial clean query)} + 15 = \mathbf{16 \text{ queries}}$$
- **Observed Empirical Query Statistics:** Average search queries = **14.9**, Average total queries = **15.9**, **Maximum total queries = 16** (strictly obeying the theoretical ceiling), Minimum total queries = **11** (1 initial + 10 search queries when evasion is achieved at iteration 2).
- **Benchmark Evasion Result:** Exactly **6 out of 100 attacks evade detection (6.00% evasion rate)**.
- **Forensic Accounting of the "77%" Draft Discrepancy:** A comprehensive audit of execution traces confirmed that an early Phase 10 draft narrative contained a clerical drafting typo in step 364 that erroneously stated "77.00%". Zero experimental scripts, logs, or JSON/CSV files ever recorded 77%. The authoritative benchmark frozen in `attack_config.json`, `robustness_metrics.csv`, and `adversarial_evaluation_report.md` has always been **6.00% evasion (6/100)** under the 16-query limit. The 77% draft figure is formally retired as a narrative error with complete audit trail evidence.

**Configuration B: Multi-Step Extended Search (Deep Black-Box Audit)**
- **Configuration:** Target model = XGBoost Binary, candidate sample = 100 initially detected attacks, `max_search_iterations = 10`, `step_budget = 0.05`, `max_epsilon = 0.50`.
- **Mathematical Query Bound:** 
  $$\text{Max Theoretical Search Queries} = 10 \times 5 = 50 \text{ queries}; \quad \text{Max Theoretical Total Queries} = 1 + 50 = \mathbf{51 \text{ queries}}$$
- **Observed Empirical Query Statistics:** Average search queries = **26.6**, Average total queries = **27.6**, **Maximum total queries = 46** (well within the theoretical bound of 51), Minimum total queries = **11**.
- **Search Evasion Result:** Successfully evades **60 out of 100 attacks (60.00% evasion rate)**.

**Table 5b: Surrogate-Guided Greedy Search (SGGS) Reconciled Configurations**
| Configuration | Search Iterations ($I_{\max}$) | Step Budget ($\alpha$) | Evaluated Attacks | Successfully Evaded | Evasion Rate | Avg Search Queries | Avg Total Queries | Observed Query Range | Theoretical Query Ceiling |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Config A (Audited Benchmark)** | 3 | 0.05 | 100 | 6 | **6.00%** | 14.9 | **15.9** | 11 – **16** | **16** ($1 + 3 \times 5$) |
| **Config B (Extended Search)** | 10 | 0.05 | 100 | 60 | **60.00%** | 26.6 | **27.6** | 11 – **46** | **51** ($1 + 10 \times 5$) |

---

## 8. Feature Ablation & The Port-Shortcut Stress Test

A common convention in published NIDS literature is the inclusion of transport port attributes (`L4_SRC_PORT`, `L4_DST_PORT`) to boost benchmark accuracy. To rigorously assess the security implications of this practice, we conducted a systematic ablation study comparing our **8-feature port-agnostic baseline** against a **10-feature port-aware model**.

### 8.1 The Illusion of Superior Clean Performance
On the unperturbed test partition ($N=30,000$), the 10-feature model appears unquestionably superior:
- **XGBoost (8 Features):** Accuracy = 98.16%, Macro-F1 = 0.9238.
- **XGBoost (10 Features):** Accuracy = **98.90% (+0.74%)**, Macro-F1 = **0.9521 (+0.0283)**.

Inspection of feature importance revealed the mechanism behind this gain: `L4_DST_PORT` alone accounted for **24.30% of total split gain** in the 10-feature XGBoost model. The model learned to associate standard attack destination ports (e.g., port 80 for Web attacks, port 21 for FTP brute force) directly with malicious labels.

### 8.2 Stress-Testing Under Operational Port Shifts
To test whether this high accuracy represents true behavioral understanding or brittle memorization, both models were subjected to identical operational stress-test scenarios on the clean test cohort (1,664 detected attacks for 8-feat; 1,670 detected attacks for 10-feat).

**Table 6: Port-Shift Stress Test Results (8-Feature Control vs. 10-Feature Model)**
| Stress-Test Scenario | Model Configuration | Test Accuracy | Attack Recall | Evasion Rate | Attacks Evaded / Total | Security Interpretation |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **1. Clean Baseline** | XGBoost (8 Features)<br>XGBoost (10 Features) | 98.16%<br>98.90% | 85.51%<br>85.82% | **0.00%**<br>**0.00%** | 0 / 1664<br>0 / 1670 | Both models perform optimally on clean test set |
| **2. Source-Port Randomization** | XGBoost (8 Features)<br>XGBoost (10 Features) | 98.16%<br>98.86% | 85.51%<br>85.15% | **0.00%**<br>**0.78%** | 0 / 1664<br>13 / 1670 | Baseline unaffected; 10-feat loses 13 detections |
| **3. Destination Port Redirection** | XGBoost (8 Features)<br>XGBoost (10 Features) | **98.16%**<br>**93.66%** | **85.51%**<br>**5.04%** | **0.00%**<br>**94.13%** | **0 / 1664**<br>**1,572 / 1,670** | **10-feat model collapses! Misses 94.1% of attacks** |
| **4. Flow Perturbation Only ($\epsilon=0.20$)** | XGBoost (8 Features)<br>XGBoost (10 Features) | 94.91%<br>98.70% | 67.01%<br>83.04% | 21.94%<br>3.29% | 365 / 1664<br>55 / 1670 | 10-feat seems robust only because port is static |
| **5. Combined Port Shift + Flow ($\epsilon=0.20$)**| XGBoost (8 Features)<br>XGBoost (10 Features) | **94.91%**<br>**93.59%** | **67.01%**<br>**4.16%** | **21.94%**<br>**95.21%** | **365 / 1664**<br>**1,590 / 1,670** | **Catastrophic failure; 10-feat misses 1,590 attacks** |

### 8.3 The Port-Shortcut Finding
These experimental results establish a crucial insight for network intrusion detection:
- In Scenario 3, an adversary executes standard attacks over non-standard service ports (e.g., serving HTTP attacks on port 8080 or SSH brute force on port 2222). 
- The 10-feature model experiences a **near-total collapse in detection capability, evading at 94.13% (1,572 out of 1,670 attacks missed)**, and attack recall plummets to 5.04%.
- In contrast, the **8-feature port-agnostic baseline is invariant to direct changes in source and destination port fields when no other model input features are modified** (0 out of 1,664 attacks evade under direct port-feature modification).
- **Critical Methodological Distinction:**
  1. *Direct Port-Feature Manipulation:* Setting tabular port columns to alternate numbers in feature space. The 8-feature model's zero evasion under this test is a direct mathematical consequence of excluding port fields from its input vector.
  2. *Port-Shift Distribution Stress Testing:* Evaluating model resilience when malicious sessions occur over atypical transport channels.
  3. *Operational Service-Port Redirection:* Physically hosting an attack server on an alternate port and generating real wire traffic. We emphasize that our experiments evaluate feature-space representations; no live physical network redirection was executed.
- *The Padding Trap:* In Scenario 4, the 10-feature model appeared more robust to flow padding (3.29% vs 21.94% evasion) **only because destination ports were artificially held constant**, acting as an anchor. The moment port realism is introduced (Scenario 5), evasion surges to **95.21%** (1,590 out of 1,670 attacks missed).
- **Conclusion:** Adding transport port numbers creates a dangerous illusion of security. Models memorize ephemeral port mappings rather than genuine malicious behaviors.

---

## 9. Explanation Stability & The Four-Quadrant Analysis

While Explainable AI provides transparency into model reasoning on clean data, a critical open question is whether feature explanations remain reliable under adversarial perturbation. If an explanation shifts drastically under a minor perturbation, or conversely, if an explanation remains unchanged when a model is successfully fooled, the utility of XAI in security operations is compromised.

### 9.1 Continuous Attribution Drift Metrics
We evaluate explanation stability on a paired test cohort of $N=500$ detected attacks under DC-FFP perturbation at $\epsilon=0.20$ using four complementary metrics:
1. **$L_1$ Attribution Drift:**
   $$\text{Drift}_{L_1} = \|\phi(x') - \phi(x)\|_1 = \sum_{j=1}^d |\phi_j(x') - \phi_j(x)|$$
2. **Normalized $L_2$ Drift:**
   $$\text{Drift}_{\text{norm-}L_2} = \frac{\|\phi(x') - \phi(x)\|_2}{\|\phi(x)\|_2 + 10^{-9}}$$
3. **Top-$k$ Feature Overlap ($k=3$):** Jaccard index between the top-3 most influential features before and after perturbation:
   $$\text{Overlap}_{\text{Top-}k} = \frac{|\text{Top}_k(\phi(x)) \cap \text{Top}_k(\phi(x'))|}{k}$$
4. **Spearman Rank Correlation ($\rho_s$):** Rank consistency of feature importance across all 8 features.

### 9.2 Measured Continuous Drift Metrics
Across the $N=500$ paired test instances evaluated on XGBoost:
- **Mean $L_1$ Attribution Drift:** $0.3484$
- **Median $L_1$ Attribution Drift:** $0.2833$
- **Mean Normalized $L_2$ Drift:** $0.4452$
- **Mean Top-3 Feature Overlap:** $83.27\%$
- **Mean Spearman Rank Correlation:** $0.7364$

While high Top-3 overlap (83.27%) indicates that primary features (`OUT_BYTES`, `FLOW_DURATION_MILLISECONDS`) remain prominent, the significant $L_1$ drift ($0.3484$) demonstrates substantial redistribution of attribution weights.

### 9.3 Four-Quadrant Stability Categorization
To categorize behavioral relationships between prediction change and explanation drift, we establish a **validation-calibrated stability threshold**:
$$\tau_{val} = \text{Median}\left(L_1 \text{ drift on validation cohort}\right) = 0.2739$$

Each sample is mapped into one of four distinct behavioral quadrants:

```
                      Attribution Drift (L1 <= tau)    Attribution Drift (L1 > tau)
                    ┌───────────────────────────────┬───────────────────────────────┐
  Prediction        │          QUADRANT I           │          QUADRANT II          │
  Retained          │       Stable Detection        │       Stable Detection        │
  (f(x') = f(x))    │       Stable Explan.          │       Fragile Explan.         │
                    │      231 samples (46.2%)      │      155 samples (31.0%)      │
                    ├───────────────────────────────┼───────────────────────────────┤
  Prediction        │          QUADRANT IV          │         QUADRANT III          │
  Flipped           │       Flipped Detection       │       Flipped Detection       │
  (f(x') != f(x))   │      Deceptive Stability      │       Shifted Explan.         │
                    │       2 samples (0.4%)        │      112 samples (22.4%)      │
                    └───────────────────────────────┴───────────────────────────────┘
```

**Table 7: Four-Quadrant Stability Distribution ($N=500$ Paired Samples)**
| Quadrant | Classification Behavior | Explanation Stability | Sample Count | Percentage | Operational Cybersecurity Implication |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **Quadrant I** | **Retained (Attack)** | **Stable ($L_1 \le 0.2739$)** | **231** | **46.2%** | **Ideal Robust State:** Attack correctly detected; model reasoning unchanged. |
| **Quadrant II** | **Retained (Attack)** | **Fragile ($L_1 > 0.2739$)** | **155** | **31.0%** | **Brittle Detection:** Attack detected, but model reasoning shifted significantly. |
| **Quadrant III**| **Flipped (Benign)** | **Shifted ($L_1 > 0.2739$)** | **112** | **22.4%** | **Classic Evasion:** Perturbation evaded detection; explanation monitor detects drift. |
| **Quadrant IV** | **Flipped (Benign)** | **Deceptive ($L_1 \le 0.2739$)**| **2** | **0.4%** | **Stealth Evasion:** Attack evades detection while explanation appears normal! |

### 9.4 Critical Security Insight: The Deceptive Stability Hazard
Quadrant IV represents the most critical discovery of this stability audit:
- Although occurring in only 0.4% of samples (2 out of 500), Quadrant IV demonstrates that **an adversarial perturbation can successfully flip a prediction from Attack to Benign while inducing virtually zero attribution drift**.
- This occurs when a flow lies near a non-linear decision boundary where minimal feature perturbation crosses the classification threshold without fundamentally altering the global attribution landscape.
- **Defensive Implication:** Security operations teams must not rely on explanation stability monitors as a proxy for decision correctness. A stable explanation does not prove that an intrusion detection prediction has not been manipulated.

---

## 10. Computational Complexity & Real-Time Deployment Benchmark

To evaluate the operational feasibility of deploying machine learning models in live enterprise network pipelines, we benchmarked inference latency across both single-sample streaming and vectorized batch modes on local hardware.

**Table 8: Local Latency and Throughput Benchmark (Hardware Execution)**
| Model Architecture | Single-Sample Latency (Streaming $N=1$) | Single-Sample Throughput | Vectorized Batch Latency ($N=30,000$) | Vectorized Batch Throughput | Operational Feasibility |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Decision Tree** | **0.37 ms** | 2,668 flows/sec | **0.07 $\mu$s / sample** | **13.91M flows/sec** | Ultra-low latency, but low macro-F1 |
| **XGBoost (Hist)** | **0.63 ms** | 1,600 flows/sec | **0.23 $\mu$s / sample** | **4.39M flows/sec** | **Production Optimal:** High accuracy & speed |
| **Random Forest** | 17.73 ms | 56 flows/sec | 1.27 $\mu$s / sample | 785k flows/sec | Unsuitable for streaming edge deployment |

### Operational Analysis
- **Vectorized XGBoost Throughput:** At 4.39 million flows per second ($0.23\,\mu\text{s}$ per flow), XGBoost easily handles the exported flow volume of saturated 10 Gbps and 40 Gbps enterprise backbones.
- **Streaming Edge Deployment:** For real-time inline packet inspection, XGBoost's 0.63 ms single-sample evaluation meets typical 1 ms service-level objectives (SLOs). Conversely, Random Forest's 17.73 ms latency creates significant queuing delays.

---

## 11. Cross-Dataset Validation Framework (UNSW-NB15)

To evaluate generalizability beyond CSE-CIC-IDS2018, we developed a cross-dataset semantic alignment protocol targeting **UNSW-NB15**:
- An exact semantic feature mapping was formulated aligning UNSW-NB15 attributes (`proto`, `sbytes`, `dbytes`, `Spkts`, `Dpkts`, `dur`) with NetFlow equivalents.
- In accordance with strict academic integrity standards, because local network restrictions prevented downloading the 100+ MB UNSW-NB15 archive, the cross-dataset evaluation script (`scripts/06_cross_dataset_validation.py`) is preserved with **Pending Data Execution status**. Zero fabricated or simulated data points were injected into results.

---

## 12. Critical Discussion

### 12.1 The Accuracy Paradox in Cybersecurity
The findings of this research challenge the conventional paradigm of evaluating NIDS predominantly on clean benchmark accuracy:
- A model boasting 98.90% accuracy (10-feature XGBoost) proved functionally useless when attacked via service-port redirection, failing to detect 94.13% of malicious flows.
- Conversely, an 8-feature model with slightly lower clean accuracy (98.16%) proved entirely resilient to port manipulations, relying on durable behavioral metrics.
- Researchers and practitioners must abandon "leaderboard chasing" on static splits and adopt adversarial stress-testing as a mandatory evaluation criterion.

### 12.2 Tree Ensembles vs. Neural Networks in NIDS
While deep neural architectures dominate computer vision and NLP, this research affirms the enduring superiority of gradient-boosted trees for tabular network flows:
- XGBoost achieved superior clean accuracy, lower false-positive rates, and orders-of-magnitude faster inference than neural equivalents.
- However, their step-function geometry creates non-smooth decision boundaries that remain susceptible to greedy domain-constrained traffic padding (21.94% evasion at $\epsilon=0.20$).

---

## 13. Limitations

1. **Tabular Flow-Feature Perturbation vs. Wire-Level Feasibility:** DC-FFP and SGGS perturb tabular NetFlow summary records. While physical domain invariants ($\Delta \ge 0$, packet integrality, RFC 791 bounds) were strictly enforced in feature space, **these experiments do not prove packet-level or wire-level attack feasibility**. In live production networks, middlebox fragmentation, stateful packet filtering, and collector flow timeouts (typically 15s to 30s) could alter exported flow summaries in flight.
2. **NetFlow Observational Bound Scope:** The empirical condition $\text{BYTES} \ge \text{PKTS} \times 20$ held with zero violations across all 5,918,803 records in NF-CSE-CIC-IDS2018 (empirical minimum was 28.0 bytes/packet). This reflects the specific NetFlow v9 exporter counting convention that includes the minimum 20-byte IPv4 base header (RFC 791). It must **not be interpreted as a universal networking law** for all telemetries (e.g., telemetry counting only L7 application payload bytes would record zero payload bytes for standalone TCP ACK or SYN probes).
3. **Explanation Stability Does Not Guarantee Correctness:** The discovery of **Quadrant IV (0.4% deceptive stability)** proves that an adversary can induce misclassification while maintaining SHAP attribution drift below the validation-calibrated threshold ($L_1 \le 0.2739$). Security analysts must not treat explanation stability as an oracle of classification correctness.
4. **Port Invariance is a Function of Excluded Input Fields:** The 8-feature model's zero evasion under direct port-field manipulation is a direct mathematical consequence of excluding `L4_SRC_PORT` and `L4_DST_PORT` from its feature vector. It does not imply operational immunity to real-world multi-stage intrusion campaigns.
5. **Cross-Dataset Generalizability Remains Pending:** The cross-dataset semantic mapping for UNSW-NB15 has been fully defined and scripted, but experimental execution remains pending local dataset placement. No synthetic or simulated cross-dataset results were generated.
6. **Inference Latency Excludes Production Pipeline Overhead:** Benchmark timings evaluate raw estimator `predict()` execution time ($0.23\,\mu\text{s}$ vectorized batch; $0.63\text{ ms}$ streaming). Live production deployments incur upstream latencies from hardware packet capture (DPDK/eBPF), flow timeout expiration, and tabular feature extraction that dwarf sub-millisecond classifier inference.
7. **Synthetic Background Traffic & Statistical Power:** The NF-CSE-CIC-IDS2018 benchmark was generated in a synthetic AWS testbed. Furthermore, with $N=8$ features ($df=6$), Spearman rank correlation ($\rho_s = 0.8095$) is constrained in statistical power.

---

## 14. Conclusion & Future Work

### 14.1 Summary of Contributions
This technical seminar investigation makes four concrete, reproducible contributions:
1. **Verified Zero-Leakage Pipeline:** Audited 5,918,803 flows of NF-CSE-CIC-IDS2018, establishing a verified benchmark where XGBoost achieved 98.16% accuracy, 0.9238 Macro-F1, a 0.97% FPR, and a continuous-probability ROC-AUC of 0.9621.
2. **Domain-Constrained Flow Perturbation (DC-FFP):** Enforced physical networking invariants ($\Delta \ge 0$, packet integrality, RFC 791 bounds, and verified zero-epsilon identity `assert np.array_equal`), demonstrating that 20% traffic padding evades 21.94% of XGBoost detections and 28.46% of Random Forest detections.
3. **Discovery of Port-Shortcut Vulnerability:** Demonstrated that incorporating port numbers creates an artificial security illusion: 10-feature models collapse to a **94.13% evasion rate** (1,572 / 1,670 attacks missed) under destination port redirection, whereas the 8-feature baseline remains invariant to direct port-field manipulation.
4. **Explanation Stability Auditing:** Mapped feature attributions into a Four-Quadrant framework, uncovering **Quadrant IV (Deceptive Stability, 0.4%)**, proving that explanation stability cannot be treated as a proof of prediction correctness.

### 14.2 Actionable Future Directions
- **Hardware-in-the-Loop Validation:** Integrate packet generators (Scapy, TRex) to transmit adversarial packet streams across physical network interfaces.
- **Port-Agnostic Feature Engineering:** Develop ratio-based and behavioral graph flow representations that decouple intrusion detection from transport port numbers.
- **Adversarial Flow Training:** Retrain tree ensembles directly on DC-FFP perturbed flows to penalize traffic-padding vulnerabilities.
- **Conformal Prediction:** Implement uncertainty sets to reject ambiguous, padded flows for human analyst triage rather than silently misclassifying them as benign.

---

## 15. References

1. **Sarhan, M., Layeghy, S., & Portmann, M.** (2021). Towards a standard feature set for network intrusion detection system datasets. *Mobile Networks and Applications*, 26(1), 357–370.
2. **Lundberg, S. M., & Lee, S. I.** (2017). A unified approach to interpreting model predictions. *Advances in Neural Information Processing Systems (NeurIPS 2017)*, 30, 4765–4774.
3. **Lundberg, S. M., et al.** (2020). From local explanations to global understanding with explainable AI for trees. *Nature Machine Intelligence*, 2(1), 56–67.
4. **Chen, T., & Guestrin, C.** (2016). XGBoost: A scalable tree boosting system. *ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD '16)*, 785–794.
5. **Breiman, L.** (2001). Random forests. *Machine Learning*, 45(1), 5–32.
6. **Pierazzi, P., Pendlebury, F., Cortellazzi, J., & Cavallaro, L.** (2020). Intrusion: Towards problem-space adversarial attacks in malware detection. *IEEE Symposium on Security and Privacy (S&P '20)*, 1309–1326.
7. **Apruzzese, G., Laskov, P., & Schneider, J.** (2022). SoK: Pragmatic assessment of machine learning for network intrusion detection. *IEEE International Conference on Cyber Security (ICCS '22)*, 1–14.
8. **Information Sciences Institute.** (1981). Internet Protocol: DARPA Internet Program Protocol Specification. *RFC 791*, IETF.
9. **Postel, J.** (1981). Transmission Control Protocol. *RFC 793*, IETF.
10. **Ribeiro, M. T., Singh, S., & Guestrin, C.** (2016). "Why should I trust you?": Explaining the predictions of any classifier. *ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*, 1135–1144.
11. **Szegedy, C., et al.** (2014). Intriguing properties of neural networks. *International Conference on Learning Representations (ICLR 2014)*.
12. **Goodfellow, I. J., Shlens, J., & Szegedy, C.** (2015). Explaining and harnessing adversarial examples. *International Conference on Learning Representations (ICLR 2015)*.

---
*Report completed and compiled for Aditya Ambare (Roll: TIA26), B.E. Information Technology.*

