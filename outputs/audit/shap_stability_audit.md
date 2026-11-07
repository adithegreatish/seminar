# Explainable AI (SHAP) & Explanation Stability Audit

**Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Auditor:** Independent Research Auditor & Cybersecurity Methodology Reviewer  
**Audit Date:** November 2026  
**Audit Status:** AUDITED & SCIENTIFICALLY RECONCILED  

---

## 1. Executive Summary & Audit Scope
This audit reviews the technical implementation, mathematical rigor, and security interpretation of Explainable AI (SHAP) in `src/explainability/shap_explainer.py`, `src/evaluation/stability.py`, and `scripts/04_explanation_stability.py`.

---

## 2. TreeExplainer Configuration & Output Space Analysis

### 2.1 XGBoost Binary Classifier: Log-Odds (Margin) Space
- **Configuration:** `shap.TreeExplainer(xgb_model.estimator)`
- **Output Space:** Evaluates attributions in **raw log-odds (margin) space** before the logistic sigmoid link function.
- **Base Value:** $\mathbb{E}[f(x)] = 0.0$ (representing the neutral decision boundary threshold in logit space).
- **Additive Efficiency Property:** For any input flow $x$,
  $$\sum_{j=1}^d \phi_j(x) + \phi_0 = \text{logit}(\mathcal{P}(\text{Attack} \mid x))$$
  Positive $\phi_j(x)$ indicates that feature $j$ increases the log-odds of an attack; negative $\phi_j(x)$ pushes the decision toward benign traffic.

### 2.2 Random Forest Classifier: Probability Space
- **Configuration:** `shap.TreeExplainer(rf_model.estimator)`
- **Output Space:** Evaluates attributions in **probability space** $\in [0, 1]$.
- **Base Value:** $\mathbb{E}[f(x)] = 0.50$ (reflecting the training set class prior under balanced weights).
- **Critical Cross-Model Auditor Note:**
  Because XGBoost outputs in log-odds ($\mathbb{R}$) while Random Forest outputs in probability fractions ($[0, 1]$), **raw SHAP values cannot be directly compared across model families by magnitude**. However, computing **feature attribution rankings** is invariant to monotonic output scaling and enables valid cross-model comparison.

---

## 3. Mathematical Formulation of Explanation Stability Metrics

Given a clean flow $x$ with attributions $\phi(x) \in \mathbb{R}^d$ and a perturbed flow $x'$ with attributions $\phi(x') \in \mathbb{R}^d$:

### 3.1 Mean Absolute Attribution Drift ($L_1$ Drift)
$$L_1(\phi, \phi') = \frac{1}{d} \sum_{j=1}^d |\phi_j(x) - \phi_j(x')|$$
Measures the average unscaled displacement in feature log-odds attributions across the $d=8$ baseline features.
- **Audited Empirical Values ($N=500$ paired samples at $\epsilon=0.20$):**
  - Mean: **0.3484** | Median: **0.2833** | Std Dev: **0.2442** | Range: $[0.0462, 0.9238]$

### 3.2 Normalized Attribution Drift ($L_2$ Drift)
$$\text{Norm-}L_2(\phi, \phi') = \frac{\|\phi(x) - \phi(x')\|_2}{\|\phi(x)\|_2 + \epsilon_0}$$
where $\epsilon_0 = 10^{-6}$ prevents division by zero. Measures attribution shift relative to the clean explanation's norm.
- **Audited Empirical Values:**
  - Mean: **0.5456** | Median: **0.5597** | Std Dev: **0.3642** | Range: $[0.0496, 1.8637]$

### 3.3 Top-$k$ Feature Set Overlap (Jaccard Index at $k=3$)
$$J_k(x, x') = \frac{|\text{TopK}(\phi(x)) \cap \text{TopK}(\phi(x'))|}{k}$$
where $\text{TopK}(\phi)$ denotes the indices of the $k=3$ features with the largest absolute SHAP magnitudes $|\phi_j|$.
- **Audited Empirical Values:**
  - Mean: **83.27%** | Median: **100.00%** | Std Dev: **17.72%**
  - 58.6% of samples retained all 3 top features (100% overlap); 32.8% retained 2 features (66.7% overlap); 8.6% retained 1 feature (33.3% overlap).

### 3.4 Spearman Feature-Ranking Correlation ($\rho_s$)
$$\rho_s = 1 - \frac{6 \sum_{j=1}^d (R(\phi_j(x)) - R(\phi_j(x')))^2}{d(d^2 - 1)}$$
Measures whether the relative hierarchy of feature influence is preserved under perturbation.
- **Audited Empirical Values:**
  - Mean: **0.7364** | Median: **0.8810** | Std Dev: **0.2427**

---

## 4. Four-Quadrant Behavioral Analysis Audit

The four-quadrant framework categorizes model behavior under adversarial perturbation along two orthogonal axes:
1. **Prediction Shift Axis:** Did the model's classification flip from Attack ($\hat{y}=1$) to Benign ($\hat{y}=0$)?
2. **Explanation Shift Axis:** Did the attribution drift $L_1$ exceed the non-parametric threshold $\tau$?

### 4.1 Threshold Justification
- Threshold $\tau$ was set to the **median $L_1$ drift** across the paired evaluation cohort ($\tau = 0.2833$).
- Using the median provides an objective, data-driven partition dividing lower 50% attribution shifts from upper 50% attribution shifts without arbitrary hyperparameter tuning.

### 4.2 Mutually Exclusive Partition Verification ($N=500$ Paired Attacks at $\epsilon=0.20$)

| Quadrant | Prediction Behavior | Explanation Behavior | Sample Count | Percentage | Research Description |
|---|---|---|---|---|---|
| **Quadrant I** | Attack Maintained ($\hat{y}=1$) | Stable Explanation ($L_1 < 0.2833$) | **248** | **49.6%** | **Robust Detection & Consistent Attribution** |
| **Quadrant II** | Attack Maintained ($\hat{y}=1$) | Drifted Explanation ($L_1 \ge 0.2833$) | **138** | **27.6%** | **Detection Maintained, Explanatory Rationale Fragile** |
| **Quadrant III** | Prediction Flipped to Benign ($\hat{y}=0$) | Drifted Explanation ($L_1 \ge 0.2833$) | **112** | **22.4%** | **Evasion Successful, Attribution Shift Reflects Evasion** |
| **Quadrant IV** | Prediction Flipped to Benign ($\hat{y}=0$) | Stable Explanation ($L_1 < 0.2833$) | **2** | **0.4%** | **Evasion Successful, Deceptively Stable Attribution** |
| **Total** | - | - | **500** | **100.0%** | **Mathematically Exhaustive & Mutually Exclusive** |

### 4.3 Auditor Revision of Terminology
- Earlier drafts used the term *"reliable security"* to describe Quadrant I. 
- **Audited Correction:** The term has been updated to **"Robust Detection & Consistent Attribution"**. In adversarial cybersecurity, no machine learning system can claim absolute "security"; it can only demonstrate bounded empirical empirical invariance.

### 4.4 The Critical Danger of Quadrant IV (Deceptive Stability)
> [!WARNING]
> **Core Finding for Seminar Defense:**
> Quadrant IV comprises flows where the adversarial attack successfully fooled the classifier into predicting Benign, yet the top-ranked features and attribution patterns remained superficially similar to the clean attack flow.
> 
> If a Security Operations Center (SOC) analyst or automated trust score relied solely on "explanation stability" to verify alert confidence, Quadrant IV flows would pass undetected. **Explanation stability does not prove prediction correctness.**

---

## 5. Statistical Power Audit of Cross-Model Spearman Correlation

In Section 8 of Phase 4, a Spearman rank correlation of $\rho_s = 0.8095$ ($p = 0.0149$) was reported between XGBoost and Random Forest feature importances.

### Auditor Statistical Review:
1. **Sample Size:** The correlation was calculated over the $d=8$ baseline features.
2. **Degrees of Freedom:** $df = d - 2 = 6$.
3. **Statistical Power Limitation:**
   While $\rho_s = 0.8095$ with $p = 0.0149$ is nominally statistically significant at $\alpha = 0.05$, a sample of only 8 points has low statistical power. A single rank swap (e.g., between `IN_BYTES` and `IN_PKTS`) significantly alters the correlation coefficient.
4. **Mandated Clarification:**
   In your seminar report and presentation, **do not present this as statistical proof of global model equivalence**. Present it as: *"Empirical evidence that both tree ensembles identify the same four primary flow attributes (`OUT_BYTES`, `FLOW_DURATION`, `IN_BYTES`, `IN_PKTS`) as dominant decision drivers."*

