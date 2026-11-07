# Phase 6 Research Report: Explanation Stability Under Adversarial Perturbations

**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Status:** Experimental Evaluation Completed

---

## 1. Executive Summary: The Link Between Robustness and Explainability

To assess explanation stability, paired SHAP values $\phi(x)$ and $\phi(x')$ were computed for malicious network flows subjected to domain-constrained perturbation at budget $\epsilon = 0.20$.

## 2. Quantitative Stability Metrics

| Metric | Mean | Median | Standard Deviation | Research Interpretation |

|---|---|---|---|---|

| **$L_1$ Attribution Drift** | 0.3484 | 0.2833 | 0.2439 | Average absolute change in feature log-odds attributions |
| **Normalized $L_2$ Drift** | 0.5456 | 0.5597 | 0.3639 | Relative magnitude change relative to clean explanation norm |
| **Top-3 Feature Overlap** | 0.8327 | 1.0000 | 0.1770 | Fraction of top 3 most influential features retained |
| **Spearman Rank Correlation ($ho_s$)** | 0.7364 | 0.8810 | 0.2425 | Consistency of relative feature ranking order |
| **Perturbation Evasion Rate** | 22.80% | - | - | Percentage of attacks successfully evading detection |


## 3. Four-Quadrant Behavioral Analysis (Prediction vs. Explanation)

- **Q1: Prediction Stable, Explanation Stable:** `248` samples (49.6%)
- **Q2: Prediction Stable, Explanation Fragile:** `138` samples (27.6%)
- **Q3: Prediction Flipped, Explanation Shifted:** `112` samples (22.4%)
- **Q4: Prediction Flipped, Explanation Deceptive:** `2` samples (0.4%)


### Quadrant Definitions:

- **Quadrant I (Stable Detection):** Prediction remains Attack, and SHAP feature ranking remains stable. The system maintains dependable security and explanation fidelity.
- **Quadrant II (Fragile Explanation):** Prediction remains Attack, but SHAP feature attributions shift dramatically. The prediction is correct, but the rationale is unstable under flow variation.
- **Quadrant III (Reflective Shift):** Prediction flips to Benign (evasion succeeded), and SHAP attribution shifts accordingly, capturing the altered decision pathway.
- **Quadrant IV (Deceptive Stability):** Prediction flips to Benign (evasion succeeded), but top feature attributions appear superficially similar to clean profiles, misleading human analysts.

## 4. Scientific Caveats: Limitations of SHAP as a Security Indicator

> [!WARNING]

> A stable SHAP explanation **does not guarantee security correctness**. If an adversary crafts a perturbation that causes a model to misclassify an attack while preserving feature attribution rank order (Quadrant IV), relying solely on explanation stability as a trust metric would create a dangerous false sense of security. Robustness must be evaluated jointly across decision boundaries and attribution spaces.
