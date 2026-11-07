# Phase 7 Research Report: Comparative Evaluation & Feature Ablation Study

**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Status:** Comprehensive Synthesis Completed

---

## 1. Master Model Comparison (Clean vs Adversarial vs Efficiency)

| Model | Features | Clean Acc | Macro-F1 | Attack Recall | FPR | ROC-AUC | Evasion Rate ($\epsilon=0.20$) | Train Time (s) | Inference (ms/sample) |

|---|---|---|---|---|---|---|---|---|---|

| **Decision Tree** | Baseline (8 features) | 97.13% | 0.8901 | 0.8597 | 0.0209 | 0.9506 | 21.40% | 0.24s | 0.0001 ms |
| **Random Forest** | Baseline (8 features) | 97.79% | 0.9113 | 0.8577 | 0.0137 | 0.9574 | 28.46% | 1.39s | 0.0015 ms |
| **XGBoost** | Baseline (8 features) | 98.16% | 0.9238 | 0.8551 | 0.0097 | 0.9621 | 21.94% | 0.36s | 0.0003 ms |


## 2. Port Feature Ablation Study Findings

A documented research concern in NIDS literature is whether transport layer port numbers (`L4_SRC_PORT`, `L4_DST_PORT`) introduce ephemeral port memorization or enhance flow discrimination.

| Model Configuration | Features Used | Accuracy | Macro-F1 | Attack Recall | FPR | Evasion Rate ($\epsilon=0.20$) |

|---|---|---|---|---|---|---|

| **Random Forest** | Baseline Excluded (8 features) | 97.79% | 0.9113 | 0.8577 | 0.0137 | 28.46% |
| **XGBoost** | Baseline Excluded (8 features) | 98.16% | 0.9238 | 0.8551 | 0.0097 | 21.94% |
| **Random Forest (10 feats)** | Ports Included (10 features) | 98.89% | 0.9519 | 0.8597 | 0.0021 | 1.85% |
| **XGBoost (10 feats)** | Ports Included (10 features) | 98.90% | 0.9521 | 0.8582 | 0.0019 | 3.29% |


### Ablation Insights:

1. **Accuracy Gain vs Evasion Risk:** Including transport port numbers yields a slight gain in clean accuracy and macro-F1, as well-known ports (80, 443, 21, 22) provide strong static priors for certain attack vectors (e.g. FTP/SSH brute force).

2. **Vulnerability to Port Spoofing:** Because adversaries can easily randomize client source ports or redirect services to non-standard ports, port-inclusive models risk relying on brittle shortcuts rather than intrinsic flow geometry.

## 3. Scientific Reproducibility Record

- **Primary Dataset:** `NF-CSE-CIC-IDS2018` (Rows: `5,918,803`)
- **Dataset SHA-256:** `3f698d6f8c1673afcc77262d98d8433bdf419ee31f567eb026518c5a074e2bdf`
- **Platform:** `Windows-11-10.0.26300-SP0` | **Python:** `3.12.10`
- **Key Libraries:** `numpy=2.2.6`, `scikit-learn=1.9.1`, `xgboost=3.4.1`, `shap=0.49.1`
- **Global Random Seed:** `42`
