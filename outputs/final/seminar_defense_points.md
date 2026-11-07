# Seminar Defense Executive Cheat Sheet & Viva Voce Guide

**Project Title:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll Number: TIA26)  
**Academic Target:** Third Year B.E. Information Technology Technical Seminar  
**Department:** Information Technology  
**Date:** November 2026  

---

## 1. Executive Research Elevator Pitch (30-Second Summary)

> *"Good morning, respected committee members. My research investigates whether machine learning models for Network Intrusion Detection remain dependable when subjected to controlled adversarial perturbations, and whether their explanations remain stable when predictions fail.*  
> *Using the 5.9-million flow NF-CSE-CIC-IDS2018 benchmark, we evaluate Decision Trees, Random Forests, and XGBoost under zero-leakage conditions. We introduce Domain-Constrained Flow-Feature Perturbation (DC-FFP) enforcing physical networking laws, explain model decisions with exact SHAP TreeExplainer values, uncover a severe port-shortcut vulnerability (94.13% evasion under a tabular destination-port feature-shift stress test), and demonstrate through a Four-Quadrant analysis that explanation stability does not guarantee classification security."*

---

## 2. Key Authoritative Metrics Summary Table

Keep these exact verified numbers in mind during questioning (Note: QGGS was formerly referenced as SGGS in preliminary notes):

| Metric / Experiment | Decision Tree | Random Forest | XGBoost (Top Model) |
| :--- | :---: | :---: | :---: |
| **Clean Accuracy (Test $N=30,000$)** | 97.13% | 97.79% | **98.16%** |
| **Clean Macro-F1 (Test)** | 0.8901 | 0.9113 | **0.9238** |
| **Clean Attack Recall** | 85.97% | 85.77% | **85.51%** |
| **Clean False Positive Rate (FPR)** | 2.09% | 1.37% | **0.97%** |
| **Clean ROC-AUC (from continuous probabilities)** | **0.9506** | **0.9574** | **0.9621** |
| *Clean Balanced Accuracy (hard predictions)* | *0.9194* | *0.9220* | *0.9227* |
| **Clean Multiclass Accuracy / Macro-F1** | 61.10% / 0.5432 | 73.34% / 0.5838 | 65.27% / 0.5694 |
| **Evasion Rate at $\epsilon = 0.05$ (DC-FFP)** | 10.34% (173/1673) | 11.62% (194/1669) | **0.66%** (11/1664) |
| **Evasion Rate at $\epsilon = 0.20$ (DC-FFP)** | 21.40% (358/1673) | 28.46% (475/1669) | **21.94%** (365/1664) |
| **Evasion Rate at $\epsilon = 0.50$ (DC-FFP)** | 34.43% (576/1673) | 40.50% (676/1669) | **33.83%** (563/1664) |
| **QGGS Evasion (Config A: Audited 16-Query Benchmark)**| — | — | **6.00%** (6/100, 15.9 avg, max 16 queries) |
| **QGGS Evasion (Config B: Multi-Step Extended Search)**| — | — | **60.00%** (60/100, 27.6 avg, max 46 queries) |
| **Inference Latency (Single Sample Streaming)** | 0.37 ms | 17.73 ms | **0.63 ms** |
| **Inference Throughput (Vectorized Batch)** | 13.9M flows/sec | 785k flows/sec | **4.39M flows/sec** |

---

## 3. Top 10 High-Probability Examiner Questions & Rebuttals

### Q1: Why did you exclude Source and Destination Ports from your baseline model if adding them improves clean accuracy from 98.16% to 98.90%?
**Rebuttal:**
> *"Adding transport ports creates a severe **port-shortcut vulnerability**. In our feature ablation study, the 10-feature XGBoost model relied heavily on destination port (`L4_DST_PORT` accounted for 24.30% of total split gain), associating specific ports like 80 or 21 directly with attacks.*  
> *A tabular destination-port feature-shift stress test produced 1,572 evasions among 1,670 initially detected attacks (**94.13% evasion rate**). Explicitly, no live network traffic redirection or packet-level attack was performed; the test evaluates model behavior when service port numbers are modified in the feature table. In contrast, our 8-feature baseline model is **invariant to direct changes in source and destination port fields when no other model input features are modified** (0 out of 1,664 attacks missed under direct port-field manipulation).*  
> *We explicitly distinguish between direct tabular port-feature manipulation, distribution stress testing, and live operational network redirection. Clean accuracy increases with ports, but real-world resilience collapses."*

### Q2: What is the physical justification for your adversarial perturbation? Can an attacker really modify these features on a real network?
**Rebuttal:**
> *"Unlike computer vision where noise is added bidirectionally ($\pm \epsilon$) to image pixels, network traffic is governed by physical protocol laws. Our attack is titled **Domain-Constrained Flow-Feature Perturbation (DC-FFP)**. We enforce four strict invariants:*  
> 1. *$\Delta \ge 0$ (Monotonic Non-Decreasing): An attacker can inject dummy packets or pad payloads, but cannot physically delete packets or bytes that have already crossed the wire.*  
> 2. *Packet Count Integrality: Added packets must be whole integers ($\Delta_{\text{PKTS}} \in \mathbb{Z}_{\ge 0}$ when $\epsilon > 0$).*  
> 3. *Protocol Preservation: L4 Protocol and TCP flags are immutable during flow padding.*  
> 4. *Observational NetFlow Bound: $\text{BYTES} \ge \text{PKTS} \times 20$, grounded in RFC 791 (IPv4 minimum 20-byte base header), which we verified had **zero violations across all 5,918,803 flows**.*  
> 5. *Zero-Epsilon Identity: At $\epsilon = 0.00$, the perturbation reduces to an exact identity transformation, passing `assert np.array_equal(original, perturbed_at_epsilon_zero)` on all 30,000 test flows.*  
> *We explicitly note in our limitations that this is a feature-space flow perturbation; real-world deployment requires verifying physical packet transmission using tools like Scapy or TRex."*

### Q3: How does your DC-FFP attack differ from standard FGSM or PGD attacks?
**Rebuttal:**
> *"FGSM and PGD are gradient-based attacks developed for differentiable neural networks. Decision trees and tree ensembles (Random Forest, XGBoost) are step functions with non-differentiable decision boundaries where input gradients are zero almost everywhere, rendering standard FGSM/PGD mathematically undefined.*  
> *Furthermore, FGSM/PGD apply continuous bidirectional perturbations ($x \pm \epsilon$) that produce physically impossible network states (e.g., negative byte counts or 3.7 packets). DC-FFP is a black-box, domain-constrained perturbation designed specifically for tree ensembles and tabular network flows."*

### Q4: Explain the difference between SHAP TreeExplainer values in XGBoost versus Random Forest.
**Rebuttal:**
> *"TreeExplainer calculates exact game-theoretic Shapley values, but their output spaces differ:*  
> - *In **XGBoost**, SHAP values are computed in **log-odds (raw margin) space** before the sigmoid activation. Features with positive values push the log-odds toward attack, and negative values push toward benign. The sum of SHAP values plus the base score exactly equals the model's raw output margin.*  
> - *In **Random Forest**, SHAP values are computed directly in **probability space** ($[0, 1]$).*  
> *Despite this mathematical difference, both models exhibit strong global agreement: both identify `OUT_BYTES` and `FLOW_DURATION_MILLISECONDS` as the top two attack drivers, achieving a cross-model Spearman rank correlation of $\rho_s = 0.8095$ ($p = 0.0149$)."*

### Q5: What is the Four-Quadrant analysis, and which quadrant is the most dangerous for cybersecurity?
**Rebuttal:**
> *"The Four-Quadrant analysis pairs clean attacks with their perturbed counterparts across two dimensions: prediction change (Retained vs. Flipped) and SHAP attribution drift relative to a validation-calibrated threshold ($\tau_{val} = 0.2739$):*  
> - **Q1 (46.2%):** Stable Detection & Stable Explanation (Robust).*  
> - **Q2 (31.0%):** Stable Detection & Fragile Explanation (Detected, but reasoning shifted).*  
> - **Q3 (22.4%):** Flipped Detection & Shifted Explanation (Classic evasion).*  
> - **Q4 (0.4%, 2 samples):** **Flipped Detection & Deceptive Stability (The most dangerous quadrant!)**.*  
> *In Quadrant IV, the model flips its prediction from Attack to Benign, but the SHAP explanation exhibits almost no drift ($L_1 \le \tau$). This proves that **explanation stability is NOT a proof of model correctness**; a model can be deceived without its explanation monitor alarming."*

### Q6: Why did you train on a 200,000 sample instead of the full 5.9 million records in NF-CSE-CIC-IDS2018?
**Rebuttal:**
> *"NF-CSE-CIC-IDS2018 contains 5,918,803 flows. First, we conducted a complete audit of the entire 5.9M dataset, confirming 0 missing values, 0 infinite values, 0 duplicate rows, and 0 physical constraint violations.*  
> *Training tree ensembles with 100 estimators and calculating exact TreeExplainer SHAP values on 5.9M records requires tens of gigabytes of RAM and several days of compute. A stratified sample of $N=200,000$ (140,000 training, 30,000 validation, 30,000 test) maintains exact class proportions (6.49% attack rate), yields statistical confidence intervals under $\pm 0.15\%$ for test accuracy, and ensures **100% reproducible local execution** on standard academic hardware."*

### Q7: Why is multiclass macro-F1 (~0.58) so much lower than binary macro-F1 (~0.92)?
**Rebuttal:**
> *"This is caused by **severe real-world class imbalance** across the 15 attack categories. In our 200,000-flow sample, categories like `DDoS attacks-LOIC-HTTP` have 38,000 samples, whereas `SQL Injection` has only 6 samples, `Infiltration` has 11, and `Brute Force -Web` has 23.*  
> *Because decision tree split criteria (Gini/Information Gain) optimize overall node purity, minority categories with only 6 instances are starved of dedicated splits. Macro-F1 weights all classes equally, meaning a failure on a 6-sample category penalizes the overall macro score heavily."*

### Q8: How did you prevent data leakage during preprocessing?
**Rebuttal:**
> *"We implemented a strict zero-leakage pipeline:*  
> 1. *We performed stratified splitting into Train (70%), Validation (15%), and Test (15%) **before any preprocessing occurred**.*  
> 2. *The median imputer and standard scaler were **fit strictly on the training partition only**.*  
> 3. *Validation and test sets were transformed using the frozen training parameters (`transform()`, never `fit_transform()`).*  
> 4. *This was formally audited in `data_leakage_audit.md` and verified by automated unit tests in `tests/test_preprocessing.py`."*

### Q9: What was the inconsistency between 0.9231 and 0.9171 in XGBoost validation Macro-F1, and how did you resolve it?
**Rebuttal:**
> *"During our Phase 9 experimental audit, we reconciled this exact inconsistency by inspecting saved metrics and model logs:*  
> - *The actual XGBoost **Validation Macro-F1 is 0.917064**.*  
> - *The XGBoost **Test Macro-F1 is 0.923828**.*  
> *An earlier draft narrative accidentally rounded and conflated the test score into the validation section. The discrepancy was formally documented and corrected in `metric_reconciliation.csv` with zero alteration to underlying experimental outputs."*

### Q10: How fast is your model, and can it handle high-speed 10 Gbps enterprise traffic?
**Rebuttal:**
> *"Algorithmic inference is extremely fast. On our local benchmark, vectorized XGBoost processes 30,000 flows in **$0.23\,\mu\text{s/sample}$**, achieving a throughput of **4.39 million flows per second**.*  
> *However, we emphasize in our seminar paper that raw model inference is not the true bottleneck. In a live network, end-to-end latency is dominated by packet buffering, flow timeout expiration (typically 15 to 30 seconds before a flow record is exported), and tabular preprocessing."*

---

## 4. Key Mathematical Formulations to Write on the Board

If asked to write equations on the blackboard or whiteboard, write these clearly:

1. **DC-FFP Transformation:**
   $$x'_j = x_j(1 + \epsilon) + \Delta_{\min}^{(j)}$$
   $$\text{where } \epsilon \in [0.0, 0.50], \quad \Delta_{\min} = 1 \text{ for packet counts}$$

2. **Physical Invariant Constraint:**
   $$\text{BYTES} \ge \text{PKTS} \times 20 \quad (\text{RFC 791 Minimum IPv4 Header})$$

3. **Evasion Rate (Conditioned on Clean Detection):**
   $$\text{Evasion Rate} = \frac{|\{i \in \mathcal{D}_{\text{mal}} \mid f(x_i) = 1 \land f(x'_i) = 0\}|}{|\{i \in \mathcal{D}_{\text{mal}} \mid f(x_i) = 1\}|}$$

4. **Normalized $L_2$ Attribution Drift:**
   $$\text{Drift}_{\text{norm-}L_2} = \frac{\|\phi(x') - \phi(x)\|_2}{\|\phi(x)\|_2 + \varepsilon}$$

5. **Spearman Rank Correlation:**
   $$\rho_s = 1 - \frac{6 \sum d_i^2}{N(N^2 - 1)}$$

---

## 5. Defense Strategy by Presentation Section

| Section | Strategic Emphasis for Aditya Ambare |
| :--- | :--- |
| **Problem Statement** | Do not just say "we made an accurate model." Emphasize that standard ML NIDS suffer from adversarial fragility and explainability blindness. |
| **Dataset & Audit** | Mention the 5.9M flow audit, 0 missing values, zero-leakage 70/15/15 split, and RFC 791 constraint validation. |
| **Model Selection** | Present Decision Tree (baseline), Random Forest (bagging), and XGBoost (boosting). XGBoost achieved the best balance (98.16% Acc, 0.9238 Macro-F1, 0.97% FPR). |
| **Explainability (SHAP)** | Emphasize exact Shapley values. Highlight that `OUT_BYTES` and `FLOW_DURATION_MILLISECONDS` drive detections across both models ($\rho_s = 0.8095$). |
| **Adversarial Robustness** | Highlight that at $\epsilon = 0.20$, evasion reaches 21.94% for XGBoost and 28.46% for RF. Explain why RF collapses faster than XGBoost. |
| **Port Ablation (Shortcut)** | This is your strongest novelty point! Explain that 10-feature models cheat on ports, collapsing to 94.13% evasion (1,572/1,670 attacks missed) under a tabular destination-port feature-shift stress test, while the 8-feature baseline is invariant to direct port manipulation. |
| **Explanation Stability** | Present the 4-Quadrant analysis. Warn the committee about Quadrant IV (0.4% deceptive stability). |
| **Conclusion & Limitations** | Acknowledge that this is feature-space perturbation, not wire-level packet injection. State that future work will validate on hardware testbeds. |

---

*Keep this document accessible during the seminar preparation and presentation rehearsal.*

