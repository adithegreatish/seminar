# University Technical Seminar Presentation Script & Viva Defense Guide

**Seminar Title:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Candidate Name:** Aditya Ambare  
**Roll Number:** TIA26  
**Department:** Information Technology  
**Academic Level:** Third Year B.E. (Seminar & Project Preliminary)  

---

## Part I: 15-Slide Presentation Structure & Speaking Script

### Slide 1: Title & Candidature
- **Slide Title:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations
- **Presenter:** Aditya Ambare (Roll: TIA26), Third Year B.E. Information Technology
- **Speaking Notes (1 min):**
  > "Respected panel members and faculty, I welcome you to my technical seminar presentation on 'Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations'. Modern cybersecurity relies heavily on machine learning to filter millions of packets per second. While academic literature regularly reports clean test accuracies exceeding 98%, deployed classifiers operate in an adversarial battlefield. This seminar evaluates whether machine learning predictions and their Explainable AI rationales remain reliable when malicious traffic is modified under physical networking constraints."

---

### Slide 2: Problem Statement & Motivation
- **Slide Content:**
  - High clean accuracy $\ne$ Dependable security.
  - The "Black Box" dilemma in Security Operations Centers (SOCs).
  - Unconstrained adversarial attacks (e.g. image FGSM) fail on network protocols because packet headers must obey physical RFC standards.
  - Research Question: How do tree models behave under domain-constrained traffic padding, and do their SHAP explanations remain stable?
- **Speaking Notes (1 min):**
  > "Why is this research critical? If an ML model detects 98% of intrusions in the lab, but an adversary can bypass detection simply by adding 20% payload padding or delaying packet timing, the system is fundamentally insecure. Furthermore, explainability is not just a regulatory buzzword; SOC analysts need to know why a flow was flagged. We investigate the crucial link between detection performance, explainability, adversarial robustness, and explanation stability."

---

### Slide 3: Research Pipeline & Architecture
- **Slide Content:**
  - Full end-to-end modular pipeline diagram:
    Dataset Ingestion (5.9M rows) $\to$ Zero-Leakage Split $\to$ ML Baselines (DT, RF, XGBoost) $\to$ SHAP TreeExplainer $\to$ Domain-Constrained Adversarial Perturbations (DCPA/SGGS) $\to$ Explanation Stability (4 Quadrants) $\to$ Feature Ablation Study.
- **Speaking Notes (1 min):**
  > "Here is our research architecture. Rather than relying on a single monolithic notebook, the entire framework is implemented across 6 clean Python modules with an automated test suite. We perform a strict 70/15/15 train/validation/test split, ensuring zero data leakage, and establish formal evaluation criteria using Validation Macro-F1."

---

### Slide 4: Dataset Audit: NF-CSE-CIC-IDS2018
- **Slide Content:**
  - 5,918,803 NetFlow v9 records; 12 attributes.
  - Benign: 5,534,773 (93.51%); Attack: 384,030 (6.49%).
  - Verified ground truth mapping: Label 0 strictly Benign, Label 1 strictly Attack.
  - Severe class imbalance: 4 extreme minority categories (`SQL Injection`: 36, `Brute Force -XSS`: 101, `Brute Force -Web`: 173, `DDOS attack-HOIC`: 230).
- **Speaking Notes (1.5 min):**
  > "We audited the NF-CSE-CIC-IDS2018 dataset across all 5.9 million rows. Notice the extreme long-tail distribution: while DoS Hulk has over 108,000 flows, SQL Injection has only 36 samples in the entire dataset. In existing published notebooks, naive class weighting caused catastrophic false alarms because an attack with 36 samples was weighted 150,000 times higher than benign traffic. We identified this flaw and established stratified evaluation."

---

### Slide 5: Clean Machine Learning Baselines
- **Slide Content:**
  - Table of Test Set Results ($N=30,000$):
    - Decision Tree: Accuracy 97.13%, Macro-F1 0.8901, FPR 2.09%, Latency 0.37 ms.
    - Random Forest: Accuracy 97.79%, Macro-F1 0.9113, FPR 1.37%, Latency 17.73 ms.
    - XGBoost (Top Model): **Accuracy 98.16%**, **Macro-F1 0.9238**, **FPR 0.97%**, Latency 0.63 ms.
- **Speaking Notes (1.5 min):**
  > "On clean, unperturbed network traffic, all three tree ensembles perform well. XGBoost achieved the highest validation Macro-F1 (0.9171) and was selected as our primary classifier. On the unseen test partition, XGBoost achieved 98.16% accuracy, a Macro-F1 of 0.9238, and a low false positive rate of 0.97%, with sub-millisecond inference latency (0.63 ms/flow)."

---

### Slide 6: Explainable AI: Global SHAP Feature Attributions
- **Slide Content:**
  - SHAP summary beeswarm plot and feature importance ranking.
  - Top decision drivers: `OUT_BYTES` (0.7051), `FLOW_DURATION_MILLISECONDS` (0.6560), `IN_BYTES` (0.4589), `IN_PKTS` (0.4404).
  - Cross-model Spearman correlation between XGBoost and Random Forest: $\rho_s = 0.8095$ ($p = 0.0149$).
- **Speaking Notes (1.5 min):**
  > "Using TreeExplainer, we calculated exact Shapley values. Outbound bytes and flow duration dominate model predictions. Large discrepancies between packet count and byte volume push the log-odds toward attack classification. Furthermore, comparing XGBoost and Random Forest yields a Spearman rank correlation of 0.8095, demonstrating that both bagging and boosting architectures capture congruent flow geometry."

---

### Slide 7: Physical Network Invariants & The Threat Model
- **Slide Content:**
  - Why standard image FGSM fails on tabular network flows.
  - Mutable vs. Immutable features.
  - Monotonicity: Attackers can add payload bytes, dummy packets, and inter-packet delays ($\Delta \ge 0$), but cannot un-send packets.
  - Physical Invariant: $\text{BYTES} \ge \text{PKTS} \times 20$ (RFC 791 IPv4 20-byte header).
  - Protocol code and TCP flags must remain valid discrete states.
- **Speaking Notes (1.5 min):**
  > "This slide marks our core research departure from naive adversarial ML. In computer vision, an attacker can modify any pixel in any direction. In a network, you cannot create a negative byte count, fractional packet, or arbitrary protocol number. We audited the invariant BYTES >= PKTS * 20 across all 5.9 million rows; zero violations exist because RFC 791 mandates a 20-byte IP header. Our attacks strictly enforce these domain invariants."

---

### Slide 8: Adversarial Robustness Degradation
- **Slide Content:**
  - Robustness curves plot across $\epsilon \in [0.0, 0.50]$.
  - At $\epsilon = 0.05$: XGBoost evasion is 0.66%, RF is 11.62%.
  - At $\epsilon = 0.20$: XGBoost evasion jumps to **21.94%**, RF reaches **28.46%**.
  - At $\epsilon = 0.50$: Recall drops to **51.18% - 58.07%**; Random Forest misses over 40% of attacks!
- **Speaking Notes (2 min):**
  > "Here is our first major experimental finding: high clean accuracy does not guarantee adversarial robustness. When an adversary applies moderate 20% payload padding and transmission delay ($\epsilon=0.20$), over 1 in 5 attacks evade detection completely. At 50% flow padding, Random Forest's attack recall collapses from 85.77% down to 51.18%. The model is effectively guessing on padded attacks."

---

### Slide 9: Explanation Stability Under Perturbation
- **Slide Content:**
  - Linking XAI and Robustness on $N=500$ paired attack samples ($\epsilon=0.20$).
  - Mean $L_1$ Attribution Drift: **0.3484** (Median: 0.2833).
  - Mean Top-3 Feature Overlap: **83.27%**.
  - Mean Spearman Attribution Rank Correlation: **0.7364** (Median: 0.8810).
- **Speaking Notes (1.5 min):**
  > "Now we explore the central link: when inputs are perturbed, do the SHAP explanations remain stable? Across 500 paired clean and perturbed flows, the mean absolute attribution drift is 0.3484 in log-odds space. The top 3 features are retained in 83.27% of cases, and the rank correlation is 0.7364, showing moderate structural stability with localized fragility."

---

### Slide 10: Four-Quadrant Behavioral Analysis
- **Slide Content:**
  - 4-Quadrant Partition (Median threshold $\tau = 0.2833$):
    - **Quadrant I (49.6%, 248 flows):** Prediction Stable, Explanation Stable.
    - **Quadrant II (27.6%, 138 flows):** Prediction Stable, Explanation Fragile.
    - **Quadrant III (22.4%, 112 flows):** Prediction Flipped, Explanation Shifted.
    - **Quadrant IV (0.4%, 2 flows):** Prediction Flipped, Explanation Deceptively Stable!
- **Speaking Notes (2 min):**
  > "We partitioned model behavior into four mutually exclusive quadrants. In Quadrant I (49.6%), both detection and explanation hold. In Quadrant II (27.6%), the model catches the attack, but its explanatory reasoning has shifted. In Quadrant III (22.4%), the attack successfully evades, and SHAP reflectively captures the altered path. Crucially, in Quadrant IV (0.4%), the attack evaded detection, but its explanation remained deceptively similar to a clean attack profile. This proves that explanation stability cannot be used as a standalone indicator of security correctness."

---

### Slide 11: Feature Ablation Study: The Port Shortcut Trap
- **Slide Content:**
  - Comparing 8 baseline features vs. 10 features (including `L4_SRC_PORT` and `L4_DST_PORT`).
  - Clean Accuracy: 98.16% $\to$ **98.90%**.
  - False Positive Rate: 0.0097 $\to$ **0.0019** (-80%).
  - Apparent flow padding evasion drops from 21.94% to **3.29%**.
- **Speaking Notes (1.5 min):**
  > "Why did existing notebooks exclude ports? We performed a formal ablation study. Adding transport ports increased clean accuracy to 98.90% and cut false alarms by 80%. When we tested flow padding, evasion dropped from 21.94% to 3.29%. At first glance, including ports seems superior. But our next slide reveals the danger of shortcut learning."

---

### Slide 12: Discovery of the 94.13% Port Redirection Evasion
- **Slide Content:**
  - Testbed artifact: Attacks targeted default ports (80 HTTP, 22 SSH, 21 FTP).
  - The model learned: `L4_DST_PORT == 80/22/21` $\implies$ Attack.
  - **Adversarial Evaluation:** Attacker hosts service on alternate ports (HTTP on 8080, SSH on 2222).
  - **Result:** **1,572 out of 1,670 attacks evade detection (94.13% EVASION RATE!)**
- **Speaking Notes (2 min):**
  > "This is a key discovery in our research. The 10-feature model achieved high accuracy through shortcut learning. In CSE-CIC-IDS2018, attacks were run against standard server ports. The trees memorized destination port numbers rather than learning traffic geometry. When we simulated a realistic adversary running an attack on an alternate port—like SSH on 2222 or HTTP on 8080—the model suffered a catastrophic collapse, missing 94.13% of attacks! Excluding ports forces the model to learn intrinsic packet dynamics."

---

### Slide 13: Interactive Streamlit Dashboard Demonstration
- **Slide Content:**
  - Screenshot / live demo of `dashboard/app.py`.
  - Modules: Dataset Statistics, Model Comparisons, Live Adversarial Flow Simulator (interactive $\epsilon$ slider), SHAP Beeswarm & Local Waterfall, Seminar Reports Viewer.
- **Speaking Notes (1 min):**
  > "To make this research accessible, we developed a local Streamlit dashboard. It allows an analyst or examiner to pick any real malicious flow, adjust the perturbation budget slider in real time, and observe the exact byte padding, probability decay, and explanation drift dynamically."

---

### Slide 14: Reproducibility & Code Verification
- **Slide Content:**
  - SHA-256 Dataset Hash: `94a974b20bb611c0f4f9d21c97a5a8a113d9ea1ce2860d4da55bfa025687796f`.
  - Python 3.12, UV package manager, zero cloud dependencies.
  - Automated test suite: 13/13 pytest unit tests passing.
  - Master smoke test runner: `scripts/verify_all.py` (100% verification pass).
- **Speaking Notes (1 min):**
  > "Every single result presented today is 100% reproducible. We have locked all dependencies in requirements.txt, verified the SHA-256 hash of the 5.9-million-row dataset, and written 13 automated unit tests that validate data leakage prevention, domain invariants, and metric calculations."

---

### Slide 15: Conclusions & Future Research
- **Slide Content:**
  - Summary of contributions:
    1. Leakage-free baseline: XGBoost 98.16% Acc, 0.9238 Macro-F1.
    2. Domain-constrained evasion: 21.9% - 28.5% evasion under 20% flow padding.
    3. Port shortcut vulnerability: 94.13% evasion under port redirection.
    4. SHAP stability caveat: Stability $\ne$ correctness (Quadrant IV deception).
  - Future Work: Hardware packet capture validation on UNSW-NB15, adversarial training under physical flow bounds.
- **Speaking Notes (1 min):**
  > "To conclude, this seminar establishes that NIDS evaluation must transcend clean accuracy. High accuracy on static benchmarks can conceal catastrophic adversarial fragility and shortcut learning. Trustworthy NIDS requires joint verification across decision boundaries, physical flow invariants, and attribution stability. Thank you, and I look forward to your questions."

---

## Part II: Top 10 Examiner Viva Defense Questions & Winning Technical Answers

### Q1: "Why did you choose tree-based models (Random Forest, XGBoost) rather than deep neural networks (CNNs, LSTMs, Transformers)?"
**Examiner Intent:** Testing architectural awareness and domain-specific ML engineering.  
**Aditya's Answer:**
> *"In tabular network flow records (NetFlow/IPFIX), features represent heterogeneous physical quantities—such as discrete protocol codes, bitmask flags, continuous byte counts, and long-tailed duration distributions. Decades of empirical ML research (including Grinsztajn et al., NeurIPS 2022) prove that gradient-boosted decision trees routinely outperform deep neural networks on tabular data without requiring aggressive normalization that distorts physical units. Furthermore, tree ensembles provide sub-millisecond inference latencies (0.63 ms/flow for XGBoost), which is essential for line-rate network filtering, and support exact polynomial-time Shapley value computation via TreeExplainer, whereas deep networks require sampling approximations."*

---

### Q2: "Why couldn't you just use standard FGSM or PGD attacks directly on Random Forest or XGBoost?"
**Examiner Intent:** Testing understanding of adversarial machine learning fundamentals.  
**Aditya's Answer:**
> *"Standard FGSM and PGD compute gradients $\nabla_x \mathcal{L}$ of a continuous, differentiable loss function with respect to the input features. Decision trees and tree ensembles are piecewise-constant step functions; their derivatives are zero almost everywhere and undefined at split boundaries. Therefore, gradient-based attacks cannot be backpropagated through tree splits. Furthermore, unconstrained FGSM perturbs features in continuous arbitrary directions, which would create physically impossible network records—such as negative bytes, fractional packets, or corrupted protocol codes. We designed domain-constrained black-box attacks (DCPA and SGGS) that respect network protocol physics."*

---

### Q3: "What is the physical justification for your constraint $\text{BYTES} \ge \text{PKTS} \times 20$?"
**Examiner Intent:** Testing domain knowledge in computer networking and RFC standards.  
**Aditya's Answer:**
> *"The constraint $\text{BYTES} \ge \text{PKTS} \times 20$ is derived directly from RFC 791, the IPv4 standard specification. An IPv4 header has a mandatory minimum length of 20 bytes (five 32-bit words). NetFlow v9 aggregates total IP packet lengths on the wire. Even for a zero-payload packet, the IP header alone consumes 20 bytes. When transport headers are included, RFC 793 mandates 20 bytes for TCP (yielding 40 bytes minimum per packet), and RFC 768 mandates 8 bytes for UDP (yielding 28 bytes minimum). We independently audited all 5,918,803 flows in the NF-CSE-CIC-IDS2018 dataset; zero records violate this constraint, and the empirical minimum ratio is 28.0 bytes per packet. Thus, 20 bytes is a conservative physical floor."*

---

### Q4: "Why did you exclude port numbers (`L4_SRC_PORT`, `L4_DST_PORT`) in your primary baseline when including them gives 98.90% accuracy?"
**Examiner Intent:** Testing understanding of feature engineering and shortcut learning.  
**Aditya's Answer:**
> *"While including port numbers improves clean accuracy from 98.16% to 98.90% and cuts false alarms by 80%, our feature ablation study proved that this represents shortcut learning. In the CSE-CIC-IDS2018 testbed, attacks were directed at fixed default ports (80 HTTP, 22 SSH, 21 FTP). The decision trees memorized these port numbers rather than learning traffic geometry. When we conducted an adversarial evaluation where an attacker simply redirected traffic to an alternate port (such as SSH on 2222 or HTTP on 8080), the 10-feature model suffered a catastrophic collapse, missing 94.13% of attacks! Excluding ports in our 8-feature baseline forces the model to learn intrinsic flow geometry (packet rates, byte ratios, and flag transitions), providing true generalization."*

---

### Q5: "In your execution log, there was an initial mention of Validation Macro-F1 0.9231, but later 0.9171 was reported. Which is correct?"
**Examiner Intent:** Testing honesty, audit rigor, and experimental precision.  
**Aditya's Answer:**
> *"0.9171 (specifically 0.917064) is the authoritative validation Macro-F1 score recorded in our programmatic metric log (`outputs/metrics/baseline_metrics.csv`). The 0.9231 mention was an interim narrative typo that conflated the validation score (0.9171) with the held-out test Macro-F1 (0.9238). During our Phase 9 independent audit, we regenerated all comparison tables directly from saved predictions and ground-truth labels on disk, reconciling this discrepancy in `outputs/audit/metric_reconciliation.csv`."*

---

### Q6: "Why did Benign class recall drop to ~58% in the multiclass classification experiment in existing notebooks?"
**Examiner Intent:** Testing understanding of extreme class imbalance and loss functions.  
**Aditya's Answer:**
> *"The dataset contains extreme class imbalance: out of 5.9 million flows, 93.5% are Benign, while rare attack classes like SQL Injection and Brute Force -Web have only 36 and 173 samples. In the original notebook, the authors applied naive balanced sample weights (`class_weight='balanced'`) across all 15 classes. This gave a flow from a 36-sample class an artificial weight of over 150,000 times that of a benign flow. Consequently, the gradient booster penalized even the slightest doubt on rare classes, generating massive false positives on benign traffic and dragging Benign recall down to 58%. We documented that extreme minority classes must either be grouped or evaluated using per-class support metrics rather than naive balanced weighting."*

---

### Q7: "What is Quadrant IV in your four-quadrant analysis, and why is it dangerous?"
**Examiner Intent:** Testing understanding of the relationship between explainability and security.  
**Aditya's Answer:**
> *"Quadrant IV represents 'Deceptive Explanation Stability'. It comprises malicious flows where the adversarial perturbation successfully caused the model to flip its prediction to Benign, yet its SHAP attribution ranking remained deceptively similar to a clean attack profile. This is dangerous because many proposed defense systems suggest using explanation stability as a secondary automated trust metric. If an analyst or automated gatekeeper assumes that a stable explanation implies a correct prediction, Quadrant IV attacks will evade completely undetected. Explanation stability does not prove prediction correctness."*

---

### Q8: "Why do you evaluate using Macro-F1 rather than Accuracy or Weighted-F1?"
**Examiner Intent:** Testing metric selection and evaluation methodology.  
**Aditya's Answer:**
> *"In highly imbalanced datasets where Benign traffic comprises 93.51% of all flows, a naive dummy classifier that predicts 'Benign' for every single flow achieves 93.51% accuracy and a 0.90 Weighted-F1, despite detecting exactly zero attacks. Weighted-F1 weights each class's score by its prevalence, allowing the dominant Benign class to mask complete failure on attack classes. Macro-F1 gives equal weight to every class regardless of support, ensuring that a model cannot achieve a high score without accurately detecting attacks."*

---

### Q9: "Did you cross-validate your results on UNSW-NB15, and why is it marked pending?"
**Examiner Intent:** Testing research ethics, data transparency, and cross-dataset validity.  
**Aditya's Answer:**
> *"In accordance with strict scientific integrity, we mark live UNSW-NB15 evaluation as pending because the raw 100MB CSV was not bundled locally in the repository. We did not fabricate synthetic benchmark numbers. Instead, we established and documented a formal semantic alignment protocol in `outputs/cross_dataset/unsw_nb15_evaluation_protocol.md` mapping UNSW-NB15 attributes (`sbytes`, `dbytes`, `spkts`, `dpkts`, `dur`, `proto`) to our NetFlow schema. Crucially, we note that evaluating directly across datasets without domain adaptation is flawed due to covariate shift in MTU sizes and network topologies."*

---

### Q10: "How would you defend an ML-based NIDS in production against the adversarial flow perturbations you demonstrated?"
**Examiner Intent:** Testing forward-looking engineering solutions and defensive mitigation.  
**Aditya's Answer:**
> *"We recommend a three-tier defense: First, adversarial training incorporating domain-constrained perturbations (DCPA), augmenting training batches with padded and delayed flows to smooth tree branch thresholds. Second, multi-scale feature engineering: combining NetFlow aggregated statistics with sequence-based packet inter-arrival transitions (Markov chains) that are harder to pad uniformly. Third, defensive dual-verification: flagging flows that fall into Quadrant II or Quadrant III (where attribution drift diverges from historical baseline profiles) for secondary inspection, treating explainability drift as an anomaly signal."*

