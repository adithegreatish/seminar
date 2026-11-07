# Feature Ablation Audit & Port-Shortcut Vulnerability Analysis

**Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Auditor:** Independent Research Auditor & Cybersecurity Methodology Reviewer  
**Audit Date:** November 2026  
**Audit Status:** CRITICAL SECURITY FINDING DOCUMENTED & VERIFIED  

---

## 1. Executive Summary: The Port Inclusion Dilemma
In network intrusion detection literature, whether to include transport-layer port numbers (`L4_SRC_PORT` and `L4_DST_PORT`) is a fiercely debated design choice. 
- The reference GitHub repository excluded ports without explanation.
- Our initial Phase 7 experiment evaluated both configurations (8 baseline features vs. 10 features with ports).

On clean benchmark data, including ports appears to dramatically improve performance:
- **Clean Accuracy:** Increases from **98.16%** to **98.90%** (+0.74%)
- **Macro-F1 Score:** Increases from **0.9238** to **0.9521** (+0.0283)
- **False Positive Rate:** Decreases from **0.0097** to **0.0019** (-80% false alarms)
- **Flow Padding Evasion Rate ($\epsilon=0.20$):** Drops from **21.94%** to **3.29%**

This audit investigated **why** this shift occurs and discovered that the apparent "robustness" is an artifact of **dataset-specific shortcut learning**.

---

## 2. Root Cause Analysis: Port-Based Shortcut Learning

### 2.1 Testbed Artifacts in NF-CSE-CIC-IDS2018
In the CSE-CIC-IDS2018 simulation environment:
- DoS and DDoS attack tools (Hulk, GoldenEye, Slowloris, LOIC-HTTP) were directed almost exclusively against a small set of web servers listening on port **80** (HTTP) and **443** (HTTPS).
- SSH-Bruteforce attacks were directed strictly against port **22**.
- FTP-BruteForce attacks were directed strictly against port **21**.

When `L4_DST_PORT` is provided to tree algorithms:
1. Decision trees discover that splitting on `L4_DST_PORT \in {80, 22, 21}` yields massive Gini / entropy impurity reductions with minimal tree depth.
2. The model learns a heuristic: *"Traffic directed at port 80/22/21 with elevated duration is almost certainly an attack."*
3. Consequently, the trees de-emphasize complex non-linear combinations of packet sizes, byte ratios, and flag transitions in favor of the static port shortcut.

### 2.2 Why Flow Padding Evasion Appeared to Drop to 3.29%
In the initial Domain-Constrained Perturbation Attack (DCPA), the threat model designated `L4_SRC_PORT` and `L4_DST_PORT` as immutable flow identifiers (assuming an established ongoing connection). 
Because the adversary only padded payload bytes, inserted packets, and delayed flow duration, `L4_DST_PORT` remained 80 or 22. The tree branches testing destination port never switched paths, falsely making the 10-feature model appear resistant to flow padding.

---

## 3. Independent Audit Experiment: Adversarial Port Evasion

To test whether the 10-feature model had learned brittle shortcuts, the auditor executed an independent adversarial evaluation modifying port numbers under two realistic attacker scenarios:

### Scenario A: Ephemeral Client Source Port Randomization
- **Threat Realism:** In standard operating systems (RFC 6335), clients choose ephemeral source ports dynamically between 49152 and 65535. An attacker can easily randomize their local source port.
- **Empirical Result:** Tested on all 1,670 initially detected attack flows in the test set. Only 13 attacks (0.78%) evaded detection. Source port randomization alone is insufficient for evasion because the models relied primarily on destination port.

### Scenario B: Service Port Redirection (Alternate Port Evasion)
- **Threat Realism:** A realistic attacker targeting a web server or SSH server running on non-standard ports (e.g., HTTP on port **8080** instead of 80; SSH on port **2222** instead of 22; FTP on **2121** instead of 21) or routing through reverse proxies.
- **Empirical Result:**
  $$\text{Previously Detected Attacks:} \quad 1,670$$
  $$\text{Attacks Evading via Port Redirection Alone:} \quad \mathbf{1,572} \quad (\mathbf{94.13\%}\text{ Evasion Rate!})$$
  $$\text{Attacks Evading under Joint Port Redirection + Flow Padding:} \quad \mathbf{1,590} \quad (\mathbf{95.21\%}\text{ Evasion Rate!})$$

---

## 4. Comparative Synthesis & Security Trade-Off Table

| Metric | Baseline Configuration (8 Features, Ports Excluded) | Extended Configuration (10 Features, Ports Included) | Architectural Audit Conclusion |
|---|---|---|---|
| **Clean Accuracy** | 98.16% | **98.90%** | Ports provide static prior (+0.74%) |
| **Clean Macro-F1** | 0.9238 | **0.9521** | Ports reduce false alarms on clean data |
| **Clean False Positive Rate** | 0.0097 | **0.0019** | Lower false alarm rate on known topology |
| **Flow Padding Evasion ($\epsilon=0.20$)** | 21.94% | **3.29%** | Trees anchor on static port numbers |
| **Service Port Redirection Evasion** | **0.00%** (Immune) | **94.13%** (Catastrophic Collapse) | 10-feature model completely fails when service runs on alternate port |
| **Underlying Representation** | Intrinsic flow geometry (Packet/byte distributions) | Topology memorization (Service port shortcuts) | **8 features provides superior generalization** |

---

## 5. Seminar Defense Recommendation for Aditya Ambare

> [!IMPORTANT]
> **Key Defense Takeaway:**
> If an examiner asks: *"Why did you exclude port numbers in your primary 8-feature baseline when including them gives 98.90% accuracy?"*
> 
> **Defensible Scientific Answer:**
> *"Including transport port numbers yields a higher clean accuracy (98.90% vs 98.16%) because benchmark datasets contain testbed-specific topology correlations where attacks target specific default ports (80, 22, 21). However, our ablation study demonstrates that this represents shortcut learning. The moment an adversary redirects traffic to non-standard ports (such as running HTTP on 8080 or SSH on 2222), the 10-feature model suffers a catastrophic 94.13% evasion rate. By excluding ports in our primary baseline, we force the machine learning models to learn intrinsic traffic flow dynamics (packet-to-byte ratios and TCP flag state transitions), ensuring resilience against service port evasion."*

