# Comprehensive Limitations and Future Work

**Project Title:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll Number: TIA26)  
**Academic Target:** Third Year B.E. Information Technology Technical Seminar  
**Institution:** Department of Information Technology  
**Date:** November 2026  

---

## 1. Scope and Realism of Feature-Space Adversarial Perturbations

### 1.1 Flow-Feature Level vs. Physical Packet Transmission
The adversarial evaluations in this research—specifically the Domain-Constrained Flow-Feature Perturbation (DC-FFP) and Query-Guided Greedy Search (QGGS / SGGS)—operate entirely within tabular feature space. 
- Perturbations mathematically modify the aggregated statistical properties of network flows (e.g., packet counts, byte counts, flow duration) as recorded in NetFlow v9 records.
- Although rigorous domain constraints were implemented (monotonic non-decreasing modifications $\Delta \ge 0$, integer packet counts, preservation of immutable transport protocols and TCP flags, and adherence to minimum byte-to-packet ratios), **no physical network packets were generated, fragmented, or transmitted across physical wire interfaces**.
- In operational network environments, an adversary must realize these flow-level modifications by manipulating physical packet streams (e.g., crafting TCP dummy payloads, injecting chaff packets with high TTLs, fragmenting IP packets across anomalous MTU boundaries, or pacing transmissions to introduce jitter).

### 1.2 Collector Discrepancies and In-Flight Filtering
Manipulating packet streams in real time does not guarantee identical flow record generation by middleboxes:
- Flow exporters (e.g., Cisco NetFlow, nProbe, Softflowd) employ internal cache timeout mechanisms (active timeout typically 1800s, inactive timeout typically 15s). Pacing packets to inflate `FLOW_DURATION_MILLISECONDS` may cause the exporter to fragment a single logical session into multiple distinct flow records.
- Intermediate security devices (Stateful Firewalls, Scrubbing Centers, Network Address Translation boxes) may strip dummy TCP options, drop out-of-order padding packets, or normalize TCP headers, preventing the synthetic flow perturbations from reaching the machine learning sensor unmodified.

---

## 2. Observational Bounds vs. Fundamental Networking Axioms

### 2.1 NetFlow v9 Observational Constraints
The physical constraint enforced during perturbation:
$$\text{BYTES} \ge \text{PKTS} \times 20$$
was empirically verified across the entire NF-CSE-CIC-IDS2018 dataset (5,918,803 flows), exhibiting **zero violations** and an empirical minimum ratio of $28.0\text{ bytes/packet}$.

### 2.2 Telemetry Assumptions & Non-Universality
While this bound is theoretically grounded in RFC 791 (which mandates an IPv4 header minimum length of 20 bytes when options are absent), it must be understood as an observational property of the NetFlow v9 collector rather than a universal law across all network telemetries:
- **Header Counting Convention:** The NetFlow collector utilized in CSE-CIC-IDS2018 counts the total IP packet length (IP header + transport header + payload) in `IN_BYTES` and `OUT_BYTES`. If a telemetry collector only logs L7 application payload bytes (excluding L3/L4 headers), valid traffic flows (e.g., TCP ACK packets, SYN probes, or DNS keep-alives) would have $0\text{ payload bytes}$ for non-zero packets, rendering $\text{BYTES} \ge \text{PKTS} \times 20$ invalid.
- **Protocol Variability:** Non-IP protocols, raw Ethernet layer-2 frames, or emerging tunneling protocols (e.g., Geneve, VXLAN, MPLS) have different baseline overheads. In IPv6 (RFC 8200), the base header is 40 bytes, which would necessitate $\text{BYTES} \ge \text{PKTS} \times 40$.
- **Conclusion:** The constraint is sound and necessary for the evaluated NetFlow v9 dataset, but must be dynamically parameterized according to the specific collector specifications and network stack in deployment.

---

## 3. Dataset Characteristics and Partitioning Limitations

### 3.1 Synthetic Testbed Environment
The NF-CSE-CIC-IDS2018 dataset is derived from network captures conducted in 2018 by the Canadian Institute for Cybersecurity on Amazon Web Services (AWS) infrastructure.
- While it represents one of the largest publicly available NetFlow benchmarks (5.9M records), the background benign traffic was synthetically generated via automated user profiles (B-Profiles) simulating email, web browsing, and SSH sessions.
- As a consequence, synthetic background traffic exhibits more predictable statistical regularities than true enterprise or ISP-scale network traffic, which features heavy-tailed distributions, transient network congestion, BGP flapping, and diverse application behaviors.

### 3.2 Random Flow-Level Splitting vs. Temporal Splitting
In this implementation, stratified random partitioning (70% train, 15% validation, 15% test) was executed across the flow records.
- **Temporal Contamination Risk:** In continuous network intrusion campaigns (e.g., a multi-hour DDoS or slow-scan Brute Force campaign), flows originating from the same attack session may be distributed across both training and test partitions.
- While strict zero-data-leakage was maintained (no target leakage, scalers and imputers fit strictly on training data), random splitting can provide an optimistic estimate of test accuracy because models can interpolate between time-adjacent flow instances.
- Evaluating models on strict time-separated splits (e.g., training on Days 1–3 and testing on Days 4–5) would test resistance to temporal drift, but is constrained by the aggregated parquet structure of the standardized NetFlow dataset.

### 3.4 Cross-Dataset Generalizability Pending Local Data Placement
While an exact semantic alignment protocol and executable evaluation script (`scripts/06_cross_dataset_validation.py`) were developed for the UNSW-NB15 benchmark, experimental execution remains pending local dataset placement due to local network download constraints. In strict accordance with academic integrity standards, no simulated or fabricated cross-dataset scores were reported.

### 3.5 Nature of Port Invariance and Tabular Port-Shift Scope
The port shortcut investigation evaluated how models respond when transport ports are manipulated:
- **10-Feature Model Vulnerability:** A tabular destination-port feature-shift stress test produced 1,572 evasions among 1,670 initially detected attacks (94.13% evasion rate). We explicitly emphasize that this was conducted as a tabular feature-space stress test; **no live network traffic redirection or packet-level attack was performed**.
- **8-Feature Baseline Invariance:** The 8-feature baseline model's zero evasion under direct port modification (0 / 1,664 attacks missed) is a direct mathematical consequence of excluding transport port numbers from its input feature vector. This confirms feature invariance to direct tabular port-field changes when other features remain static, but does not imply operational immunity to real-world multi-stage intrusion campaigns where attackers alter both transmission ports and packet dynamics simultaneously.

---

## 4. Statistical Power and Cross-Model Attribution Ranking

### 4.1 Sample Size Constraints in Feature Ranking
Cross-model explanation consistency was evaluated using the Spearman rank correlation coefficient ($\rho_s$) between the global SHAP feature importance vectors of Random Forest and XGBoost:
$$\rho_s = 0.8095 \quad (p = 0.0149)$$
- While this correlation is statistically significant at the $\alpha = 0.05$ level ($p < 0.05$), the sample size is strictly limited to the number of evaluated flow features ($N = 8$).
- With degrees of freedom $df = N - 2 = 6$, rank correlation is highly sensitive to the permutation of individual mid-tier features.
- While both models agree unambiguously that the top two drivers of malicious classification are `OUT_BYTES` and `FLOW_DURATION_MILLISECONDS`, the relative ranking of intermediate features (`IN_BYTES`, `IN_PKTS`, `OUT_PKTS`) exhibits rank swaps that disproportionately impact $\rho_s$.

### 4.2 Raw Margin (Log-Odds) vs. Probability Space
TreeExplainer attributions for XGBoost were computed in log-odds (raw margin) space, whereas Random Forest attributions were computed in probability space. While both provide exact additive feature attribution, their numerical magnitudes are not directly commensurate without monotonic logit transformations, necessitating rank-based rather than direct numerical distance comparisons across architectures.

---

## 5. Explanation Stability is Not a Proof of Model Robustness

### 5.1 The Deceptive Stability Hazard (Quadrant IV)
A critical insight of this research is the empirical identification of **Quadrant IV (Flipped Prediction with Deceptive Explanation Stability)**:
- In the paired 500-sample explanation stability evaluation, $0.4\%$ of adversarial samples successfully deceived the XGBoost classifier into predicting `Benign` while maintaining an attribution drift well below the validation-calibrated stability threshold ($L_1 \le \tau_{val} = 0.2739$).
- In these cases, minimal feature perturbations at critical decision thresholds caused the classification output to cross the decision boundary without causing substantial redistribution of overall feature attributions.

### 5.2 Regulatory and Operational Caveat
Security analysts and SOC engineers must not treat high explanation stability ($L_1 \le \tau$) as an oracle proving that a classifier has made a correct, unmanipulated decision. Adversaries operating with black-box or white-box query access can formulate multi-objective optimization attacks that simultaneously minimize classification loss and explanation divergence, creating "stealthy" evasions that evade both the detector and the explanation monitor.

---

## 6. Inference Latency vs. Operational Real-World Pipeline Latency

### 6.1 Algorithmic Inference vs. End-to-End Pipeline
The latency benchmark evaluated in this research demonstrated exceptional algorithmic throughput:
- Vectorized XGBoost inference: $0.23\,\mu\text{s/sample}$ ($4,389,064\text{ flows/sec}$).
- Single-sample streaming inference: $0.63\,\text{ms/sample}$ ($1,599\text{ flows/sec}$).

### 6.2 Operational Production Realities
However, in production enterprise intrusion detection systems, model inference represents only a fraction of the total processing latency:
1. **Packet Capture & Buffer Management:** Capturing raw packets from high-speed 10/40/100 Gbps interfaces requires specialized kernel bypass frameworks (e.g., DPDK, AF_XDP, PF_RING) to prevent packet loss.
2. **Flow Aggregation Timeouts:** A flow cannot be categorized until its bidirectional session terminates (TCP FIN/RST) or an exporter inactivity timer expires (typically 15 to 30 seconds). Therefore, flow-based NIDS cannot detect an attack on packet #1; detection is inherently delayed until the flow summary is exported.
3. **Feature Preprocessing Overhead:** Extracting TCP flags, verifying packet counters, imputing missing values, and executing tabular data conversions introduces operational latency that exceeds tree evaluation time by orders of magnitude.

---

## 7. Actionable Future Work Directions

Based on the verified experimental findings and limitations, the following research avenues are proposed:

### 7.1 Packet-Level Physical Adversarial Validation
- Bridge the gap between feature-space perturbations and physical network traffic by integrating software packet generators (e.g., Scapy, Cisco TRex).
- Transmit adversarial packet streams across an isolated hardware testbed, capture the resulting flows using industrial NetFlow exporters, and evaluate whether feature-space evasion rates translate directly to physical evasion.

### 7.2 Adversarial Training with Domain-Constrained Invariants
- Incorporate DC-FFP perturbed flows directly into the training pipeline of tree ensembles and neural baselines.
- Explore adversarial retraining formulations that penalize vulnerability to traffic padding while preserving clean-flow precision and preventing false positive inflation.

### 7.3 Port-Agnostic Feature Engineering
- To mitigate the severe vulnerability identified in the port ablation study (where a tabular destination-port feature-shift stress test produced 1,572 evasions among 1,670 initially detected attacks, representing a 94.13% evasion rate in 10-feature models), develop port-invariant flow representations.
- Investigate behavioral graph embeddings, relative inter-arrival packet dynamics, and ratio-based statistical features (e.g., byte-to-packet ratios, forward-to-backward packet ratios) that decouple intrusion detection from ephemeral or spoofable transport port numbers.

### 7.4 Temporal Block Evaluation & Drift Monitoring
- Benchmark intrusion detection models across longitudinal datasets covering multiple weeks or months (e.g., CIC-Bell-DNS2021 or modern Zeek logs).
- Implement statistical drift detection algorithms (e.g., Population Stability Index, Kolmogorov-Smirnov tests on SHAP values) to trigger automated retraining before model performance degrades in production.

### 7.5 Conformal Prediction and Out-of-Distribution Rejection
- Equip the tree-based NIDS with conformal prediction intervals to output valid confidence sets rather than overconfident point predictions.
- Implement an out-of-distribution (OOD) rejection layer that flags anomalous flow patterns characteristic of adversarial padding for human analyst triage rather than silently misclassifying them as benign.

---

## 8. Summary Table: Research Limitations & Mitigation Roadmap

| Research Dimension | Current Implementation Scope | Known Boundary / Limitation | Proposed Long-Term Mitigation |
| :--- | :--- | :--- | :--- |
| **Attack Realism** | Feature-space DC-FFP & QGGS / SGGS | Tabular flow modifications; no wire transmission | Hardware testbed with TRex / Scapy packet injection |
| **Physical Constraints** | $\text{BYTES} \ge \text{PKTS} \times 20$ (RFC 791) | NetFlow v9 telemetry specific; not universal L7 law | Collector-adaptive constraint parametrization |
| **Data Partitioning** | Stratified random splitting (70/15/15) | Potential optimistic bias across multi-flow sessions | Time-blocked chronological evaluation |
| **Multiclass Support** | 15 attack classes in 200k sample | Severe minority scarcity (e.g., SQLi $N=6$) | Specialized synthetic oversampling or binary cascades |
| **Port Dependence** | Baseline (8-feat) vs. Extended (10-feat) | 10-feat model exhibits 94.13% tabular port-shift evasion (1,572/1,670) | Strict port-agnostic behavioral feature design |
| **Explainability** | TreeExplainer log-odds / prob attributions | $N=8$ features limits Spearman rank correlation power | Dimensionality expansion with higher-order flow metrics |
| **Explanation Stability** | Paired 500-sample 4-quadrant analysis | Quadrant IV ($0.4\%$) proves stability $\ne$ correctness | Multi-objective defense; conformal uncertainty sets |
| **Inference Benchmark** | Sub-millisecond single/batch evaluation | Excludes packet capture and flow timeout latency | Full-stack eBPF / XDP pipeline benchmarking |

---

*This document constitutes the official limitations and research outlook statement for Aditya Ambare's technical seminar dissertation.*

