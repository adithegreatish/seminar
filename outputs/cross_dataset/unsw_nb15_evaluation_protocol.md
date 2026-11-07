# Phase 8 Protocol: Cross-Dataset Validation on UNSW-NB15

**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Status:** Formal Evaluation Protocol Defined

---

## 1. Cross-Dataset Methodological Rationale

In machine learning-based NIDS, cross-dataset validation prevents models from overfitting to environment-specific flow artifacts present in a single testbed (such as synthetic topology quirks in CSE-CIC-IDS2018). UNSW-NB15 provides an independent synthetic-real hybrid benchmark created using the IXIA PerfectStorm tool at the Cyber Range Lab of UNSW Canberra.

## 2. Feature Schema Alignment Protocol

| Semantic Flow Concept | Primary Dataset (`NF-CSE-CIC-IDS2018`) | Validation Dataset (`UNSW-NB15`) | Alignment Transformation |

|---|---|---|---|

| Inbound Byte Volume | `IN_BYTES` | `sbytes` | Direct mapping (Byte count) |
| Outbound Byte Volume | `OUT_BYTES` | `dbytes` | Direct mapping (Byte count) |
| Inbound Packet Count | `IN_PKTS` | `spkts` | Direct mapping (Packet count) |
| Outbound Packet Count | `OUT_PKTS` | `dpkts` | Direct mapping (Packet count) |
| Flow Duration | `FLOW_DURATION_MILLISECONDS` | `dur` | Unit conversion: $	ext{dur} 	imes 1000$ (seconds to ms) |
| Protocol Identifier | `PROTOCOL` (IANA integer) | `proto` (string code) | Categorical map: `tcp` $\to 6$, `udp` $\to 17$, `icmp` $\to 1$ |
| Binary Ground Truth | `Label` (0=Benign, 1=Attack) | `label` (0=Normal, 1=Attack) | Direct identity mapping |

## 3. Methodological Guardrails Against Naive Generalization

> [!IMPORTANT]

> **Direct Cross-Testing Caution:** Training on NF-CSE-CIC-IDS2018 and evaluating directly on raw UNSW-NB15 without domain adaptation is invalid due to significant covariate shift (different MTU configurations, packet capture buffering, and background traffic baselines). Instead, the rigorous methodology:

> 1. Evaluates each dataset using identical feature engineering and tree architectures.

> 2. Validates whether the adversarial robustness hierarchy (XGBoost vs RF vs DT) and explanation stability findings remain consistent across independent benchmark architectures.
