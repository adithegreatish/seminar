# Phase 1 Dataset Audit: NF-CSE-CIC-IDS2018

**Research Project:** Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations  
**Lead Researcher:** Aditya Ambare (Roll: TIA26)  
**Status:** Audit Completed & Verified

---

## 1. Dataset Dimensions & Basic Integrity

- **Total Flow Records:** `5,918,803`
- **Total Attributes:** `12`
- **Exact Duplicate Rows:** `0` (0.00%)
- **Label Mapping Integrity Verified:** `VALID (0=Benign, 1=Attack)`

## 2. Binary Class Distribution

| Label | Class Name | Flow Count | Percentage |
|---|---|---|---|
| `0` | Benign | 5,534,773 | 93.51% |
| `1` | Attack | 384,030 | 6.49% |
| **Total** | - | **5,918,803** | **100.00%** |

## 3. Multiclass Attack Taxonomy & Imbalance Analysis

| Attack Category | Binary Label | Total Flow Count | Proportion of Attacks |
|---|---|---|---|
| `DoS attacks-Hulk` | `1` | 108,129 | 28.156% |
| `SSH-Bruteforce` | `1` | 71,148 | 18.527% |
| `Infilteration` | `1` | 59,374 | 15.461% |
| `DDoS attacks-LOIC-HTTP` | `1` | 49,751 | 12.955% |
| `DoS attacks-GoldenEye` | `1` | 32,582 | 8.484% |
| `DoS attacks-Slowloris` | `1` | 17,109 | 4.455% |
| `Bot` | `1` | 15,498 | 4.036% |
| `DoS attacks-SlowHTTPTest` | `1` | 14,116 | 3.676% |
| `FTP-BruteForce` | `1` | 14,116 | 3.676% |
| `DDOS attack-LOIC-UDP` | `1` | 1,667 | 0.434% |
| `DDOS attack-HOIC` | `1` | 230 | 0.060% |
| `Brute Force -Web` | `1` | 173 | 0.045% |
| `Brute Force -XSS` | `1` | 101 | 0.026% |
| `SQL Injection` | `1` | 36 | 0.009% |


### Rare Attack Categories (< 1,000 flows)

The following attack categories exhibit extreme sparsity in the dataset:

- **DDOS attack-HOIC**: 230 flows (0.0039% of entire dataset)
- **Brute Force -Web**: 173 flows (0.0029% of entire dataset)
- **Brute Force -XSS**: 101 flows (0.0017% of entire dataset)
- **SQL Injection**: 36 flows (0.0006% of entire dataset)

> [!WARNING]
> Rare attack classes must not be evaluated using naïve macro-averaging without stratification or grouping, as a handful of samples will dominate classification error variance.

## 4. Feature Summary & Numerical Ranges

| Feature | Dtype | Missing | Infinite | Negative | Min | Median | Max | Mean ± Std |
|---|---|---|---|---|---|---|---|---|
| `L4_SRC_PORT` | `int32` | 0 | 0 | 0 | 0.0 | 52670.0 | 65535.0 | 48316.9 ± 16998.7 |
| `L4_DST_PORT` | `int32` | 0 | 0 | 0 | 0.0 | 443.0 | 65535.0 | 4085.5 ± 11784.8 |
| `PROTOCOL` | `int8` | 0 | 0 | 0 | 0.0 | 6.0 | 58.0 | 9.6 ± 5.2 |
| `L7_PROTO` | `float32` | 0 | 0 | 0 | 0.0 | 0.0 | 248.0 | 17.5 ± 34.3 |
| `IN_BYTES` | `int32` | 0 | 0 | 0 | 0.0 | 282.0 | 24371270.0 | 5151.4 ± 155524.2 |
| `OUT_BYTES` | `int32` | 0 | 0 | 0 | 0.0 | 198.0 | 214122854.0 | 6143.1 ± 307149.3 |
| `IN_PKTS` | `int32` | 0 | 0 | 0 | 0.0 | 4.0 | 279963.0 | 54.6 ± 2319.8 |
| `OUT_PKTS` | `int32` | 0 | 0 | 0 | 0.0 | 2.0 | 142798.0 | 8.2 ± 211.0 |
| `TCP_FLAGS` | `int16` | 0 | 0 | 0 | 0.0 | 26.0 | 223.0 | 73.9 ± 94.9 |
| `FLOW_DURATION_MILLISECONDS` | `int32` | 0 | 0 | 0 | 0.0 | 4293672.0 | 4294967.0 | 3563917.8 ± 1605110.6 |
| `Label` | `int8` | 0 | 0 | 0 | 0.0 | 0.0 | 1.0 | 0.1 ± 0.2 |
| `Attack` | `object` | 0 | 0 | 0 | N/A | N/A | N/A | N/A |


## 5. Methodological Observations & Data Preprocessing Plan

1. **Data Leakage Prevention:** Duplicate removal and imputation must occur strictly within training folds or downstream samples after explicit train/val/test splits.

2. **No Infinite or Missing Values:** The raw dataset has 0 null and 0 infinite values across all 12 columns, validating dataset ingestion.

3. **Transport Protocol Integrity:** `PROTOCOL` has discrete standard values (6 for TCP, 17 for UDP, 0/1 for ICMP/HOPOPT). It must not be perturbed arbitrarily into invalid protocol numbers during adversarial testing.

4. **Byte-Packet Physical Constraints:** `IN_BYTES >= IN_PKTS` and `OUT_BYTES >= OUT_PKTS` represent physical network flow invariants. Adversarial perturbations must respect flow feasibility.
