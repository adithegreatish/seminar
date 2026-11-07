"""
Interactive Research Dashboard for Technical Seminar.
Project: Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations
Researcher: Aditya Ambare (Roll: TIA26)
"""

from pathlib import Path
import json
import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns

# Set page config
st.set_page_config(
    page_title="Robust & Explainable NIDS | TIA26",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUTS_DIR = BASE_DIR / "outputs"
DATA_DIR = BASE_DIR / "data"

@st.cache_resource
def load_models_and_explainer():
    import joblib
    from src.models.baseline_models import NIDSModelWrapper
    from src.explainability.shap_explainer import NIDSShapExplainer
    
    xgb_path = OUTPUTS_DIR / "models" / "xgboost_binary.joblib"
    rf_path = OUTPUTS_DIR / "models" / "random_forest_binary.joblib"
    dt_path = OUTPUTS_DIR / "models" / "decision_tree_binary.joblib"
    
    xgb_model = NIDSModelWrapper.load(xgb_path)
    rf_model = NIDSModelWrapper.load(rf_path)
    dt_model = NIDSModelWrapper.load(dt_path)
    
    explainer = NIDSShapExplainer(xgb_model)
    explainer.fit_explainer()
    
    return {"XGBoost": xgb_model, "Random Forest": rf_model, "Decision Tree": dt_model}, explainer

@st.cache_data
def load_test_sample():
    cache_dir = DATA_DIR / "processed" / "sample_200000_ports_False"
    X_test = pd.read_parquet(cache_dir / "X_test.parquet")
    y_test_df = pd.read_parquet(cache_dir / "y_test.parquet")
    return X_test, y_test_df

def main():
    st.sidebar.title("🛡️ Project Navigation")
    st.sidebar.markdown(
        "**Researcher:** Aditya Ambare  \n"
        "**Roll No:** TIA26  \n"
        "**Program:** Third Year B.E. IT  \n"
        "**Seminar:** Robust & Explainable NIDS"
    )
    st.sidebar.markdown("---")
    
    menu = st.sidebar.radio(
        "Select Module:",
        [
            "1. Research Executive Summary",
            "2. Dataset Audit & Statistics",
            "3. Model Comparative Evaluation",
            "4. Interactive Adversarial Flow Simulator",
            "5. SHAP Explainability & Stability",
            "6. Seminar Technical Reports"
        ]
    )
    
    if menu == "1. Research Executive Summary":
        st.title("🛡️ Robust and Explainable Network Intrusion Detection Under Adversarial Perturbations")
        st.markdown(
            "> **Technical Seminar Research Implementation**  \n"
            "> **Researcher:** Aditya Ambare (Roll: TIA26) | **Department:** Information Technology"
        )
        st.markdown("---")
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Dataset Flows", "5,918,803", "NF-CSE-CIC-IDS2018")
        col2.metric("Best Clean Accuracy", "98.16%", "XGBoost Binary")
        col3.metric("Clean Macro-F1", "0.9238", "Zero Data Leakage")
        col4.metric("Evasion at eps=0.20", "21.94%", "Under Domain Invariants")
        
        st.subheader("Core Research Ideology")
        st.markdown(r"""
        The objective of this research is not merely to achieve high classification accuracy on clean benchmark data. 
        Instead, we evaluate whether network intrusion detection predictions and their **SHAP explainability attributions**
        remain dependable when inputs are subjected to **controlled adversarial perturbations under physical network flow invariants**.
        
        ### Key Scientific Questions Answered:
        1. **Clean Detection Performance:** How accurately do tree models (Decision Tree, Random Forest, XGBoost) detect attacks under strict leakage-free conditions? (XGBoost: **98.16% Acc, 0.9238 Macro-F1**).
        2. **Explainability:** Which flow features dominate model decisions? (`OUT_BYTES`, `FLOW_DURATION_MILLISECONDS`, and packet-byte ratios dominate).
        3. **Adversarial Robustness:** How do models behave under domain-constrained perturbations (padding, packet injection, delay)? (At $\epsilon=0.20$, evasion rate reaches **21.9% - 28.5%**; at $\epsilon=0.50$, recall drops to **51% - 58%**).
        4. **Explanation Stability:** Do SHAP explanations remain stable when predictions evade? (In **22.4%** of flows, explanations shift reflective of evasion; however, in **0.4%**, explanations remain deceptively stable, proving stability alone is insufficient as a security metric).
        """)
        
        # Display tradeoff chart
        tradeoff_img = OUTPUTS_DIR / "metrics" / "comparative_tradeoff_chart.png"
        if tradeoff_img.exists():
            st.image(str(tradeoff_img), caption="Clean Macro-F1 vs Adversarial Robustness Trade-off & Port Feature Ablation")

    elif menu == "2. Dataset Audit & Statistics":
        st.title("📊 Dataset Audit: NF-CSE-CIC-IDS2018")
        audit_json_path = OUTPUTS_DIR / "audit" / "dataset_audit.json"
        
        if audit_json_path.exists():
            with open(audit_json_path) as f:
                audit = json.load(f)
                
            c1, c2, c3 = st.columns(3)
            c1.metric("Total Records", f"{audit['total_records']:,}")
            c2.metric("Benign Flows", f"{audit['binary_distribution']['Benign (0)']:,} (93.51%)")
            c3.metric("Attack Flows", f"{audit['binary_distribution']['Attack (1)']:,} (6.49%)")
            
            st.subheader("Class Distribution Plots")
            dist_img = OUTPUTS_DIR / "audit" / "class_distribution.png"
            if dist_img.exists():
                st.image(str(dist_img), use_container_width=True)
                
            st.subheader("Feature Summary Statistics")
            feat_csv = OUTPUTS_DIR / "audit" / "feature_summary.csv"
            if feat_csv.exists():
                df_feat = pd.read_csv(feat_csv)
                st.dataframe(df_feat, use_container_width=True)

    elif menu == "3. Model Comparative Evaluation":
        st.title("📈 Machine Learning Baselines & Comparative Evaluation")
        
        comp_csv = OUTPUTS_DIR / "metrics" / "model_comparison_table.csv"
        if comp_csv.exists():
            df_comp = pd.read_csv(comp_csv)
            st.subheader("Clean vs Adversarial Master Comparison (8 Features)")
            st.dataframe(df_comp.style.format({
                "accuracy": "{:.4f}",
                "macro_f1": "{:.4f}",
                "attack_recall": "{:.4f}",
                "false_positive_rate": "{:.4f}",
                "evasion_rate_eps_0.20": "{:.4f}",
                "train_time_sec": "{:.2f}s",
                "inference_latency_ms": "{:.4f} ms"
            }), use_container_width=True)
            
        st.subheader("Port Feature Ablation Study")
        st.markdown(
            "Comparing baseline models excluding transport ports (`PROTOCOL`, `L7_PROTO`, `IN_BYTES`, `OUT_BYTES`, `IN_PKTS`, `OUT_PKTS`, `TCP_FLAGS`, `FLOW_DURATION`) "
            "against models including `L4_SRC_PORT` and `L4_DST_PORT`."
        )
        ablation_csv = OUTPUTS_DIR / "metrics" / "port_ablation_results.csv"
        if ablation_csv.exists():
            df_abl = pd.read_csv(ablation_csv)
            st.dataframe(df_abl.style.format({
                "accuracy": "{:.4f}",
                "macro_f1": "{:.4f}",
                "attack_recall": "{:.4f}",
                "false_positive_rate": "{:.4f}",
                "evasion_rate_eps_0.20": "{:.4f}"
            }), use_container_width=True)
            
        st.subheader("Multiclass Evaluation on 15 Attack Categories")
        st.info("Demonstrating that uncalibrated weighting on extreme minority classes (e.g. SQL Injection with 36 samples) collapses Benign recall, whereas macro-F1 accurately exposes minority failures.")
        xgb_mc_csv = OUTPUTS_DIR / "metrics" / "classification_reports" / "xgboost_multiclass_report.csv"
        if xgb_mc_csv.exists():
            df_mc = pd.read_csv(xgb_mc_csv, index_col=0)
            st.dataframe(df_mc.style.format("{:.4f}"), use_container_width=True)

    elif menu == "4. Interactive Adversarial Flow Simulator":
        st.title("🎯 Interactive Adversarial Flow Evasion Simulator")
        st.markdown(
            "Select a real malicious flow from the test set or input custom parameters, apply domain-constrained "
            "perturbations (payload padding, packet injection, delay), and observe model prediction flips in real time."
        )
        
        models_dict, explainer = load_models_and_explainer()
        X_test, y_test_df = load_test_sample()
        
        # Select sample
        attack_idx_pool = np.where(y_test_df["Label"] == 1)[0]
        selected_sample_idx = st.selectbox(
            "Select Malicious Flow Sample (Index from Test Set):",
            attack_idx_pool[:20],
            format_func=lambda idx: f"Flow #{idx} | Attack Category: {y_test_df['Attack'].iloc[idx]}"
        )
        
        clean_row = X_test.iloc[selected_sample_idx].copy()
        
        st.markdown("#### Clean Network Flow Attributes")
        cols = st.columns(4)
        cols[0].metric("IN_BYTES", f"{clean_row['IN_BYTES']:,}")
        cols[1].metric("OUT_BYTES", f"{clean_row['OUT_BYTES']:,}")
        cols[2].metric("IN_PKTS", f"{clean_row['IN_PKTS']:,}")
        cols[3].metric("FLOW_DURATION (ms)", f"{clean_row['FLOW_DURATION_MILLISECONDS']:,}")
        
        st.markdown("---")
        st.subheader("Apply Adversarial Perturbation")
        eps = st.slider(r"Perturbation Budget ($\epsilon$):", 0.0, 0.50, 0.20, step=0.05)
        
        from src.adversarial.threats import ThreatModel, enforce_domain_constraints
        threat = ThreatModel()
        
        pert_row = clean_row.copy()
        for f in threat.mutable_features:
            pert_row[f] = pert_row[f] * (1.0 + eps)
            if "PKTS" in f:
                pert_row[f] = max(pert_row[f], clean_row[f] + (1 if eps > 0 else 0))
                
        df_pert = enforce_domain_constraints(pd.DataFrame([pert_row]), pd.DataFrame([clean_row]))
        pert_row_fixed = df_pert.iloc[0]
        
        # Predictions
        xgb = models_dict["XGBoost"]
        clean_prob = xgb.predict_proba(pd.DataFrame([clean_row]))[0, 1]
        pert_prob = xgb.predict_proba(df_pert)[0, 1]
        
        res_col1, res_col2 = st.columns(2)
        with res_col1:
            st.markdown("### 🟢 Clean Traffic Analysis")
            st.metric("Attack Probability", f"{clean_prob*100:.2f}%")
            st.info(f"Prediction: **{'ATTACK (1)' if clean_prob >= 0.5 else 'BENIGN (0)'}**")
            
        with res_col2:
            st.markdown("### 🔴 Perturbed Traffic Analysis")
            st.metric("Attack Probability", f"{pert_prob*100:.2f}%", delta=f"{(pert_prob - clean_prob)*100:.2f}%")
            if clean_prob >= 0.5 and pert_prob < 0.5:
                st.error("🚨 EVASION SUCCESSFUL! Attack disguised as Benign traffic.")
            elif clean_prob >= 0.5 and pert_prob >= 0.5:
                st.success("🛡️ ATTACK STILL DETECTED. Model remained robust.")
            else:
                st.warning(f"Prediction: {'ATTACK (1)' if pert_prob >= 0.5 else 'BENIGN (0)'}")

    elif menu == "5. SHAP Explainability & Stability":
        st.title("🔍 Explainable AI & Explanation Stability")
        
        st.subheader("Global SHAP Feature Importance")
        g_imp_csv = OUTPUTS_DIR / "shap" / "shap_global_importance.csv"
        if g_imp_csv.exists():
            df_g = pd.read_csv(g_imp_csv)
            st.dataframe(df_g.style.format({"mean_abs_shap": "{:.4f}"}), use_container_width=True)
            
        c1, c2 = st.columns(2)
        with c1:
            beeswarm_img = OUTPUTS_DIR / "shap" / "shap_summary_beeswarm.png"
            if beeswarm_img.exists():
                st.image(str(beeswarm_img), caption="SHAP Summary Beeswarm Plot")
        with c2:
            bar_img = OUTPUTS_DIR / "shap" / "shap_importance_bar.png"
            if bar_img.exists():
                st.image(str(bar_img), caption="Global Feature Importance Bar Plot")
                
        st.markdown("---")
        st.subheader("Explanation Stability Under Adversarial Perturbations")
        stab_img = OUTPUTS_DIR / "stability" / "explanation_stability.png"
        if stab_img.exists():
            st.image(str(stab_img), use_container_width=True)
            
        quad_csv = OUTPUTS_DIR / "stability" / "quadrant_analysis.csv"
        if quad_csv.exists():
            df_quad = pd.read_csv(quad_csv)
            st.markdown("#### Four-Quadrant Prediction vs Explanation Distribution")
            st.dataframe(df_quad["quadrant"].value_counts().reset_index(), use_container_width=True)

    elif menu == "6. Seminar Technical Reports":
        st.title("📄 University Seminar Technical Reports")
        
        reports = {
            "Phase 1: Dataset Audit Report": OUTPUTS_DIR / "audit" / "dataset_audit.md",
            "Phase 4: SHAP Explainability Report": OUTPUTS_DIR / "shap" / "shap_explanation_report.md",
            "Phase 5: Adversarial Robustness Report": OUTPUTS_DIR / "adversarial" / "adversarial_evaluation_report.md",
            "Phase 6: Explanation Stability Report": OUTPUTS_DIR / "stability" / "explanation_stability_report.md",
            "Phase 7: Comparative Evaluation Report": OUTPUTS_DIR / "comparative_evaluation_report.md",
            "Phase 8: Cross-Dataset Alignment Protocol": OUTPUTS_DIR / "cross_dataset" / "unsw_nb15_evaluation_protocol.md"
        }
        
        chosen_rep = st.selectbox("Select Report to View:", list(reports.keys()))
        rep_path = reports[chosen_rep]
        if rep_path.exists():
            with open(rep_path, encoding="utf-8") as f:
                st.markdown(f.read())
        else:
            st.warning("Report not found on disk.")

if __name__ == "__main__":
    main()
