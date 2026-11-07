"""
SHAP Explainability Module for Tree-based NIDS Models.
Calculates Global and Local SHAP attributions using TreeExplainer.
"""

from pathlib import Path
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import shap
import shap.explainers._tree as tree_mod

# Fix XGBoost 3.x compatibility in SHAP TreeExplainer where base_score is serialized as '[5E-1]'
_orig_decode = tree_mod.decode_ubjson_buffer

def _patched_decode(fd):
    jmodel = _orig_decode(fd)
    try:
        lmp = jmodel.get("learner", {}).get("learner_model_param", {})
        if "base_score" in lmp and isinstance(lmp["base_score"], str):
            lmp["base_score"] = lmp["base_score"].strip("[]")
    except Exception:
        pass
    return jmodel

tree_mod.decode_ubjson_buffer = _patched_decode

from src.utils.config import SHAP_OUTPUT_DIR
from src.utils.logger import setup_logger
from src.models.baseline_models import NIDSModelWrapper

logger = setup_logger("shap_explainer")

class NIDSShapExplainer:
    """Wrapper for TreeExplainer computation and visualization."""
    def __init__(self, model_wrapper: NIDSModelWrapper):
        self.model_wrapper = model_wrapper
        self.estimator = model_wrapper.estimator
        self.explainer = None
        self.expected_value = None

    def fit_explainer(self, background_data: pd.DataFrame | None = None):
        """Initializes shap.TreeExplainer."""
        logger.info(f"Initializing SHAP TreeExplainer for {self.model_wrapper.name}...")
        try:
            self.explainer = shap.TreeExplainer(self.estimator, data=background_data)
        except Exception as e:
            logger.warning(f"TreeExplainer with background data note ({e}), using standard TreeExplainer")
            self.explainer = shap.TreeExplainer(self.estimator)
            
        self.expected_value = self.explainer.expected_value
        logger.info(f"TreeExplainer initialized successfully. Base value: {self.expected_value}")
        return self

    def compute_shap_values(self, X: pd.DataFrame) -> tuple[np.ndarray, shap.Explanation]:
        """Computes SHAP values for given evaluation samples."""
        if self.explainer is None:
            self.fit_explainer()
            
        logger.info(f"Computing SHAP values on {len(X):,} samples...")
        shap_values_raw = self.explainer.shap_values(X)
        
        # Format binary classification SHAP values cleanly: positive class (Attack = 1)
        if isinstance(shap_values_raw, list):
            # scikit-learn tree classifiers return [class_0_shap, class_1_shap]
            shap_values_attack = shap_values_raw[1] if len(shap_values_raw) > 1 else shap_values_raw[0]
        elif isinstance(shap_values_raw, np.ndarray) and len(shap_values_raw.shape) == 3:
            shap_values_attack = shap_values_raw[:, :, 1]
        else:
            shap_values_attack = shap_values_raw
            
        base_val = self.expected_value[1] if isinstance(self.expected_value, (list, np.ndarray)) and len(self.expected_value) > 1 else self.expected_value
        if isinstance(base_val, (list, np.ndarray)):
            base_val = float(base_val[0])
        else:
            base_val = float(base_val) if base_val is not None else 0.0
            
        explanation = shap.Explanation(
            values=shap_values_attack,
            base_values=base_val,
            data=X.values,
            feature_names=list(X.columns)
        )
        return shap_values_attack, explanation

def plot_local_waterfall_fallback(explanation_single: shap.Explanation, title: str, output_path: Path):
    """Custom reliable waterfall bar plot for local sample attributions."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    features = explanation_single.feature_names
    values = explanation_single.values
    data = explanation_single.data
    base = float(explanation_single.base_values) if hasattr(explanation_single, "base_values") else 0.0
    
    # Sort by absolute SHAP contribution
    order = np.argsort(np.abs(values))
    sorted_features = [f"{features[i]} ({data[i]:.2f})" for i in order]
    sorted_values = values[order]
    
    colors = ["#d95f02" if v > 0 else "#2b5c8f" for v in sorted_values]
    
    plt.figure(figsize=(9, 5))
    bars = plt.barh(sorted_features, sorted_values, color=colors)
    plt.axvline(0, color="gray", linestyle="--", linewidth=0.8)
    plt.xlabel("SHAP Value (Impact on Attack Prediction)")
    plt.title(f"{title}\nBase Value: {base:.3f} | Model Output: {base + float(np.sum(values)):.3f}", fontsize=11, fontweight="bold")
    
    for bar in bars:
        width = bar.get_width()
        ha = "left" if width >= 0 else "right"
        offset = 0.02 if width >= 0 else -0.02
        plt.text(width + offset, bar.get_y() + bar.get_height()/2, f"{width:+.3f}",
                 va='center', ha=ha, fontsize=9)
                 
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
