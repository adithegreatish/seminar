"""
Execution script for Phase 3: Train and Evaluate Machine Learning Baselines.
Covers Binary Classification and Multiclass Classification across DT, RF, and XGBoost.
"""

import sys
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.metrics import confusion_matrix

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.utils.config import (
    RANDOM_SEED,
    DEFAULT_SAMPLE_SIZE,
    METRICS_OUTPUT_DIR,
    MODELS_OUTPUT_DIR
)
from src.utils.logger import setup_logger
from src.preprocessing.pipeline import prepare_nids_splits
from src.models.baseline_models import create_binary_models, create_multiclass_models
from src.evaluation.metrics import (
    compute_binary_metrics,
    compute_multiclass_metrics,
    plot_and_save_confusion_matrix
)

logger = setup_logger("script_01_baselines")

def run_binary_pipeline(splits):
    logger.info("=========================================================")
    logger.info("STARTING BINARY CLASSIFICATION PIPELINE (Benign=0, Attack=1)")
    logger.info("=========================================================")
    
    models = create_binary_models(random_seed=RANDOM_SEED)
    metrics_records = []
    
    # Compute sample weight for XGBoost binary training
    sample_weights_binary = compute_sample_weight(
        class_weight="balanced",
        y=splits.y_binary_train
    )
    
    # 1. Validation phase (Model Selection)
    val_macro_f1s = {}
    fitted_models = {}
    
    for name, model_wrapper in models.items():
        logger.info(f"--- Fitting {name} ---")
        if model_wrapper.model_type == "xgboost":
            model_wrapper.fit(splits.X_train, splits.y_binary_train, sample_weight=sample_weights_binary)
        else:
            model_wrapper.fit(splits.X_train, splits.y_binary_train)
            
        fitted_models[name] = model_wrapper
        model_wrapper.save(MODELS_OUTPUT_DIR)
        
        # Validation Evaluation
        y_val_pred, val_latency = model_wrapper.predict(splits.X_val)
        y_val_prob = model_wrapper.predict_proba(splits.X_val)
        
        val_metrics = compute_binary_metrics(
            y_true=splits.y_binary_val.values,
            y_pred=y_val_pred,
            y_prob=y_val_prob,
            train_time=model_wrapper.train_time,
            inference_time_ms=val_latency,
            model_name=name,
            split_name="validation"
        )
        metrics_records.append(val_metrics)
        val_macro_f1s[name] = val_metrics["macro_f1"]
        logger.info(
            f"[{name}] Val Macro-F1: {val_metrics['macro_f1']:.4f} | "
            f"Val Accuracy: {val_metrics['accuracy']:.4f} | "
            f"Val FPR: {val_metrics['false_positive_rate']:.4f} | "
            f"Val Attack Recall: {val_metrics['attack_recall']:.4f}"
        )
        
    # Model Selection criterion
    best_model_name = max(val_macro_f1s, key=val_macro_f1s.get)
    logger.info(f">>> BEST BINARY MODEL SELECTED BY VALIDATION MACRO-F1: {best_model_name} (Macro-F1: {val_macro_f1s[best_model_name]:.4f}) <<<")
    
    # 2. Test Set Evaluation
    logger.info("--- Evaluating Models on Unseen Test Partition ---")
    for name, model_wrapper in fitted_models.items():
        y_test_pred, test_latency = model_wrapper.predict(splits.X_test)
        y_test_prob = model_wrapper.predict_proba(splits.X_test)
        
        test_metrics = compute_binary_metrics(
            y_true=splits.y_binary_test.values,
            y_pred=y_test_pred,
            y_prob=y_test_prob,
            train_time=model_wrapper.train_time,
            inference_time_ms=test_latency,
            model_name=name,
            split_name="test"
        )
        metrics_records.append(test_metrics)
        logger.info(
            f"[{name}] TEST Macro-F1: {test_metrics['macro_f1']:.4f} | "
            f"TEST Accuracy: {test_metrics['accuracy']:.4f} | "
            f"TEST FPR: {test_metrics['false_positive_rate']:.4f} | "
            f"TEST Attack F1: {test_metrics['attack_f1']:.4f}"
        )
        
        # Save confusion matrix plot
        cm = confusion_matrix(splits.y_binary_test.values, y_test_pred, labels=[0, 1])
        cm_path = METRICS_OUTPUT_DIR / "confusion_matrices" / f"{name.lower().replace(' ', '_')}_binary_cm.png"
        plot_and_save_confusion_matrix(
            cm=cm,
            classes=["Benign", "Attack"],
            title=f"{name} Binary Confusion Matrix (Test Set)",
            output_path=cm_path
        )
        
    return metrics_records, best_model_name, fitted_models

def run_multiclass_pipeline(splits):
    logger.info("=========================================================")
    logger.info("STARTING MULTICLASS CLASSIFICATION PIPELINE (Attack taxonomy)")
    logger.info("=========================================================")
    
    # Label encode attack categories
    encoder = LabelEncoder()
    # Fit encoder on train labels
    y_train_encoded = encoder.fit_transform(splits.y_multi_train)
    
    # Handle possible unseen classes in val/test safely
    classes = list(encoder.classes_)
    num_classes = len(classes)
    logger.info(f"Target classes ({num_classes}): {classes}")
    
    # Transform val and test
    def safe_transform(series):
        return np.array([encoder.transform([x])[0] if x in encoder.classes_ else -1 for x in series])
        
    y_val_encoded = safe_transform(splits.y_multi_val)
    y_test_encoded = safe_transform(splits.y_multi_test)
    
    # Filter any unseen classes if present
    val_mask = y_val_encoded != -1
    test_mask = y_test_encoded != -1
    
    # Balanced weights for multiclass
    sample_weights_multi = compute_sample_weight(
        class_weight="balanced",
        y=y_train_encoded
    )
    
    models = create_multiclass_models(num_classes=num_classes, random_seed=RANDOM_SEED)
    multi_metrics_records = []
    
    for name, model_wrapper in models.items():
        logger.info(f"--- Fitting Multiclass {name} ---")
        if model_wrapper.model_type == "xgboost":
            model_wrapper.fit(splits.X_train, y_train_encoded, sample_weight=sample_weights_multi)
        else:
            model_wrapper.fit(splits.X_train, y_train_encoded)
            
        model_wrapper.save(MODELS_OUTPUT_DIR)
        
        # Test evaluation
        y_test_pred_enc, test_latency = model_wrapper.predict(splits.X_test[test_mask])
        y_test_actual = y_test_encoded[test_mask]
        
        summary, per_class_df = compute_multiclass_metrics(
            y_true=y_test_actual,
            y_pred=y_test_pred_enc,
            labels=list(range(num_classes)),
            train_time=model_wrapper.train_time,
            inference_time_ms=test_latency,
            model_name=name,
            split_name="test"
        )
        
        # Map indices back to class names for the report
        per_class_df.index = [classes[i] if isinstance(i, int) and i < num_classes else str(i) for i in per_class_df.index]
        report_path = METRICS_OUTPUT_DIR / "classification_reports" / f"{name.lower().replace(' ', '_')}_report.csv"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        per_class_df.to_csv(report_path)
        
        multi_metrics_records.append(summary)
        logger.info(
            f"[{name}] Multiclass Test Macro-F1: {summary['macro_f1']:.4f} | "
            f"Test Accuracy: {summary['accuracy']:.4f} | "
            f"Weighted-F1: {summary['weighted_f1']:.4f}"
        )
        
        # Confusion matrix
        cm = confusion_matrix(y_test_actual, y_test_pred_enc, labels=list(range(num_classes)))
        cm_path = METRICS_OUTPUT_DIR / "confusion_matrices" / f"{name.lower().replace(' ', '_')}_multiclass_cm.png"
        plot_and_save_confusion_matrix(
            cm=cm,
            classes=classes,
            title=f"{name} Multiclass Confusion Matrix (Test Set)",
            output_path=cm_path
        )
        
    return multi_metrics_records

def main():
    logger.info("=== Phase 3: Machine Learning Baselines Training & Evaluation ===")
    
    # 1. Prepare 200,000 stratified sample splits
    splits = prepare_nids_splits(
        sample_size=DEFAULT_SAMPLE_SIZE,
        use_ports=False, # Baseline 8 features
        decompose_tcp_flags=False,
        scale_features=False,
        random_seed=RANDOM_SEED,
        cache_to_disk=True
    )
    
    # 2. Binary classification pipeline
    binary_records, best_binary_model, fitted_binary_models = run_binary_pipeline(splits)
    
    # 3. Multiclass classification pipeline
    multiclass_records = run_multiclass_pipeline(splits)
    
    # 4. Save aggregated metrics table
    all_metrics_df = pd.DataFrame(binary_records + multiclass_records)
    metrics_csv_path = METRICS_OUTPUT_DIR / "baseline_metrics.csv"
    METRICS_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_metrics_df.to_csv(metrics_csv_path, index=False)
    logger.info(f"Saved aggregated baseline metrics to {metrics_csv_path}")
    
    # 5. Save run configuration
    run_config = {
        "dataset": "NF-CSE-CIC-IDS2018",
        "sample_size": DEFAULT_SAMPLE_SIZE,
        "train_size": len(splits.X_train),
        "val_size": len(splits.X_val),
        "test_size": len(splits.X_test),
        "features": splits.feature_names,
        "best_binary_model": best_binary_model,
        "random_seed": RANDOM_SEED
    }
    config_path = METRICS_OUTPUT_DIR / "run_config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(run_config, f, indent=4)
    logger.info(f"Saved run configuration to {config_path}")
    
    print("\n================== BASELINE METRICS SUMMARY ==================")
    print(all_metrics_df[["model", "split", "accuracy", "macro_f1", "weighted_f1", "train_time_sec", "inference_latency_ms"]].to_string())
    print("==============================================================")

if __name__ == "__main__":
    main()

