"""
Evaluation metrics calculation and reporting module.
"""

from pathlib import Path
import json
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

def compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray | None = None,
    train_time: float = 0.0,
    inference_time_ms: float = 0.0,
    model_name: str = "Model",
    split_name: str = "val"
) -> dict:
    """
    Computes full set of binary classification metrics including False Positive Rate.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    acc = accuracy_score(y_true, y_pred)
    prec_macro = precision_score(y_true, y_pred, average="macro", zero_division=0)
    rec_macro = recall_score(y_true, y_pred, average="macro", zero_division=0)
    f1_macro = f1_score(y_true, y_pred, average="macro", zero_division=0)
    f1_weighted = f1_score(y_true, y_pred, average="weighted", zero_division=0)
    
    # Class-specific (Benign=0, Attack=1)
    prec_benign, prec_attack = precision_score(y_true, y_pred, average=None, labels=[0, 1], zero_division=0)
    rec_benign, rec_attack = recall_score(y_true, y_pred, average=None, labels=[0, 1], zero_division=0)
    f1_benign, f1_attack = f1_score(y_true, y_pred, average=None, labels=[0, 1], zero_division=0)
    
    auc = np.nan
    if y_prob is not None:
        try:
            if len(y_prob.shape) > 1 and y_prob.shape[1] > 1:
                prob_pos = y_prob[:, 1]
            else:
                prob_pos = y_prob
            auc = roc_auc_score(y_true, prob_pos)
        except Exception:
            auc = np.nan
            
    return {
        "model": model_name,
        "split": split_name,
        "accuracy": float(acc),
        "macro_precision": float(prec_macro),
        "macro_recall": float(rec_macro),
        "macro_f1": float(f1_macro),
        "weighted_f1": float(f1_weighted),
        "roc_auc": float(auc) if not np.isnan(auc) else None,
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "benign_precision": float(prec_benign),
        "benign_recall": float(rec_benign),
        "benign_f1": float(f1_benign),
        "attack_precision": float(prec_attack),
        "attack_recall": float(rec_attack),
        "attack_f1": float(f1_attack),
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        "train_time_sec": float(train_time),
        "inference_latency_ms": float(inference_time_ms)
    }

def compute_multiclass_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    labels: list[str],
    train_time: float = 0.0,
    inference_time_ms: float = 0.0,
    model_name: str = "Model",
    split_name: str = "val"
) -> tuple[dict, pd.DataFrame]:
    """
    Computes multiclass macro, weighted and per-class metrics.
    """
    acc = accuracy_score(y_true, y_pred)
    macro_prec = precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    macro_rec = recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    macro_f1 = f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_true, y_pred, labels=labels, average="weighted", zero_division=0)
    
    # Per-class report
    clf_report_dict = classification_report(
        y_true, y_pred, labels=labels, output_dict=True, zero_division=0
    )
    per_class_df = pd.DataFrame(clf_report_dict).transpose()
    
    summary = {
        "model": model_name,
        "split": split_name,
        "accuracy": float(acc),
        "macro_precision": float(macro_prec),
        "macro_recall": float(macro_rec),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
        "train_time_sec": float(train_time),
        "inference_latency_ms": float(inference_time_ms)
    }
    return summary, per_class_df

def plot_and_save_confusion_matrix(
    cm: np.ndarray,
    classes: list[str],
    title: str,
    output_path: Path,
    normalize: bool = False
):
    """Plots and saves confusion matrix heatmap."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if normalize:
        cm_norm = cm.astype('float') / (cm.sum(axis=1)[:, np.newaxis] + 1e-9)
        fmt = ".2f"
        data_to_plot = cm_norm
    else:
        fmt = "d"
        data_to_plot = cm
        
    plt.figure(figsize=(8 if len(classes) <= 5 else 14, 6 if len(classes) <= 5 else 12))
    sns.heatmap(
        data_to_plot,
        annot=True,
        fmt=fmt,
        cmap="Blues",
        xticklabels=classes,
        yticklabels=classes
    )
    plt.title(title, fontsize=12, fontweight="bold")
    plt.ylabel("Actual Label", fontsize=10)
    plt.xlabel("Predicted Label", fontsize=10)
    if len(classes) > 5:
        plt.xticks(rotation=90, fontsize=8)
        plt.yticks(rotation=0, fontsize=8)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()

