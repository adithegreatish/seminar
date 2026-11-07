"""
Machine Learning Baseline Classifiers for NIDS.
Includes Decision Tree, Random Forest, and XGBoost.
"""

import time
import joblib
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from src.utils.config import RANDOM_SEED, MODELS_OUTPUT_DIR
from src.utils.logger import setup_logger

logger = setup_logger("models")

class NIDSModelWrapper:
    """Standardized wrapper for NIDS classifiers."""
    def __init__(self, name: str, model_type: str, estimator, is_multiclass: bool = False):
        self.name = name
        self.model_type = model_type
        self.estimator = estimator
        self.is_multiclass = is_multiclass
        self.train_time: float = 0.0
        self.classes_: np.ndarray | None = None

    def fit(self, X: pd.DataFrame, y: pd.Series, sample_weight: np.ndarray | None = None):
        logger.info(f"Training {self.name} on {len(X):,} samples...")
        start_t = time.time()
        if sample_weight is not None and hasattr(self.estimator, "fit"):
            try:
                self.estimator.fit(X, y, sample_weight=sample_weight)
            except TypeError:
                self.estimator.fit(X, y)
        else:
            self.estimator.fit(X, y)
        self.train_time = time.time() - start_t
        self.classes_ = getattr(self.estimator, "classes_", np.unique(y))
        logger.info(f"Trained {self.name} in {self.train_time:.2f} seconds.")
        return self

    def predict(self, X: pd.DataFrame) -> tuple[np.ndarray, float]:
        """Returns predictions and per-sample inference latency in milliseconds."""
        start_t = time.time()
        preds = self.estimator.predict(X)
        latency_ms = ((time.time() - start_t) / max(1, len(X))) * 1000.0
        return preds, latency_ms

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray | None:
        if hasattr(self.estimator, "predict_proba"):
            return self.estimator.predict_proba(X)
        return None

    def save(self, output_dir: Path = MODELS_OUTPUT_DIR) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{self.name.lower().replace(' ', '_')}.joblib"
        path = output_dir / filename
        joblib.dump(self, path)
        logger.info(f"Saved model artifact to {path}")
        return path

    @staticmethod
    def load(model_path: Path) -> "NIDSModelWrapper":
        model = joblib.load(model_path)
        logger.info(f"Loaded model artifact from {model_path}")
        return model

def create_binary_models(random_seed: int = RANDOM_SEED) -> dict[str, NIDSModelWrapper]:
    """Factory function for binary baseline classifiers."""
    models = {
        "Decision Tree": NIDSModelWrapper(
            name="Decision Tree Binary",
            model_type="decision_tree",
            estimator=DecisionTreeClassifier(
                max_depth=12,
                min_samples_split=20,
                min_samples_leaf=10,
                class_weight="balanced",
                random_state=random_seed
            ),
            is_multiclass=False
        ),
        "Random Forest": NIDSModelWrapper(
            name="Random Forest Binary",
            model_type="random_forest",
            estimator=RandomForestClassifier(
                n_estimators=100,
                max_depth=16,
                min_samples_split=10,
                min_samples_leaf=5,
                class_weight="balanced",
                n_jobs=-1,
                random_state=random_seed
            ),
            is_multiclass=False
        ),
        "XGBoost": NIDSModelWrapper(
            name="XGBoost Binary",
            model_type="xgboost",
            estimator=XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                objective="binary:logistic",
                eval_metric="logloss",
                tree_method="hist",
                n_jobs=-1,
                random_state=random_seed
            ),
            is_multiclass=False
        )
    }
    return models

def create_multiclass_models(num_classes: int, random_seed: int = RANDOM_SEED) -> dict[str, NIDSModelWrapper]:
    """Factory function for multiclass baseline classifiers."""
    models = {
        "Decision Tree Multiclass": NIDSModelWrapper(
            name="Decision Tree Multiclass",
            model_type="decision_tree",
            estimator=DecisionTreeClassifier(
                max_depth=14,
                min_samples_split=20,
                min_samples_leaf=5,
                class_weight="balanced",
                random_state=random_seed
            ),
            is_multiclass=True
        ),
        "Random Forest Multiclass": NIDSModelWrapper(
            name="Random Forest Multiclass",
            model_type="random_forest",
            estimator=RandomForestClassifier(
                n_estimators=100,
                max_depth=18,
                min_samples_split=10,
                class_weight="balanced",
                n_jobs=-1,
                random_state=random_seed
            ),
            is_multiclass=True
        ),
        "XGBoost Multiclass": NIDSModelWrapper(
            name="XGBoost Multiclass",
            model_type="xgboost",
            estimator=XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                objective="multi:softprob",
                eval_metric="mlogloss",
                tree_method="hist",
                n_jobs=-1,
                random_state=random_seed
            ),
            is_multiclass=True
        )
    }
    return models

