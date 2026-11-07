"""
Tests for Phase 3: Model definitions, training, prediction, and serialization.
"""

import pytest
import numpy as np
import pandas as pd
from pathlib import Path
import tempfile

from src.models.baseline_models import create_binary_models, NIDSModelWrapper
from src.evaluation.metrics import compute_binary_metrics

def test_model_wrapper_fit_predict_and_serialization():
    # Synthetic small dataset
    np.random.seed(42)
    X = pd.DataFrame(np.random.randn(100, 4), columns=["f1", "f2", "f3", "f4"])
    y = pd.Series(np.random.choice([0, 1], size=100))
    
    models = create_binary_models(random_seed=42)
    dt_wrapper = models["Decision Tree"]
    
    # Fit
    dt_wrapper.fit(X, y)
    assert dt_wrapper.train_time > 0
    
    # Predict
    preds, latency = dt_wrapper.predict(X)
    assert len(preds) == 100
    assert latency >= 0
    
    # Save & reload
    with tempfile.TemporaryDirectory() as tmp_dir:
        saved_path = dt_wrapper.save(Path(tmp_dir))
        assert saved_path.exists()
        reloaded = NIDSModelWrapper.load(saved_path)
        reloaded_preds, _ = reloaded.predict(X)
        assert np.array_equal(preds, reloaded_preds)

def test_compute_binary_metrics():
    y_true = np.array([0, 0, 1, 1, 0])
    y_pred = np.array([0, 0, 1, 0, 1]) # 1 FN, 1 FP
    metrics = compute_binary_metrics(y_true, y_pred, model_name="TestModel")
    
    assert metrics["model"] == "TestModel"
    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["true_negatives"] == 2
    assert metrics["false_negatives"] == 1
    assert pytest.approx(metrics["accuracy"]) == 3/5
    assert metrics["false_positive_rate"] == 1/3 # FP / (FP + TN)

