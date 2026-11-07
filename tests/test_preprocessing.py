"""
Tests for Phase 2: Preprocessing and Data Leakage Prevention.
"""

import pytest
import numpy as np
import pandas as pd
from src.preprocessing.pipeline import NIDSPreprocessor, prepare_nids_splits
from src.utils.config import BASELINE_FEATURES, PORT_FEATURES

def test_nids_preprocessor_no_leakage():
    # Synthetic dataset with missing values in train and test
    X_train = pd.DataFrame({
        "A": [1.0, 3.0, 5.0, np.nan], # median of clean = 3.0
        "B": [10.0, 20.0, 30.0, 40.0]
    })
    X_test = pd.DataFrame({
        "A": [np.nan, 100.0],
        "B": [50.0, 60.0]
    })
    
    preprocessor = NIDSPreprocessor()
    X_train_trans = preprocessor.fit_transform(X_train)
    X_test_trans = preprocessor.transform(X_test)
    
    # Check that test nan was imputed with train median (3.0), NOT test mean/median
    assert X_test_trans["A"].iloc[0] == 3.0
    assert not X_train_trans.isnull().any().any()
    assert not X_test_trans.isnull().any().any()

def test_prepare_nids_splits_shapes_and_features():
    # Test on a small sample of 2,000 rows
    splits = prepare_nids_splits(sample_size=2_000, use_ports=False, cache_to_disk=False)
    
    # Verify split sizes (70% train, 15% val, 15% test)
    assert len(splits.X_train) == 1400
    assert len(splits.X_val) == 300
    assert len(splits.X_test) == 300
    
    # Verify feature columns strictly equal baseline features
    assert list(splits.X_train.columns) == BASELINE_FEATURES
    assert "Label" not in splits.X_train.columns
    assert "Attack" not in splits.X_train.columns
    assert "L4_SRC_PORT" not in splits.X_train.columns
    
    # Verify stratification
    train_mean = splits.y_binary_train.mean()
    val_mean = splits.y_binary_val.mean()
    test_mean = splits.y_binary_test.mean()
    assert pytest.approx(train_mean, abs=0.02) == val_mean
    assert pytest.approx(train_mean, abs=0.02) == test_mean

def test_prepare_nids_splits_with_ports():
    splits = prepare_nids_splits(sample_size=1_000, use_ports=True, cache_to_disk=False)
    assert len(splits.X_train.columns) == len(BASELINE_FEATURES) + len(PORT_FEATURES)
    assert "L4_SRC_PORT" in splits.X_train.columns
    assert "L4_DST_PORT" in splits.X_train.columns

