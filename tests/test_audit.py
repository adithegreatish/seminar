"""
Tests for Phase 1: Dataset Audit and Schema Validation.
"""

import pytest
from pathlib import Path
from src.utils.config import PRIMARY_DATASET_PARQUET, BASELINE_FEATURES, ALL_FEATURES
from src.data.loader import ensure_dataset_extracted, get_parquet_schema, load_dataset

def test_parquet_file_exists():
    path = ensure_dataset_extracted()
    assert path.exists()
    assert path.stat().st_size > 0

def test_parquet_schema():
    schema = get_parquet_schema()
    field_names = schema.names
    for feat in ALL_FEATURES + ["Label", "Attack"]:
        assert feat in field_names, f"Missing expected column: {feat}"

def test_label_mapping():
    # Load a small sample to verify label mapping
    df = load_dataset(sample_size=10_000, stratify_col="Label")
    assert 0 in df["Label"].values
    assert 1 in df["Label"].values
    
    # Benign must only be Label 0
    benign_labels = df[df["Attack"] == "Benign"]["Label"].unique()
    assert list(benign_labels) == [0], f"Expected Benign to have label 0 only, got {benign_labels}"
    
    # Attacks must only be Label 1
    attack_labels = df[df["Attack"] != "Benign"]["Label"].unique()
    assert list(attack_labels) == [1], f"Expected Attacks to have label 1 only, got {attack_labels}"

