"""
Robust and Leakage-Free Preprocessing Pipeline for NIDS.
"""

from dataclasses import dataclass
from pathlib import Path
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from src.utils.config import (
    BASELINE_FEATURES,
    PORT_FEATURES,
    ALL_FEATURES,
    TARGET_BINARY,
    TARGET_MULTICLASS,
    RANDOM_SEED,
    DEFAULT_SAMPLE_SIZE,
    TRAIN_RATIO,
    VAL_RATIO,
    TEST_RATIO,
    PROCESSED_DATA_DIR,
    PRIMARY_DATASET_PARQUET
)
from src.utils.logger import setup_logger
from src.data.loader import load_dataset

logger = setup_logger("preprocessing")

@dataclass
class DatasetSplits:
    """Container for partitioned and preprocessed datasets."""
    X_train: pd.DataFrame
    X_val: pd.DataFrame
    X_test: pd.DataFrame
    y_binary_train: pd.Series
    y_binary_val: pd.Series
    y_binary_test: pd.Series
    y_multi_train: pd.Series
    y_multi_val: pd.Series
    y_multi_test: pd.Series
    feature_names: list[str]
    split_metadata: dict

class NIDSPreprocessor:
    """
    Handles sampling, feature selection, train/val/test splitting,
    and fit/transform preprocessing without data leakage.
    """
    def __init__(
        self,
        use_ports: bool = False,
        decompose_tcp_flags: bool = False,
        scale_features: bool = False,
        random_seed: int = RANDOM_SEED
    ):
        self.use_ports = use_ports
        self.decompose_tcp_flags = decompose_tcp_flags
        self.scale_features = scale_features
        self.random_seed = random_seed
        
        self.imputer = SimpleImputer(strategy="median")
        self.scaler = StandardScaler() if scale_features else None
        self.is_fitted = False
        self.feature_names_: list[str] = []

    def get_feature_list(self) -> list[str]:
        """Returns the base feature columns to extract."""
        features = list(BASELINE_FEATURES)
        if self.use_ports:
            features = PORT_FEATURES + features
        return features

    @staticmethod
    def extract_tcp_flag_bits(df: pd.DataFrame) -> pd.DataFrame:
        """Decomposes the TCP_FLAGS bitmask into individual semantic binary flags."""
        df = df.copy()
        flags = df["TCP_FLAGS"].astype(int)
        df["TCP_FLAG_FIN"] = (flags & 0x01).astype(int)
        df["TCP_FLAG_SYN"] = ((flags & 0x02) >> 1).astype(int)
        df["TCP_FLAG_RST"] = ((flags & 0x04) >> 2).astype(int)
        df["TCP_FLAG_PSH"] = ((flags & 0x08) >> 3).astype(int)
        df["TCP_FLAG_ACK"] = ((flags & 0x10) >> 4).astype(int)
        df["TCP_FLAG_URG"] = ((flags & 0x20) >> 5).astype(int)
        df["TCP_FLAG_ECE"] = ((flags & 0x40) >> 6).astype(int)
        df["TCP_FLAG_CWR"] = ((flags & 0x80) >> 7).astype(int)
        return df

    def fit(self, X_train: pd.DataFrame):
        """Fits imputer and scaler strictly on training features."""
        X_clean = X_train.replace([np.inf, -np.inf], np.nan)
        self.imputer.fit(X_clean)
        
        if self.scaler:
            X_imputed = self.imputer.transform(X_clean)
            self.scaler.fit(X_imputed)
            
        self.feature_names_ = list(X_train.columns)
        self.is_fitted = True
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        """Transforms features using strictly parameters learned from train fold."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fit before calling transform.")
            
        X_clean = X.replace([np.inf, -np.inf], np.nan)
        X_imputed = self.imputer.transform(X_clean)
        
        if self.scaler:
            X_transformed = self.scaler.transform(X_imputed)
        else:
            X_transformed = X_imputed
            
        return pd.DataFrame(X_transformed, columns=self.feature_names_, index=X.index)

    def fit_transform(self, X_train: pd.DataFrame) -> pd.DataFrame:
        return self.fit(X_train).transform(X_train)

def prepare_nids_splits(
    parquet_path: Path = PRIMARY_DATASET_PARQUET,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    use_ports: bool = False,
    decompose_tcp_flags: bool = False,
    scale_features: bool = False,
    random_seed: int = RANDOM_SEED,
    cache_to_disk: bool = True
) -> DatasetSplits:
    """
    End-to-end data preparation:
    1. Loads a reproducible stratified sample from the Parquet archive.
    2. Splits cleanly into 70% Train, 15% Val, 15% Test.
    3. Fits preprocessor strictly on Train, transforms Val and Test.
    4. Caches processed splits to disk for fast reuse.
    """
    logger.info(f"Preparing dataset splits: sample_size={sample_size:,}, ports={use_ports}, seed={random_seed}")
    
    # 1. Load stratified sample
    cols_to_load = BASELINE_FEATURES + PORT_FEATURES + [TARGET_BINARY, TARGET_MULTICLASS]
    df_sample = load_dataset(
        parquet_path=parquet_path,
        columns=cols_to_load,
        sample_size=sample_size,
        stratify_col=TARGET_BINARY,
        random_state=random_seed
    )
    
    # Select predictors
    features_to_use = list(BASELINE_FEATURES)
    if use_ports:
        features_to_use = PORT_FEATURES + features_to_use
        
    X_raw = df_sample[features_to_use].copy()
    if decompose_tcp_flags:
        X_raw = NIDSPreprocessor.extract_tcp_flag_bits(X_raw)
        
    y_binary = df_sample[TARGET_BINARY].astype(int)
    y_multi = df_sample[TARGET_MULTICLASS].astype(str)
    
    # 2. Perform 3-way stratified partition: 70% Train, 15% Val, 15% Test
    val_plus_test_ratio = VAL_RATIO + TEST_RATIO
    test_share_of_val_test = TEST_RATIO / val_plus_test_ratio  # 0.15 / 0.30 = 0.50
    
    X_train_raw, X_temp_raw, y_b_train, y_b_temp, y_m_train, y_m_temp = train_test_split(
        X_raw,
        y_binary,
        y_multi,
        train_size=TRAIN_RATIO,
        stratify=y_binary,
        random_state=random_seed
    )
    
    X_val_raw, X_test_raw, y_b_val, y_b_test, y_m_val, y_m_test = train_test_split(
        X_temp_raw,
        y_b_temp,
        y_m_temp,
        test_size=test_share_of_val_test,
        stratify=y_b_temp,
        random_state=random_seed
    )
    
    # 3. Fit preprocessor on training data only
    preprocessor = NIDSPreprocessor(
        use_ports=use_ports,
        decompose_tcp_flags=decompose_tcp_flags,
        scale_features=scale_features,
        random_seed=random_seed
    )
    
    X_train = preprocessor.fit_transform(X_train_raw)
    X_val = preprocessor.transform(X_val_raw)
    X_test = preprocessor.transform(X_test_raw)
    
    # 4. Compile metadata
    split_meta = {
        "sample_size": sample_size,
        "train_size": len(X_train),
        "val_size": len(X_val),
        "test_size": len(X_test),
        "feature_count": len(preprocessor.feature_names_),
        "features": preprocessor.feature_names_,
        "use_ports": use_ports,
        "decompose_tcp_flags": decompose_tcp_flags,
        "scale_features": scale_features,
        "random_seed": random_seed,
        "class_distributions": {
            "train": y_b_train.value_counts().to_dict(),
            "val": y_b_val.value_counts().to_dict(),
            "test": y_b_test.value_counts().to_dict(),
        }
    }
    
    logger.info(
        f"Splits complete: Train={len(X_train):,}, Val={len(X_val):,}, Test={len(X_test):,}. "
        f"Attack ratio train={y_b_train.mean():.4f}, val={y_b_val.mean():.4f}, test={y_b_test.mean():.4f}"
    )
    
    if cache_to_disk:
        cache_dir = PROCESSED_DATA_DIR / f"sample_{sample_size}_ports_{use_ports}"
        cache_dir.mkdir(parents=True, exist_ok=True)
        X_train.to_parquet(cache_dir / "X_train.parquet")
        X_val.to_parquet(cache_dir / "X_val.parquet")
        X_test.to_parquet(cache_dir / "X_test.parquet")
        pd.DataFrame({"Label": y_b_train, "Attack": y_m_train}).to_parquet(cache_dir / "y_train.parquet")
        pd.DataFrame({"Label": y_b_val, "Attack": y_m_val}).to_parquet(cache_dir / "y_val.parquet")
        pd.DataFrame({"Label": y_b_test, "Attack": y_m_test}).to_parquet(cache_dir / "y_test.parquet")
        with open(cache_dir / "split_metadata.json", "w", encoding="utf-8") as f:
            json.dump(split_meta, f, indent=4)
        logger.info(f"Cached processed splits to {cache_dir}")
        
    return DatasetSplits(
        X_train=X_train,
        X_val=X_val,
        X_test=X_test,
        y_binary_train=y_b_train,
        y_binary_val=y_b_val,
        y_binary_test=y_b_test,
        y_multi_train=y_m_train,
        y_multi_val=y_m_val,
        y_multi_test=y_m_test,
        feature_names=preprocessor.feature_names_,
        split_metadata=split_meta
    )

