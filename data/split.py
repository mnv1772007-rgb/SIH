import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from typing import Tuple, Optional
import yaml


def load_config(config_path: str = "ml/config/eval.yaml") -> dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def stratified_split(
    df: pd.DataFrame,
    label_col: str = "label",
    train_size: float = 0.7,
    val_size: float = 0.15,
    test_size: float = 0.15,
    random_state: int = 42,
    temporal_col: Optional[str] = None,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    assert abs(train_size + val_size + test_size - 1.0) < 1e-6
    
    if temporal_col and temporal_col in df.columns:
        df = df.sort_values(temporal_col)
        n = len(df)
        train_end = int(n * train_size)
        val_end = train_end + int(n * val_size)
        train = df.iloc[:train_end]
        val = df.iloc[train_end:val_end]
        test = df.iloc[val_end:]
    else:
        train_val, test = train_test_split(
            df, test_size=test_size, random_state=random_state, stratify=df[label_col]
        )
        val_ratio = val_size / (train_size + val_size)
        train, val = train_test_split(
            train_val, test_size=val_ratio, random_state=random_state, stratify=train_val[label_col]
        )
    
    return train.reset_index(drop=True), val.reset_index(drop=True), test.reset_index(drop=True)


def prepare_labels(df: pd.DataFrame, task: str = "phishing_spam") -> Tuple[pd.DataFrame, np.ndarray]:
    df = df.copy()
    if task == "phishing_spam":
        df["label_binary"] = df["label"].apply(lambda x: 1 if x in ["phishing", "spam", "bec", "impersonation"] else 0)
        return df, df["label_binary"].values
    elif task == "multiclass":
        label_map = {"ham": 0, "spam": 1, "phishing": 2, "bec": 3, "impersonation": 4}
        df["label_idx"] = df["label"].map(label_map)
        return df, df["label_idx"].values
    elif task == "bec_binary":
        df["label_bec"] = df["label"].apply(lambda x: 1 if x == "bec" else 0)
        return df, df["label_bec"].values
    elif task == "impersonation_binary":
        df["label_impersonation"] = df["label"].apply(lambda x: 1 if x == "impersonation" else 0)
        return df, df["label_impersonation"].values
    else:
        raise ValueError(f"Unknown task: {task}")