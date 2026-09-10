import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any
from pathlib import Path
import yaml


def load_config(config_path: str = "ml/config/features.yaml") -> Dict:
    with open(config_path) as f:
        return yaml.safe_load(f)


def load_public_dataset(name: str, data_dir: str = "ml/data/raw") -> pd.DataFrame:
    path = Path(data_dir) / name
    if name == "spamassassin":
        return _load_spamassassin(path)
    elif name == "enron":
        return _load_enron(path)
    elif name == "phishing_kaggle":
        return _load_phishing_kaggle(path)
    elif name == "nazario":
        return _load_nazario(path)
    elif name == "bec":
        return _load_bec(path)
    elif name == "ceas":
        return _load_ceas(path)
    else:
        raise ValueError(f"Unknown dataset: {name}")


def _load_spamassassin(path: Path) -> pd.DataFrame:
    rows = []
    for label_dir, label in [("spam", "spam"), ("easy_ham", "ham"), ("hard_ham", "ham")]:
        dir_path = path / label_dir
        if dir_path.exists():
            for f in dir_path.glob("*"):
                if f.is_file():
                    try:
                        content = f.read_text(encoding="latin-1", errors="ignore")
                        rows.append({"body_text": content, "label": label, "source": "spamassassin"})
                    except Exception:
                        pass
    return pd.DataFrame(rows)


def _load_enron(path: Path) -> pd.DataFrame:
    rows = []
    for f in path.rglob("*"):
        if f.is_file() and f.suffix in [".txt", ".eml", ""]:
            try:
                content = f.read_text(encoding="latin-1", errors="ignore")
                rows.append({"body_text": content, "label": "ham", "source": "enron"})
            except Exception:
                pass
    return pd.DataFrame(rows)


def _load_phishing_kaggle(path: Path) -> pd.DataFrame:
    csv_files = list(path.glob("*.csv"))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    if "text" in df.columns and "label" in df.columns:
        df = df.rename(columns={"text": "body_text"})
        df["source"] = "phishing_kaggle"
        return df[["body_text", "label", "source"]]
    return pd.DataFrame()


def _load_nazario(path: Path) -> pd.DataFrame:
    rows = []
    for f in path.rglob("*"):
        if f.is_file():
            try:
                content = f.read_text(encoding="latin-1", errors="ignore")
                rows.append({"body_text": content, "label": "phishing", "source": "nazario"})
            except Exception:
                pass
    return pd.DataFrame(rows)


def _load_bec(path: Path) -> pd.DataFrame:
    csv_files = list(path.glob("*.csv"))
    if not csv_files:
        return pd.DataFrame()
    df = pd.read_csv(csv_files[0])
    if "text" in df.columns:
        df = df.rename(columns={"text": "body_text"})
    df["label"] = "bec"
    df["source"] = "bec"
    return df[["body_text", "label", "source"]]


def _load_ceas(path: Path) -> pd.DataFrame:
    rows = []
    for f in path.rglob("*"):
        if f.is_file():
            try:
                content = f.read_text(encoding="latin-1", errors="ignore")
                label = "spam" if "spam" in str(f).lower() else "ham"
                rows.append({"body_text": content, "label": label, "source": "ceas"})
            except Exception:
                pass
    return pd.DataFrame(rows)


def combine_datasets(datasets: List[pd.DataFrame]) -> pd.DataFrame:
    if not datasets:
        return pd.DataFrame()
    return pd.concat(datasets, ignore_index=True)