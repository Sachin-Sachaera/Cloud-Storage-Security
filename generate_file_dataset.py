"""
generate_file_dataset.py
--------------------------
Generates a synthetic dataset of FILE METADATA features (not file content)
to train a risk-scoring classifier for the document safety scanner.

Features mirror what a real endpoint-security / attachment-scanning product
looks at before ever running the file:
    - size_kb
    - entropy            (Shannon entropy of the byte stream, 0-8)
    - extension_mismatch (declared extension vs actual file signature)
    - has_macro           (zip-based office doc contains vbaProject.bin)
    - double_extension     (e.g. invoice.pdf.exe)
    - suspicious_keywords  (count of script/shell-execution keywords found)
    - is_executable_sig    (file starts with MZ/ELF/script shebang)

Label: safe | suspicious | malicious
"""

import numpy as np
import pandas as pd

RANDOM_SEED = 7
np.random.seed(RANDOM_SEED)

N_SAFE = 3000
N_SUSPICIOUS = 900
N_MALICIOUS = 700


def make_safe(n):
    return pd.DataFrame({
        "size_kb": np.random.gamma(shape=3, scale=150, size=n),
        "entropy": np.clip(np.random.normal(4.2, 0.6, n), 0, 8),
        "extension_mismatch": np.random.choice([0, 1], size=n, p=[0.98, 0.02]),
        "has_macro": np.random.choice([0, 1], size=n, p=[0.95, 0.05]),
        "double_extension": np.random.choice([0, 1], size=n, p=[0.99, 0.01]),
        "suspicious_keywords": np.random.poisson(lam=0.1, size=n),
        "is_executable_sig": np.random.choice([0, 1], size=n, p=[0.99, 0.01]),
        "label": "safe",
    })


def make_suspicious(n):
    return pd.DataFrame({
        "size_kb": np.random.gamma(shape=2, scale=200, size=n),
        "entropy": np.clip(np.random.normal(5.8, 0.7, n), 0, 8),
        "extension_mismatch": np.random.choice([0, 1], size=n, p=[0.6, 0.4]),
        "has_macro": np.random.choice([0, 1], size=n, p=[0.55, 0.45]),
        "double_extension": np.random.choice([0, 1], size=n, p=[0.8, 0.2]),
        "suspicious_keywords": np.random.poisson(lam=1.5, size=n),
        "is_executable_sig": np.random.choice([0, 1], size=n, p=[0.85, 0.15]),
        "label": "suspicious",
    })


def make_malicious(n):
    return pd.DataFrame({
        "size_kb": np.random.gamma(shape=1.5, scale=120, size=n),
        "entropy": np.clip(np.random.normal(7.2, 0.5, n), 0, 8),
        "extension_mismatch": np.random.choice([0, 1], size=n, p=[0.25, 0.75]),
        "has_macro": np.random.choice([0, 1], size=n, p=[0.35, 0.65]),
        "double_extension": np.random.choice([0, 1], size=n, p=[0.4, 0.6]),
        "suspicious_keywords": np.random.poisson(lam=4.5, size=n),
        "is_executable_sig": np.random.choice([0, 1], size=n, p=[0.3, 0.7]),
        "label": "malicious",
    })


def _add_noise(df, cols, frac=0.10, flip_frac=0.03):
    n = len(df)
    for col in cols:
        std = df[col].std()
        df[col] = np.clip(df[col] + np.random.normal(0, std * frac, n), 0, None)
    n_flip = int(n * flip_frac)
    idx = np.random.choice(df.index, size=n_flip, replace=False)
    labels = df["label"].unique().tolist()
    df.loc[idx, "label"] = [np.random.choice([l for l in labels if l != c]) for c in df.loc[idx, "label"]]
    return df


def build_file_dataset():
    df = pd.concat([make_safe(N_SAFE), make_suspicious(N_SUSPICIOUS), make_malicious(N_MALICIOUS)], ignore_index=True)
    df = _add_noise(df, ["size_kb", "entropy", "suspicious_keywords"])
    df = df.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build_file_dataset()
    df.to_csv("data/file_metadata.csv", index=False)
    print(f"Generated {len(df)} rows -> data/file_metadata.csv")
    print(df["label"].value_counts())
