"""
PhishLens — Model Training

Train a TF-IDF + Logistic Regression classifier on the prepared dataset,
evaluate with standard 80/20 split and cross-source held-out tests,
and save the model pipeline to ``ml/model/phishing_model.joblib``.

Usage::

    python -m ml.train
"""

from __future__ import annotations

import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

import config

# ---------------------------------------------------------------------------
# Training helpers
# ---------------------------------------------------------------------------

def _build_pipeline() -> Pipeline:
    """Build the TF-IDF + Logistic Regression pipeline."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=10_000,
            ngram_range=(1, 2),
            stop_words="english",
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
            solver="lbfgs",
        )),
    ])


def _print_metrics(y_true, y_pred, title: str) -> None:
    """Print classification report and confusion matrix."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")
    print(classification_report(
        y_true, y_pred,
        target_names=["legit (0)", "phishing (1)"],
        digits=3,
    ))
    cm = confusion_matrix(y_true, y_pred)
    print(f"  Confusion Matrix:")
    print(f"    TN={cm[0, 0]:5d}  FP={cm[0, 1]:5d}")
    print(f"    FN={cm[1, 0]:5d}  TP={cm[1, 1]:5d}")


# ---------------------------------------------------------------------------
# Main training function
# ---------------------------------------------------------------------------

def train_model() -> None:
    """Load prepared data, train, evaluate, and save the model.

    1. 80/20 stratified split → metrics.
    2. Cross-source test (train on all but one, test on held-out).
    3. Save the model from step 1.
    4. Print honesty note about dataset limitations.
    """
    data_path = config.PROCESSED_DATASET_PATH
    if not os.path.isfile(data_path):
        print(
            f"[ERROR] Dataset not found at '{data_path}'.\n"
            f"Run `python -m ml.prepare_data` first."
        )
        sys.exit(1)

    df = pd.read_csv(data_path)
    print(f"[*] Loaded {len(df)} samples from {data_path}")
    print(f"    Labels: {dict(df['label'].value_counts())}")

    if "source" in df.columns:
        print(f"    Sources: {dict(df['source'].value_counts())}")

    X = df["text"].fillna("")
    y = df["label"]

    # ------------------------------------------------------------------
    # Split A: 80/20 stratified
    # ------------------------------------------------------------------
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    pipeline = _build_pipeline()
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    _print_metrics(y_test, y_pred, "Split A: 80/20 Stratified Hold-Out")

    # ------------------------------------------------------------------
    # Split B: cross-source held-out evaluation
    # ------------------------------------------------------------------
    if "source" in df.columns:
        sources = df["source"].unique()
        if len(sources) > 1:
            print(f"\n{'=' * 60}")
            print("  Split B: Cross-Source Evaluation")
            print(f"{'=' * 60}")

            for held_out in sources:
                test_mask = df["source"] == held_out
                train_mask = ~test_mask

                X_cs_train = df.loc[train_mask, "text"].fillna("")
                y_cs_train = df.loc[train_mask, "label"]
                X_cs_test = df.loc[test_mask, "text"].fillna("")
                y_cs_test = df.loc[test_mask, "label"]

                if len(y_cs_train.unique()) < 2:
                    print(
                        f"\n  [SKIP] Held-out='{held_out}': "
                        f"training set has only one class."
                    )
                    continue

                if len(y_cs_test) == 0:
                    print(f"\n  [SKIP] Held-out='{held_out}': no test samples.")
                    continue

                cs_pipeline = _build_pipeline()
                cs_pipeline.fit(X_cs_train, y_cs_train)
                y_cs_pred = cs_pipeline.predict(X_cs_test)

                _print_metrics(
                    y_cs_test, y_cs_pred,
                    f"Cross-Source: held-out='{held_out}' "
                    f"({len(X_cs_test)} samples)",
                )
        else:
            print("\n  [INFO] Only one source — skipping cross-source evaluation.")

    # ------------------------------------------------------------------
    # Save the model (from Split A)
    # ------------------------------------------------------------------
    model_dir = os.path.dirname(config.MODEL_PATH)
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(pipeline, config.MODEL_PATH)
    print(f"\n[✓] Model saved to {config.MODEL_PATH}")

    # ------------------------------------------------------------------
    # Honesty note
    # ------------------------------------------------------------------
    print(
        "\n" + "=" * 60 + "\n"
        "  ⚠  IMPORTANT NOTE ON METRICS\n"
        "=" * 60 + "\n"
        "  These metrics likely OVERSTATE real-world performance.\n"
        "  The datasets used are primarily from the 2000s–2010s.\n"
        "  Modern phishing tactics (e.g., AI-generated text, QR codes,\n"
        "  zero-click exploits) may differ significantly.\n"
        "\n"
        "  Always combine ML predictions with the other PhishLens\n"
        "  modules (authentication, header anomalies, URL analysis,\n"
        "  domain intelligence) for a more robust assessment.\n"
        "=" * 60
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    train_model()
