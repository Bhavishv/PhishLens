"""
PhishLens — Dataset Preparation

Read raw email corpora from ``data/raw/``, extract subject + body text,
apply uniform text cleaning, label each row, and save a balanced
``data/processed/dataset.csv`` with columns ``[text, label, source]``.

All datasets are downloaded by the user — this script prints clear
instructions if files are missing and exits gracefully.

Usage::

    python -m ml.prepare_data
"""

from __future__ import annotations

import email
import email.policy
import glob
import mailbox
import os
import re
import sys
from pathlib import Path
from typing import Any

import pandas as pd

import config

# ---------------------------------------------------------------------------
# Text cleaning helpers
# ---------------------------------------------------------------------------

_HEADER_LINE_RE = re.compile(
    r"^(From|To|Subject|Date|Received|Message-ID|MIME-Version|"
    r"Content-Type|Content-Transfer-Encoding|X-[\w-]+):\s",
    re.IGNORECASE,
)
_SIGNATURE_RE = re.compile(r"^-{2,3}\s*$")
_WHITESPACE_RE = re.compile(r"\s+")


def _clean_text(text: str) -> str:
    """Apply uniform text cleaning.

    * Strip residual email headers from the body.
    * Strip signatures (lines after ``--`` or ``---``).
    * Normalise whitespace (collapse multiple spaces / newlines).
    * Lowercase.
    """
    if not text:
        return ""

    lines: list[str] = []
    for line in text.splitlines():
        # Stop at signature delimiter
        if _SIGNATURE_RE.match(line):
            break
        # Skip residual header lines
        if _HEADER_LINE_RE.match(line):
            continue
        lines.append(line)

    cleaned = " ".join(lines)
    cleaned = _WHITESPACE_RE.sub(" ", cleaned).strip().lower()
    return cleaned


def _extract_text_from_msg(msg: email.message.Message) -> str:
    """Extract plain-text body from an ``email.message.Message``."""
    body_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_parts.append(payload.decode(charset, errors="replace"))
                    except (LookupError, UnicodeDecodeError):
                        body_parts.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                body_parts.append(payload.decode(charset, errors="replace"))
            except (LookupError, UnicodeDecodeError):
                body_parts.append(payload.decode("utf-8", errors="replace"))

    return " ".join(body_parts)


# ---------------------------------------------------------------------------
# Per-source loaders
# ---------------------------------------------------------------------------

def _load_nazario(path: str) -> list[dict[str, Any]]:
    """Load Nazario phishing corpus (mbox or directory of .eml files)."""
    rows: list[dict[str, Any]] = []

    # Try mbox files first
    mbox_files = glob.glob(os.path.join(path, "*.mbox"))
    for mbox_path in mbox_files:
        try:
            mbox = mailbox.mbox(mbox_path)
            for msg in mbox:
                subject = msg.get("Subject", "") or ""
                body = _extract_text_from_msg(msg)
                text = f"{subject} {body}"
                cleaned = _clean_text(text)
                if cleaned:
                    rows.append({"text": cleaned, "label": 1, "source": "nazario"})
        except Exception as exc:  # noqa: BLE001
            print(f"  [WARN] Error reading {mbox_path}: {exc}")

    # Also try individual .eml files
    eml_files = glob.glob(os.path.join(path, "**", "*.eml"), recursive=True)
    for eml_path in eml_files:
        try:
            with open(eml_path, "rb") as fh:
                msg = email.message_from_bytes(fh.read(), policy=email.policy.default)
            subject = msg.get("Subject", "") or ""
            body = _extract_text_from_msg(msg)
            text = f"{subject} {body}"
            cleaned = _clean_text(text)
            if cleaned:
                rows.append({"text": cleaned, "label": 1, "source": "nazario"})
        except Exception as exc:  # noqa: BLE001
            print(f"  [WARN] Error reading {eml_path}: {exc}")

    return rows


def _load_spamassassin(path: str) -> list[dict[str, Any]]:
    """Load SpamAssassin easy_ham + hard_ham corpus (directory of raw emails)."""
    rows: list[dict[str, Any]] = []

    for sub_dir in ("easy_ham", "hard_ham", "easy_ham_2"):
        dir_path = os.path.join(path, sub_dir)
        if not os.path.isdir(dir_path):
            continue
        for fname in os.listdir(dir_path):
            fpath = os.path.join(dir_path, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "rb") as fh:
                        msg = email.message_from_bytes(
                            fh.read(), policy=email.policy.default
                        )
                    subject = msg.get("Subject", "") or ""
                    body = _extract_text_from_msg(msg)
                    text = f"{subject} {body}"
                    cleaned = _clean_text(text)
                    if cleaned:
                        rows.append(
                            {"text": cleaned, "label": 0, "source": "spamassassin"}
                        )
                except Exception as exc:  # noqa: BLE001
                    print(f"  [WARN] Error reading {fpath}: {exc}")

    return rows


def _load_enron(path: str) -> list[dict[str, Any]]:
    """Load Enron email sample (directory of raw emails)."""
    rows: list[dict[str, Any]] = []

    for root, _dirs, files in os.walk(path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "rb") as fh:
                    msg = email.message_from_bytes(
                        fh.read(), policy=email.policy.default
                    )
                subject = msg.get("Subject", "") or ""
                body = _extract_text_from_msg(msg)
                text = f"{subject} {body}"
                cleaned = _clean_text(text)
                if cleaned:
                    rows.append({"text": cleaned, "label": 0, "source": "enron"})
            except Exception as exc:  # noqa: BLE001
                print(f"  [WARN] Error reading {fpath}: {exc}")

    return rows


def _load_hf_csv_parquet(path: str, label: int, source: str) -> list[dict[str, Any]]:
    """Load a Hugging Face dataset stored as CSV or Parquet files.

    Uses plain pandas — **NOT** the ``datasets`` library.
    Expects a column named ``text``, ``email_text``, ``body``, or ``content``.
    """
    rows: list[dict[str, Any]] = []
    dfs: list[pd.DataFrame] = []

    # Collect all CSV and Parquet files in the directory
    if os.path.isdir(path):
        csv_files = glob.glob(os.path.join(path, "**", "*.csv"), recursive=True)
        parquet_files = glob.glob(
            os.path.join(path, "**", "*.parquet"), recursive=True
        )
        for f in csv_files:
            try:
                dfs.append(pd.read_csv(f))
            except Exception as exc:  # noqa: BLE001
                print(f"  [WARN] Error reading {f}: {exc}")
        for f in parquet_files:
            try:
                dfs.append(pd.read_parquet(f))
            except Exception as exc:  # noqa: BLE001
                print(f"  [WARN] Error reading {f}: {exc}")
    elif os.path.isfile(path):
        # Single file
        try:
            if path.endswith(".parquet"):
                dfs.append(pd.read_parquet(path))
            else:
                dfs.append(pd.read_csv(path))
        except Exception as exc:  # noqa: BLE001
            print(f"  [WARN] Error reading {path}: {exc}")

    if not dfs:
        return rows

    df = pd.concat(dfs, ignore_index=True)

    # Find the text column
    text_col = None
    for candidate in ("text", "email_text", "body", "content", "email"):
        if candidate in df.columns:
            text_col = candidate
            break

    if text_col is None:
        print(f"  [WARN] No text column found in {path}. Columns: {list(df.columns)}")
        return rows

    for _, row in df.iterrows():
        raw_text = str(row[text_col]) if pd.notna(row[text_col]) else ""
        cleaned = _clean_text(raw_text)
        if cleaned:
            rows.append({"text": cleaned, "label": label, "source": source})

    return rows


# ---------------------------------------------------------------------------
# Main preparation function
# ---------------------------------------------------------------------------

def prepare_dataset() -> None:
    """Check for each dataset, load, clean, balance, and save.

    Prints download instructions for any missing datasets and continues
    with whatever data is available.
    """
    all_rows: list[dict[str, Any]] = []
    missing: list[str] = []

    # --- 1. Nazario Phishing Corpus ---
    if os.path.isdir(config.DATASET_NAZARIO_DIR):
        print("[*] Loading Nazario phishing corpus...")
        rows = _load_nazario(config.DATASET_NAZARIO_DIR)
        print(f"    → {len(rows)} samples loaded")
        all_rows.extend(rows)
    else:
        missing.append(
            f"  • Nazario Phishing Corpus → download from "
            f"https://monkey.org/~jose/phishing/ and extract into "
            f"'{config.DATASET_NAZARIO_DIR}'"
        )

    # --- 2. SpamAssassin Ham Corpus ---
    if os.path.isdir(config.DATASET_SPAMASSASSIN_DIR):
        print("[*] Loading SpamAssassin ham corpus...")
        rows = _load_spamassassin(config.DATASET_SPAMASSASSIN_DIR)
        print(f"    → {len(rows)} samples loaded")
        all_rows.extend(rows)
    else:
        missing.append(
            f"  • SpamAssassin Ham Corpus → download from "
            f"https://spamassassin.apache.org/old/publiccorpus/ and extract "
            f"easy_ham/ + hard_ham/ into '{config.DATASET_SPAMASSASSIN_DIR}'"
        )

    # --- 3. Enron Emails ---
    if os.path.isdir(config.DATASET_ENRON_DIR):
        print("[*] Loading Enron email corpus...")
        rows = _load_enron(config.DATASET_ENRON_DIR)
        print(f"    → {len(rows)} samples loaded")
        all_rows.extend(rows)
    else:
        missing.append(
            f"  • Enron Email Dataset → download a sample from "
            f"https://www.cs.cmu.edu/~enron/ and extract into "
            f"'{config.DATASET_ENRON_DIR}'"
        )

    # --- 4. HF Phishing Email Dataset ---
    if os.path.isdir(config.DATASET_HF_PHISHING_FILE) or os.path.isfile(
        config.DATASET_HF_PHISHING_FILE
    ):
        print("[*] Loading HuggingFace phishing-email-dataset...")
        rows = _load_hf_csv_parquet(
            config.DATASET_HF_PHISHING_FILE, label=1, source="hf_phishing"
        )
        print(f"    → {len(rows)} samples loaded")
        all_rows.extend(rows)
    else:
        missing.append(
            f"  • HF phishing-email-dataset → download CSV/Parquet from "
            f"https://huggingface.co/datasets/zefang-liu/phishing-email-dataset "
            f"and place in '{config.DATASET_HF_PHISHING_FILE}'"
        )

    # --- 5. HF AI-Generated Phishing ---
    if os.path.isdir(config.DATASET_HF_AI_PHISHING_FILE) or os.path.isfile(
        config.DATASET_HF_AI_PHISHING_FILE
    ):
        print("[*] Loading HuggingFace AI-generated phishing dataset...")
        rows = _load_hf_csv_parquet(
            config.DATASET_HF_AI_PHISHING_FILE, label=1, source="hf_ai_phishing"
        )
        print(f"    → {len(rows)} samples loaded")
        all_rows.extend(rows)
    else:
        missing.append(
            f"  • HF AI-generated phishing → download CSV/Parquet from "
            f"https://huggingface.co/datasets/kxm1k4m1/generate_phishing_email_final "
            f"and place in '{config.DATASET_HF_AI_PHISHING_FILE}'"
        )

    # --- Report missing datasets ---
    if missing:
        print("\n[!] The following datasets are missing:")
        for m in missing:
            print(m)
        print()

    if not all_rows:
        print(
            "[ERROR] No data loaded. Please download at least one dataset "
            "and re-run.\n"
        )
        sys.exit(1)

    # --- Build DataFrame ---
    df = pd.DataFrame(all_rows)
    print(f"\n[*] Total samples before balancing: {len(df)}")
    print(f"    Phishing (1): {len(df[df['label'] == 1])}")
    print(f"    Legit    (0): {len(df[df['label'] == 0])}")
    print(f"    Sources: {dict(df['source'].value_counts())}")

    # --- Balance classes (undersample majority) ---
    phishing = df[df["label"] == 1]
    legit = df[df["label"] == 0]

    if len(phishing) > 0 and len(legit) > 0:
        min_count = min(len(phishing), len(legit))
        phishing_balanced = phishing.sample(n=min_count, random_state=42)
        legit_balanced = legit.sample(n=min_count, random_state=42)
        df = pd.concat([phishing_balanced, legit_balanced], ignore_index=True)
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
        print(f"\n[*] After balancing: {len(df)} samples ({min_count} per class)")
    else:
        label_present = 1 if len(phishing) > 0 else 0
        print(
            f"\n[WARN] Only class {label_present} has data — "
            f"model will be unreliable without both classes."
        )

    # --- Save ---
    out_path = config.PROCESSED_DATASET_PATH
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    df.to_csv(out_path, index=False)
    print(f"\n[✓] Saved balanced dataset to {out_path}")
    print(f"    Columns: {list(df.columns)}")
    print(f"    Rows: {len(df)}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    prepare_dataset()
