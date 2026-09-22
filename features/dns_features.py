"""
Argus AI — DNS feature extraction for the DGA / DNS-tunnelling model.

Works with the pre-extracted columns in the dataset (dns_entropy,
dns_query_length, etc.) and adds the n-gram "English-likeness" score
that the feature_dictionary doesn't include but the roadmap requires.
"""

from __future__ import annotations

import math
import string
from collections import Counter
from typing import Dict, List, Optional, Union

import numpy as np
import pandas as pd

from features.statistical import string_char_entropy


# ── English bigram frequencies ────────────────────────────────────────
# Source: approximate letter-pair frequencies from a large English corpus.
# We only need the ranking to get a log-likelihood score; exact values
# don't matter as long as the ordering is right.
_ENGLISH_BIGRAMS: Dict[str, float] = {}

def _init_english_bigrams():
    """Build a lookup of log-probability for English bigrams."""
    # Top-50 bigrams with rough relative frequencies (from Peter Norvig's
    # analysis of the Google corpus).  Everything not listed gets a small
    # default probability.
    raw = {
        "th": 356, "he": 307, "in": 243, "er": 205, "an": 199,
        "re": 185, "on": 176, "at": 149, "en": 145, "nd": 135,
        "ti": 134, "es": 131, "or": 128, "te": 120, "of": 117,
        "ed": 113, "is": 113, "it": 112, "al": 109, "ar": 107,
        "st": 105, "to": 104, "nt": 104, "ng": 95,  "se": 93,
        "ha": 93,  "as": 87,  "ou": 87,  "io": 83,  "le": 83,
        "ve": 83,  "co": 79,  "me": 79,  "de": 76,  "hi": 76,
        "ri": 73,  "ro": 73,  "ic": 70,  "ne": 69,  "ea": 69,
        "ra": 69,  "ce": 65,  "li": 62,  "ch": 60,  "ll": 58,
        "be": 58,  "ma": 57,  "si": 55,  "om": 55,  "ur": 54,
    }
    total = sum(raw.values())
    # Smoothing: unseen bigrams get count = 0.5
    all_letters = string.ascii_lowercase
    n_possible = 26 * 26
    smooth_total = total + 0.5 * (n_possible - len(raw))
    for a in all_letters:
        for b in all_letters:
            bg = a + b
            count = raw.get(bg, 0.5)
            _ENGLISH_BIGRAMS[bg] = math.log2(count / smooth_total)

_init_english_bigrams()


def ngram_score(domain: str) -> float:
    """Log-likelihood of a domain name under an English bigram model.

    More negative → less English-like → more DGA-like.
    Strips dots and digits before scoring.
    """
    cleaned = "".join(c for c in domain.lower() if c in string.ascii_lowercase)
    if len(cleaned) < 2:
        return 0.0
    bigrams = [cleaned[i:i+2] for i in range(len(cleaned) - 1)]
    scores = [_ENGLISH_BIGRAMS.get(bg, -10.0) for bg in bigrams]
    return sum(scores) / len(scores)  # average per-bigram log-likelihood


# ── Feature columns used by the DGA XGBoost model ────────────────────
DGA_FEATURE_COLS = [
    "dns_query_length",
    "dns_entropy",
    "dns_digit_ratio",
    "dns_label_count",
    "dns_longest_label",
    "dns_unique_bigram_count",
    "dns_unique_trigram_count",
    "dns_event_count",
    "dns_unique_domain_count_per_flow",
    "dns_max_query_length_per_flow",
    "ngram_score",  # engineered feature added during training
]


def extract_dga_features(row: Union[pd.Series, dict]) -> Dict[str, float]:
    """Extract the feature vector for one row of the dataset or streaming event.

    Computes lexical features and ngram_score dynamically from dns_query if raw query is provided.
    """
    query = str(row.get("dns_query") or row.get("query") or "").strip()
    features = {}

    has_lexical = "dns_query_length" in row and pd.notna(row.get("dns_query_length")) and float(row.get("dns_query_length", 0)) > 0

    if not has_lexical and query:
        sub = query.split(".")[0] if "." in query else query
        features["dns_query_length"] = float(len(query))
        features["dns_entropy"] = float(string_char_entropy(sub))
        features["dns_digit_ratio"] = float(sum(c.isdigit() for c in query) / max(1, len(query)))
        features["dns_label_count"] = float(len(query.split(".")))
        features["dns_longest_label"] = float(max((len(lbl) for lbl in query.split(".")), default=0))
        features["dns_unique_bigram_count"] = float(len(set(query[i:i+2] for i in range(len(query)-1))))
        features["dns_unique_trigram_count"] = float(len(set(query[i:i+3] for i in range(len(query)-2))))
        features["dns_event_count"] = float(row.get("dns_event_count", 1) or 1)
        features["dns_unique_domain_count_per_flow"] = float(row.get("dns_unique_domain_count_per_flow", 1) or 1)
        features["dns_max_query_length_per_flow"] = float(row.get("dns_max_query_length_per_flow", len(query)) or len(query))
        features["ngram_score"] = float(ngram_score(query))
    else:
        for col in DGA_FEATURE_COLS:
            if col == "ngram_score":
                features[col] = ngram_score(query) if query else 0.0
            else:
                val = row.get(col, 0)
                features[col] = float(val) if pd.notna(val) else 0.0
    return features


def add_ngram_score_column(df: pd.DataFrame) -> pd.DataFrame:
    """Add the ngram_score column to a DataFrame (used during training)."""
    df = df.copy()
    df["ngram_score"] = df["dns_query"].apply(
        lambda q: ngram_score(q) if isinstance(q, str) and q else 0.0
    )
    return df
