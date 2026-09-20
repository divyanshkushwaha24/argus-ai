"""
Argus AI — Statistical feature helpers.

Pure functions used by the rule-based detectors.  No training data needed;
the "model" is the recent past (rolling statistics).
"""

from __future__ import annotations

import math
from collections import Counter
from typing import List, Optional

import numpy as np


# ── Shannon entropy ──────────────────────────────────────────────────
def shannon_entropy(values: List[str]) -> float:
    """H = −Σ p·log₂(p) over a list of discrete values.

    Example: source-IP entropy across flows in a window.
    High → many distinct values (spoofed DDoS).
    Low  → single dominant value (one attacker or normal).
    """
    if not values:
        return 0.0
    counts = Counter(values)
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


def string_char_entropy(s: str) -> float:
    """Character-level Shannon entropy of a single string.

    Used for domain-name randomness (DGA detection).
    'google' ≈ 1.9 bits, random 12-char ≈ 3.5 bits.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)


# ── Rolling z-score ──────────────────────────────────────────────────
def rolling_zscore(value: float, window_mean: float, window_std: float) -> float:
    """z = (x − μ) / σ

    If std is near zero, return 0 (no variation in the window yet).
    """
    if window_std < 1e-9:
        return 0.0
    return (value - window_mean) / window_std


def zscore_to_confidence(z: float, ceiling: float = 6.0) -> float:
    """Linear mapping: confidence = min(1.0, |z| / ceiling).

    z = 6 → 1.0,  z = 3 → 0.5,  z = 1 → 0.17
    """
    return min(1.0, abs(z) / ceiling)


# ── Coefficient of variation ─────────────────────────────────────────
def coefficient_of_variation(times: List[float]) -> float:
    """CV = std / mean of inter-arrival times.

    Beacon: CV ≈ 0.03 (metronome).  Human browsing: CV > 1.0.
    Returns inf if mean is ~0, or 0.0 if fewer than 2 values.
    """
    if len(times) < 2:
        return 0.0
    arr = np.array(times, dtype=np.float64)
    mean = arr.mean()
    if mean < 1e-9:
        return float("inf")
    return float(arr.std(ddof=1) / mean)


def interarrival_times(timestamps: List[float]) -> List[float]:
    """Compute inter-arrival times from a sorted list of epoch timestamps."""
    if len(timestamps) < 2:
        return []
    ts = sorted(timestamps)
    return [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]


# ── Autocorrelation ──────────────────────────────────────────────────
def autocorrelation(series: np.ndarray, max_lag: Optional[int] = None) -> np.ndarray:
    """Normalized autocorrelation of a 1-D series.

    Returns an array of correlation values for lags 0 … max_lag.
    A strong peak at lag k means "something repeats every k steps".
    """
    if len(series) < 3:
        return np.array([1.0])
    series = series - series.mean()
    if max_lag is None:
        max_lag = len(series) // 2
    n = len(series)
    var = np.sum(series ** 2)
    if var < 1e-12:
        return np.zeros(max_lag + 1)
    result = np.correlate(series, series, mode="full")
    # Take the right half (lags ≥ 0) and normalize
    result = result[n - 1: n + max_lag] / var
    return result


def dominant_autocorr_lag(series: np.ndarray, min_lag: int = 2,
                          max_lag: Optional[int] = None) -> tuple:
    """Find the lag with the strongest autocorrelation (ignoring lag 0).

    Returns (best_lag, correlation_value).
    """
    acorr = autocorrelation(series, max_lag)
    if len(acorr) <= min_lag:
        return (0, 0.0)
    # Skip lag 0 and very short lags
    search = acorr[min_lag:]
    if len(search) == 0:
        return (0, 0.0)
    best_idx = np.argmax(search)
    return (best_idx + min_lag, float(search[best_idx]))


# ── FFT dominant frequency ───────────────────────────────────────────
def fft_dominant_frequency(series: np.ndarray, sample_rate: float = 1.0) -> tuple:
    """Find the dominant non-DC frequency in a time series.

    Returns (frequency_hz, magnitude).
    A spike at 1/30 Hz means "repeats every 30 seconds".
    """
    if len(series) < 4:
        return (0.0, 0.0)
    series = series - series.mean()
    fft_vals = np.fft.rfft(series)
    magnitudes = np.abs(fft_vals)
    # Skip DC component (index 0)
    if len(magnitudes) < 2:
        return (0.0, 0.0)
    freqs = np.fft.rfftfreq(len(series), d=1.0 / sample_rate)
    # Find peak in non-DC frequencies
    peak_idx = np.argmax(magnitudes[1:]) + 1
    return (float(freqs[peak_idx]), float(magnitudes[peak_idx]))
