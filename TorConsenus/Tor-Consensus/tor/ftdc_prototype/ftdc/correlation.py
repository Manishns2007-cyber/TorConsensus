"""Correlation utilities for FTDC scoring."""
import numpy as np
from scipy.spatial.distance import cosine


def cosine_similarity(a, b):
    a = np.array(a, dtype=float)
    b = np.array(b, dtype=float)
    if np.linalg.norm(a) == 0 or np.linalg.norm(b) == 0:
        return 0.0
    return 1.0 - cosine(a, b)


def area_difference(a, b):
    a = np.array(a, dtype=float)
    b = np.array(b, dtype=float)
    n = max(len(a), len(b))
    if n == 0:
        return 1.0
    if len(a) != n:
        a = np.interp(np.linspace(0, 1, n), np.linspace(0, 1, len(a)), a)
    if len(b) != n:
        b = np.interp(np.linspace(0, 1, n), np.linspace(0, 1, len(b)), b)
    diff = np.sum(np.abs(a - b))
    return min(1.0, diff / 2.0)


def combined_score(density_a, density_b, w_cosine=0.7, w_area=0.3):
    cos = cosine_similarity(density_a, density_b)
    area = area_difference(density_a, density_b)
    return {
        'cosine': float(cos),
        'area_diff': float(area),
        'combined': float(w_cosine * cos + w_area * (1.0 - area))
    }
