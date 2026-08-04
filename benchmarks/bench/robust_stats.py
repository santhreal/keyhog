"""Deterministic robust statistics over benchmark trial sets.

Every estimator here is pure and seeded: the same samples and seed always
produce bit-identical intervals, so a gate verdict never depends on wall
clock or hash ordering.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Sequence

# Iglewicz-Hoaglin modified z-score rejection threshold.
DEFAULT_OUTLIER_THRESHOLD = 3.5
# Normal-consistency factor scaling MAD onto the standard-deviation scale.
_MAD_CONSISTENCY = 0.6745


def _as_samples(samples: Sequence[float], *, name: str = "samples") -> list[float]:
    values = [float(v) for v in samples]
    if not values:
        raise ValueError(f"{name} must contain at least one value")
    if any(math.isnan(v) or math.isinf(v) for v in values):
        raise ValueError(f"{name} must contain only finite values")
    return values


def median(samples: Sequence[float]) -> float:
    """Median of a non-empty finite sample."""
    values = sorted(_as_samples(samples))
    n = len(values)
    mid = n // 2
    if n % 2:
        return values[mid]
    return (values[mid - 1] + values[mid]) / 2.0


def _quantile_type7(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolation (type-7) quantile of an ascending sequence."""
    n = len(sorted_values)
    if n == 1:
        return float(sorted_values[0])
    pos = (n - 1) * q
    lower = int(math.floor(pos))
    upper = min(lower + 1, n - 1)
    frac = pos - lower
    return float(sorted_values[lower]) + frac * (
        float(sorted_values[upper]) - float(sorted_values[lower])
    )


@dataclass(frozen=True)
class BootstrapCI:
    """Bootstrap percentile interval for the sample median."""

    statistic: float
    low: float
    high: float
    confidence: float
    iterations: int
    seed: int


def bootstrap_median_ci(
    samples: Sequence[float],
    *,
    confidence: float = 0.95,
    iterations: int = 2000,
    seed: int = 0,
) -> BootstrapCI:
    """Seeded bootstrap percentile CI around the median.

    Resamples with replacement ``iterations`` times from a
    ``random.Random(seed)`` stream, so results are reproducible across hosts
    and runs. The interval is the type-7 percentile band of the resampled
    medians at ``(1 - confidence) / 2`` and ``1 - (1 - confidence) / 2``.
    """
    values = _as_samples(samples)
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be in (0, 1), got {confidence!r}")
    if isinstance(iterations, bool) or not isinstance(iterations, int) or iterations < 1:
        raise ValueError(f"iterations must be a positive integer, got {iterations!r}")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError(f"seed must be an integer, got {seed!r}")
    rng = random.Random(seed)
    n = len(values)
    resampled = sorted(
        median([values[rng.randrange(n)] for _ in range(n)])
        for _ in range(iterations)
    )
    alpha = 1.0 - confidence
    return BootstrapCI(
        statistic=median(values),
        low=_quantile_type7(resampled, alpha / 2.0),
        high=_quantile_type7(resampled, 1.0 - alpha / 2.0),
        confidence=confidence,
        iterations=iterations,
        seed=seed,
    )


def modified_z_scores(samples: Sequence[float]) -> list[float]:
    """Iglewicz-Hoaglin modified z-scores ``0.6745 * (x - median) / MAD``.

    A zero MAD (over half the sample tied at the median) cannot scale, so
    tied values score 0.0 and deviating values score ``+-inf``: with no
    measured spread, any deviation is an outlier by construction.
    """
    values = _as_samples(samples)
    center = median(values)
    mad = median([abs(v - center) for v in values])
    if mad == 0.0:
        return [
            0.0 if v == center else math.copysign(math.inf, v - center)
            for v in values
        ]
    return [_MAD_CONSISTENCY * (v - center) / mad for v in values]


def flag_outliers(
    samples: Sequence[float],
    *,
    threshold: float = DEFAULT_OUTLIER_THRESHOLD,
) -> tuple[bool, ...]:
    """Flag samples whose absolute modified z-score exceeds ``threshold``."""
    if not threshold > 0.0:
        raise ValueError(f"threshold must be positive, got {threshold!r}")
    return tuple(abs(z) > threshold for z in modified_z_scores(samples))


def median_ratio(control_median: float, candidate_median: float) -> float:
    """Candidate / control median ratio; 1.0 is parity, above 1.0 is slower."""
    if not control_median > 0.0:
        raise ValueError(
            f"control median must be positive, got {control_median!r}"
        )
    return candidate_median / control_median


def cliffs_delta(control: Sequence[float], candidate: Sequence[float]) -> float:
    """Cliff's delta ``P(candidate > control) - P(candidate < control)``.

    For wall-time samples a positive delta means the candidate is slower
    more often than it is faster; the magnitude is the effect size, free of
    any distributional assumption.
    """
    control_values = _as_samples(control, name="control")
    candidate_values = _as_samples(candidate, name="candidate")
    greater = 0
    lesser = 0
    for cand in candidate_values:
        for ctrl in control_values:
            if cand > ctrl:
                greater += 1
            elif cand < ctrl:
                lesser += 1
    pairs = len(control_values) * len(candidate_values)
    return (greater - lesser) / pairs
