"""Locks the deterministic robust-statistics contract the gates rely on."""

import math

import pytest

from bench.robust_stats import (
    BootstrapCI,
    bootstrap_median_ci,
    cliffs_delta,
    flag_outliers,
    median,
    median_ratio,
    modified_z_scores,
)


def test_median_odd_and_even_samples():
    """The gates compare medians; both parities must be exact, not averaged
    by some other convention."""
    assert median([3.0, 1.0, 2.0]) == 2.0
    assert median([4.0, 1.0, 3.0, 2.0]) == 2.5


def test_median_rejects_empty_and_non_finite():
    """A gate statistic over an empty or NaN sample must fail loudly, never
    fabricate a number."""
    with pytest.raises(ValueError):
        median([])
    with pytest.raises(ValueError):
        median([1.0, float("nan")])
    with pytest.raises(ValueError):
        median([float("inf")])


def test_bootstrap_ci_known_sample_seeded():
    """Freezes the exact seeded interval for a known sample so any drift in
    the resampling stream, quantile rule, or seeding is a test failure."""
    sample = [10.0, 11.0, 9.5, 10.5, 12.0, 9.0, 10.2, 11.5]
    ci = bootstrap_median_ci(sample, seed=42, iterations=2000, confidence=0.95)
    assert ci == BootstrapCI(
        statistic=10.35,
        low=9.5,
        high=11.5,
        confidence=0.95,
        iterations=2000,
        seed=42,
    )


def test_bootstrap_ci_is_deterministic_per_seed():
    """The same sample and seed must reproduce the interval bit for bit;
    otherwise a gate verdict could flip between identical runs."""
    sample = [100.0, 101.0, 99.0, 100.5, 100.2]
    first = bootstrap_median_ci(sample, seed=7, iterations=1000, confidence=0.9)
    second = bootstrap_median_ci(sample, seed=7, iterations=1000, confidence=0.9)
    assert first == second
    assert (first.low, first.high) == (99.0, 101.0)


def test_bootstrap_ci_seed_changes_stream():
    """Two seeds share the point statistic but steer the resampling stream
    differently (frozen low-iteration intervals), proving the seed drives the
    stream rather than being decorative."""
    sample = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 3.0, 5.0]
    a = bootstrap_median_ci(sample, seed=1, iterations=40, confidence=0.9)
    b = bootstrap_median_ci(sample, seed=2, iterations=40, confidence=0.9)
    assert a.statistic == b.statistic == 4.5
    assert (a.low, a.high) == (2.4749999999999996, 12.0)
    assert (b.low, b.high) == (2.0, 8.124999999999993)


def test_bootstrap_ci_degenerate_single_value():
    """A one-value sample resamples to itself; the interval collapses to the
    value instead of dividing by zero."""
    ci = bootstrap_median_ci([7.5], seed=1, iterations=100)
    assert (ci.statistic, ci.low, ci.high) == (7.5, 7.5, 7.5)


def test_bootstrap_ci_rejects_bad_parameters():
    """Confidence outside (0, 1) or a non-positive iteration count makes the
    interval meaningless; reject rather than emit one."""
    with pytest.raises(ValueError):
        bootstrap_median_ci([1.0], confidence=1.0)
    with pytest.raises(ValueError):
        bootstrap_median_ci([1.0], confidence=0.0)
    with pytest.raises(ValueError):
        bootstrap_median_ci([1.0], iterations=0)
    with pytest.raises(ValueError):
        bootstrap_median_ci([1.0], seed="x")


def test_modified_z_scores_known_set():
    """Freezes the Iglewicz-Hoaglin scores for a known set, including the
    0.6745 consistency factor, so the outlier gate cannot silently change
    scale."""
    scores = modified_z_scores([1.0, 1.1, 0.9, 1.0, 1.05, 0.95, 1.02, 10.0])
    assert [round(z, 4) for z in scores] == [
        -0.1349, 1.2141, -1.4839, -0.1349, 0.5396, -0.8094, 0.1349, 121.2751,
    ]


def test_flag_outliers_known_set():
    """Only the injected spike trips the default 3.5 threshold on a known
    set; a tighter or looser rule would flip this exact tuple."""
    flags = flag_outliers([1.0, 1.1, 0.9, 1.0, 1.05, 0.95, 1.02, 10.0])
    assert flags == (False, False, False, False, False, False, False, True)


def test_modified_z_scores_zero_mad():
    """With over half the sample tied, MAD is 0 and cannot scale; tied values
    score 0 and any deviation is infinitely outlying by construction."""
    scores = modified_z_scores([5.0, 5.0, 5.0, 5.0, 9.0])
    assert scores[:4] == [0.0, 0.0, 0.0, 0.0]
    assert scores[4] == math.inf
    assert flag_outliers([5.0, 5.0, 5.0, 5.0, 9.0]) == (
        False, False, False, False, True,
    )


def test_cliffs_delta_known_pairs():
    """Cliff's delta is the effect size the speed gate reports; freeze exact
    pair-count arithmetic including sign convention (positive = candidate
    slower)."""
    assert cliffs_delta([10.0, 11.0, 12.0], [13.0, 14.0, 15.0]) == 1.0
    assert cliffs_delta([13.0, 14.0, 15.0], [10.0, 11.0, 12.0]) == -1.0
    # 9 pairs: 5 candidate-below, 7 candidate... exact mixed case:
    assert cliffs_delta([10.0, 11.0, 12.0], [9.0, 10.0, 20.0]) == -2 / 9


def test_median_ratio_contract():
    """The overhead and regression budgets divide candidate by control; a
    zero control is undecidable, not a silent infinity."""
    assert median_ratio(100.0, 103.0) == 1.03
    assert median_ratio(100.0, 95.0) == 0.95
    with pytest.raises(ValueError):
        median_ratio(0.0, 1.0)
