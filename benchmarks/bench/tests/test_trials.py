"""Locks cache-state trial ordering, noise receipts, and invalid marking."""

import pytest

from bench.trials import (
    CacheState,
    ExecutionRoute,
    NoiseProber,
    NoiseReceipt,
    TrialOutcome,
    TrialSet,
    run_trials,
)

def _prober(*, governor="performance", freq=4200.0, load=0.5):
    """Test helper / contract verification."""
    return NoiseProber(
        affinity=lambda: (True, 16),
        governor=lambda: (governor, freq),
        load=lambda: (load, load, load),
    )


def _executor(walls):
    """Deterministic executor: records (state, index) calls, replays walls."""
    calls = []
    walls_iter = iter(walls)

    def run(state, index):
        """Test helper / contract verification."""
        calls.append((state, index))
        return TrialOutcome(wall_ms=next(walls_iter))

    run.calls = calls
    return run


def test_run_trials_state_order_and_priming(monkeypatch):
    """Cold trials each clear caches, warm runs once untimed to prime, steady
    runs back to back; any other order changes what the numbers mean."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 16))
    cleared = []
    executor = _executor([10.0, 20.0, 99.0, 21.0, 30.0, 31.0, 32.0, 33.0])
    trial_set = run_trials(
        workload="mirror",
        role="control",
        executor=executor,
        cold=2,
        warm=2,
        steady=3,
        clear_caches=lambda: cleared.append(1),
        prober=_prober(),
    )
    assert executor.calls == [
        (CacheState.COLD, 0),
        (CacheState.COLD, 1),
        (CacheState.WARM, -1),   # untimed priming run
        (CacheState.WARM, 2),
        (CacheState.WARM, 3),
        (CacheState.STEADY, 4),
        (CacheState.STEADY, 5),
        (CacheState.STEADY, 6),
    ]
    assert cleared == [1, 1]
    assert [t.cache_state for t in trial_set.trials] == [
        "cold", "cold", "warm", "warm", "steady", "steady", "steady",
    ]
    assert [t.wall_ms for t in trial_set.trials] == [
        10.0, 20.0, 21.0, 30.0, 31.0, 32.0, 33.0,
    ]
    assert all(t.valid for t in trial_set.trials)


def test_trial_walls_recorded_exactly(monkeypatch):
    """Wall times land on the trial in executor order, 1:1."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 16))
    executor = _executor([10.0, 20.0, 99.0, 21.0, 30.0, 31.0, 32.0, 33.0])
    trial_set = run_trials(
        workload="mirror", role="control", executor=executor,
        cold=2, warm=2, steady=3,
        clear_caches=lambda: None, prober=_prober(),
    )
    assert [t.wall_ms for t in trial_set.trials] == [
        10.0, 20.0, 21.0, 30.0, 31.0, 32.0, 33.0,
    ]


def test_affinity_not_applied_marks_every_trial_invalid(monkeypatch):
    """A run without the affinity control is not evidence; every trial must
    carry the explicit reason."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (False, 0))
    executor = _executor([10.0, 11.0, 12.0])
    trial_set = run_trials(
        workload="mirror", role="candidate", executor=executor,
        cold=0, warm=0, steady=3,
        clear_caches=lambda: None,
        prober=NoiseProber(
            affinity=lambda: (False, 0),
            governor=lambda: ("performance", 4200.0),
            load=lambda: (0.1, 0.1, 0.1),
        ),
    )
    assert [t.valid for t in trial_set.trials] == [False, False, False]
    assert trial_set.trials[0].invalid_reasons == (
        "affinity pinning was requested but not applied",
    )
    assert trial_set.valid_wall_ms() == []


def test_governor_mismatch_marks_trials_invalid(monkeypatch):
    """A host on a powersave governor throttles mid-run; trials under the
    wrong governor are flagged, never averaged in."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 8))
    executor = _executor([10.0, 11.0])
    trial_set = run_trials(
        workload="mirror", role="control", executor=executor,
        cold=0, warm=0, steady=2,
        governor_required="performance",
        clear_caches=lambda: None,
        prober=_prober(governor="powersave", freq=1800.0),
    )
    assert [t.valid for t in trial_set.trials] == [False, False]
    assert trial_set.trials[0].invalid_reasons == (
        "CPU governor is 'powersave', required 'performance'",
    )
    noise = trial_set.trials[0].noise
    assert noise.governor == "powersave"
    assert noise.frequency_mhz == 1800.0


def test_cold_trial_without_clear_hook_is_invalid(monkeypatch):
    """A cold trial with no cache-clear hook is not provably cold; marking it
    invalid beats silently benchmarking a warm cache as cold."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 8))
    executor = _executor([10.0])
    trial_set = run_trials(
        workload="mirror", role="control", executor=executor,
        cold=1, warm=0, steady=0,
        clear_caches=None,
        prober=_prober(),
    )
    assert trial_set.trials[0].invalid_reasons == (
        "cold trial ran without a cache-clear hook",
    )


def test_noise_receipt_records_load_and_affinity(monkeypatch):
    """The receipt carries the before/after load average and the affinity
    state the trial actually ran under."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 4))
    loads = iter([(1.0, 0.5, 0.2), (2.0, 1.0, 0.4)])
    executor = _executor([10.0])
    trial_set = run_trials(
        workload="mirror", role="control", executor=executor,
        cold=0, warm=0, steady=1,
        prober=NoiseProber(
            affinity=lambda: (True, 4),
            governor=lambda: ("performance", 4200.0),
            load=lambda: next(loads),
        ),
    )
    noise = trial_set.trials[0].noise
    assert noise.affinity_requested is True
    assert noise.affinity_applied is True
    assert noise.affinity_cpus == 4
    assert noise.load_avg_before == (1.0, 0.5, 0.2)
    assert noise.load_avg_after == (2.0, 1.0, 0.4)


def test_valid_wall_ms_filters_by_state_and_validity(monkeypatch):
    """Gate statistics consume only valid trials of the requested state."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 16))
    governors = iter(["performance", "powersave"])
    executor = _executor([10.0, 20.0])
    trial_set = run_trials(
        workload="mirror", role="control", executor=executor,
        cold=0, warm=0, steady=2,
        governor_required="performance",
        prober=NoiseProber(
            affinity=lambda: (True, 16),
            governor=lambda: (next(governors), 4000.0),
            load=lambda: (0.1, 0.1, 0.1),
        ),
    )
    assert trial_set.valid_wall_ms(CacheState.STEADY) == [10.0]
    assert trial_set.valid_wall_ms() == [10.0]


def test_trial_set_digest_binds_content(monkeypatch):
    """The receipt references the trial set by digest; any edit to a trial
    must change it."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 16))

    def build():
        """Test helper / contract verification."""
        return run_trials(
            workload="mirror", role="control",
            executor=_executor([10.0, 11.0]),
            cold=0, warm=0, steady=2,
            prober=_prober(),
        )

    first = build()
    assert first.digest() == build().digest()
    tampered = TrialSet(
        schema_version=first.schema_version,
        workload=first.workload,
        role=first.role,
        trials=first.trials[:1] + (
            type(first.trials[1])(
                index=1, cache_state="steady", wall_ms=999.0,
                profile=None, noise=first.trials[1].noise,
                invalid_reasons=(),
            ),
        ),
    )
    assert tampered.digest() != first.digest()


def test_trial_set_round_trip(monkeypatch):
    """Trial sets persist to JSON for the gate script; the codec must be
    lossless, receipts included."""
    monkeypatch.setattr("bench.trials.apply_affinity", lambda: (True, 16))
    trial_set = run_trials(
        workload="mirror", role="candidate",
        executor=_executor([10.0, 11.0, 12.0]),
        cold=0, warm=0, steady=3,
        governor_required="performance",
        prober=_prober(),
    )
    decoded = TrialSet.from_json(trial_set.to_json())
    assert decoded == trial_set
    assert decoded.digest() == trial_set.digest()


def test_run_trials_rejects_empty_plan():
    """A zero-trial plan would produce an empty, unverifiable trial set."""
    with pytest.raises(ValueError, match="at least one trial"):
        run_trials(
            workload="mirror", role="control",
            executor=_executor([]), cold=0, warm=0, steady=0,
            prober=_prober(),
        )
    with pytest.raises(ValueError, match="non-negative"):
        run_trials(
            workload="mirror", role="control",
            executor=_executor([]), cold=-1, warm=0, steady=0,
            prober=_prober(),
        )


def test_trial_set_rejects_bad_role():
    """Receipts pair exactly one control and one candidate set per workload."""
    with pytest.raises(ValueError, match="role"):
        TrialSet(schema_version="trial-set-v1", workload="w", role="middle",
                 trials=())


def test_noise_receipt_from_json_strict():
    """A stored receipt with missing or extra keys is corruption."""
    receipt = NoiseReceipt(
        affinity_requested=True, affinity_applied=True, affinity_cpus=8,
        governor="performance", governor_required="performance",
        frequency_mhz=4200.0,
        load_avg_before=(0.1, 0.2, 0.3), load_avg_after=(0.2, 0.2, 0.3),
    )
    assert NoiseReceipt.from_json(receipt.to_json()) == receipt
    payload = receipt.to_json()
    del payload["governor"]
    with pytest.raises(ValueError, match="missing required fields"):
        NoiseReceipt.from_json(payload)
    payload = receipt.to_json()
    payload["load_avg_before"] = [0.1]
    with pytest.raises(ValueError, match="load_avg_before"):
        NoiseReceipt.from_json(payload)
def test_cache_state_and_execution_route_identities():
    """WHY: KH-2006 requires distinct schema identities for all cache states and execution routes."""
    assert set(CacheState) == {
        CacheState.COLD,
        CacheState.WARM,
        CacheState.STEADY,
        CacheState.INCREMENTAL_WARM,
    }
    assert set(ExecutionRoute) == {
        ExecutionRoute.IN_PROCESS,
        ExecutionRoute.WARM_DAEMON,
        ExecutionRoute.MASS_DAEMON,
    }
    assert CacheState.INCREMENTAL_WARM.value == "incremental-warm"
    assert ExecutionRoute.WARM_DAEMON.value == "warm-daemon"
