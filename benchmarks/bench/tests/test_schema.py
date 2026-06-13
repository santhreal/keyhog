from bench.schema import (
    CONF_BINS,
    CorpusInfo,
    Detection,
    DetectorStat,
    Host,
    Outcome,
    RunResult,
    Scanner,
    ScannerConfig,
    Speed,
    conf_bin,
)


def test_run_result_round_trips_losslessly():
    result = RunResult(
        generated_at="2026-05-31T00:00:00Z",
        host=Host(os="Linux", cpu="test-cpu", cores=32, ram_mb=65536),
        scanner=Scanner(
            name="keyhog",
            version="0.5.37",
            config=ScannerConfig(backend="simd", cache="off", daemon="off", mode="full"),
        ),
        corpus=CorpusInfo(name="mirror", fixture_count=3, labeled_positives=2, bytes=128),
        detection=Detection(overall=Outcome(tp=2, fp=1, fn=0)),
        speed=Speed(wall_ms=12.345, throughput_mb_s=10.0, peak_rss_kb=4096),
        finding_count=3,
        exit_code=1,
        timed_out=False,
    )

    encoded = result.to_json()
    decoded = RunResult.from_json(encoded)

    assert decoded.to_json() == encoded
    assert decoded.scanner.config_id == "simd-nocache-nodaemon-full"
    assert decoded.result_filename() == "mirror-keyhog-simd-nocache-nodaemon-full.json"


def test_scanner_config_min_confidence_is_optional_and_off_the_matrix_key():
    """`min_confidence` is the harvest-only report-floor override. Unset (every
    leaderboard config) it is omitted from JSON and absent from `config_id`;
    set, it round-trips but STILL does not change `config_id` — a harvest scan
    must never fork the stable matrix key the README table / gate index on."""
    default = ScannerConfig(backend="simd")
    assert default.min_confidence is None
    assert "min_confidence" not in default.to_json()
    assert default.config_id == "simd-nocache-nodaemon-full"
    assert ScannerConfig.from_json(default.to_json()).min_confidence is None

    floored = ScannerConfig(backend="simd", min_confidence=0.0)
    encoded = floored.to_json()
    assert encoded["min_confidence"] == 0.0
    assert ScannerConfig.from_json(encoded).min_confidence == 0.0
    assert floored.config_id == default.config_id  # harvest floor ∉ matrix key


def test_per_detector_round_trips_with_histograms():
    aws = DetectorStat(unique_tp=2)
    aws.add_tp(0.91)   # tp -> 1
    aws.add_tp(0.62)   # tp -> 2
    aws.add_fp(0.41)   # fp -> 1
    assert aws.tp == 2 and aws.fp == 1  # add_* drives both count and histogram
    detection = Detection(
        overall=Outcome(tp=2, fp=1, fn=0),
        per_detector={"aws-secret-access-key": aws},
    )
    result = RunResult(detection=detection)

    encoded = result.to_json()
    decoded = RunResult.from_json(encoded)

    assert decoded.to_json() == encoded
    rt = decoded.detection.per_detector["aws-secret-access-key"]
    assert rt.tp == 2 and rt.fp == 1 and rt.unique_tp == 2
    assert len(rt.tp_hist) == CONF_BINS and len(rt.fp_hist) == CONF_BINS
    assert sum(rt.tp_hist) == 2  # two TP findings carried confidence
    assert sum(rt.fp_hist) == 1
    assert round(rt.precision(), 4) == 0.6667


def test_conf_bin_buckets_and_clamps():
    assert conf_bin(0.0) == 0
    assert conf_bin(0.049) == 0
    assert conf_bin(0.05) == 1
    assert conf_bin(0.99) == CONF_BINS - 1
    assert conf_bin(1.0) == CONF_BINS - 1  # clamp, never out of range
    assert conf_bin(1.7) == CONF_BINS - 1
    assert conf_bin(-0.3) == 0


def test_outcome_metrics_handle_zero_denominators():
    empty = Outcome()
    assert empty.precision() == 0.0
    assert empty.recall() == 0.0
    assert empty.f1() == 0.0

    outcome = Outcome(tp=3, fp=1, fn=2)
    assert round(outcome.precision(), 4) == 0.75
    assert round(outcome.recall(), 4) == 0.6
    assert round(outcome.f1(), 4) == 0.6667
