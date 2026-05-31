from bench.schema import (
    CorpusInfo,
    Detection,
    Host,
    Outcome,
    RunResult,
    Scanner,
    ScannerConfig,
    Speed,
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


def test_outcome_metrics_handle_zero_denominators():
    empty = Outcome()
    assert empty.precision() == 0.0
    assert empty.recall() == 0.0
    assert empty.f1() == 0.0

    outcome = Outcome(tp=3, fp=1, fn=2)
    assert round(outcome.precision(), 4) == 0.75
    assert round(outcome.recall(), 4) == 0.6
    assert round(outcome.f1(), 4) == 0.6667
