import pytest

from bench.schema import (
    CONF_BINS,
    BLOOM_EVIDENCE_SCHEMA_VERSION,
    BloomEvidence,
    CorpusInfo,
    Detection,
    DetectorStat,
    Host,
    HostedBinding,
    Outcome,
    RunResult,
    Scanner,
    ScannerConfig,
    Speed,
    StaticRecoveryMetrics,
    conf_bin,
)


def bloom_evidence(**overrides) -> BloomEvidence:
    values = {
        "schema_version": BLOOM_EVIDENCE_SCHEMA_VERSION,
        "corpus_name": "samsung-creddata-fx-record-spans-v1",
        "corpus_revision": "f1de3f85dbdf42bf7b3467c0d273a4dfe44d56ee",
        "fixture_sha256": "1" * 64,
        "corpus_sha256": "2" * 64,
        "detector_corpus_sha256": "3" * 64,
        "scanner_detector_digest": "4" * 16,
        "executable_sha256": "6" * 64,
        "workspace_detector_corpus_sha256": "7" * 64,
        "declared_input_count": 12,
        "unavailable_input_count": 2,
        "unavailable_reason_counts": {"source-file-missing": 2},
        "input_count": 10,
        "eligible_input_count": 8,
        "admitted_input_count": 6,
        "rejected_input_count": 4,
        "rejection_basis_points": 4_000,
        "populated_slots": 18_437,
        "total_slots": 65_536,
        "saturation_threshold_slots": 39_322,
        "density_basis_points": 2_813,
        "state": "healthy",
        "enabled_finding_count": 7,
        "bypass_finding_count": 7,
        "enabled_findings_sha256": "5" * 64,
        "bypass_findings_sha256": "5" * 64,
        "findings_identical": True,
    }
    values.update(overrides)
    return BloomEvidence(**values)


def test_run_result_round_trips_losslessly():
    """Guards run result round trips losslessly; prevents this evidence regression from false-passing or crashing."""
    result = RunResult(
        generated_at="2026-05-31T00:00:00Z",
        host=Host(
            os="Linux",
            cpu="test-cpu",
            cores=32,
            affinity_cores=4,
            cgroup_quota_cores=4.0,
            ram_mb=65536,
        ),
        scanner=Scanner(
            name="keyhog",
            version="0.5.37",
            config=ScannerConfig(backend="simd", cache="off", daemon="on", mode="full"),
            executable_sha256="b" * 64,
            detector_corpus_sha256="a" * 64,
            execution_route="daemon",
            daemon_pid=4242,
            daemon_requests=2,
        ),
        corpus=CorpusInfo(
            name="mirror",
            fixture_count=3,
            labeled_positives=2,
            bytes=128,
            workload_sha256="c" * 64,
        ),
        detection=Detection(overall=Outcome(tp=2, fp=1, fn=0)),
        speed=Speed(wall_ms=12.345, throughput_mb_s=10.0, peak_rss_kb=4096),
        finding_count=3,
        exit_code=1,
        timed_out=False,
        scan_manifest={
            "schema_version": 1,
            "preset": "full",
            "effective": {"max_decode_depth": "10"},
            "overrides": [],
        },
        static_recovery=StaticRecoveryMetrics(
            supported=3,
            unsupported=2,
            erroneous=4,
            reasons={
                "unsupported_call": 1,
                "dynamic_property_access": 1,
                "json_utf8": 4,
            },
        ),
        bloom=bloom_evidence(),
        hosted_binding=HostedBinding(
            context_sha256="d" * 64,
            repository="owner/keyhog",
            workflow_ref="owner/keyhog/.github/workflows/bench.yml@refs/heads/main",
            workflow_sha="e" * 40,
            run_id="1234",
            run_attempt="2",
            job="leaderboard",
        ),
    )

    encoded = result.to_json()
    decoded = RunResult.from_json(encoded)

    assert decoded.to_json() == encoded
    assert decoded.scanner.config_id == "simd-nocache-daemon-full"
    assert decoded.scanner.executable_sha256 == "b" * 64
    assert decoded.scanner.detector_corpus_sha256 == "a" * 64
    assert decoded.scanner.execution_route == "daemon"
    assert decoded.scanner.daemon_pid == 4242
    assert decoded.scanner.daemon_requests == 2
    assert decoded.scan_manifest["preset"] == "full"
    assert decoded.static_recovery == result.static_recovery
    assert decoded.bloom == result.bloom
    assert decoded.host.affinity_cores == 4
    assert decoded.host.cgroup_quota_cores == 4.0
    assert decoded.hosted_binding == result.hosted_binding
    assert decoded.result_filename() == "mirror-keyhog-simd-nocache-daemon-full.json"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(context_sha256=True),
        lambda value: value.update(repository=True),
        lambda value: value.update(run_id=True),
        lambda value: value.update(run_attempt=False),
        lambda value: value.pop("job"),
        lambda value: value.update(extra="unexpected"),
    ],
)
def test_hosted_binding_rejects_malformed_and_bool_fields(mutation):
    """Guards hosted binding rejects malformed and bool fields; prevents this evidence regression from false-passing or crashing."""
    value = HostedBinding(
        context_sha256="d" * 64,
        repository="owner/keyhog",
        workflow_ref="owner/keyhog/.github/workflows/bench.yml@refs/heads/main",
        workflow_sha="e" * 40,
        run_id="1234",
        run_attempt="2",
        job="leaderboard",
    ).to_json()
    mutation(value)

    with pytest.raises((TypeError, ValueError), match="hosted binding"):
        HostedBinding.from_json(value)


def test_hosted_binding_requires_an_object():
    """Guards hosted binding requires an object; prevents this evidence regression from false-passing or crashing."""
    with pytest.raises(ValueError, match="hosted binding must be an object"):
        HostedBinding.from_json(True)


@pytest.mark.parametrize("observed", [None, "bench-v999"])
def test_run_result_rejects_missing_or_unsupported_schema(observed):
    """Guards run result rejects missing or unsupported schema; prevents this evidence regression from false-passing or crashing."""
    payload = RunResult().to_json()
    if observed is None:
        payload.pop("schema_version")
    else:
        payload["schema_version"] = observed

    with pytest.raises(ValueError, match="supported='bench-v4'"):
        RunResult.from_json(payload, source="fixture.json")


def test_current_keyhog_result_requires_exact_static_recovery_object():
    """Guards current keyhog result requires exact static recovery object; prevents this evidence regression from false-passing or crashing."""
    payload = RunResult(
        scanner=Scanner(name="keyhog"),
        static_recovery=StaticRecoveryMetrics(),
    ).to_json()
    payload.pop("static_recovery")

    with pytest.raises(ValueError, match="lacks required 'static_recovery' telemetry"):
        RunResult.from_json(payload, source="fixture.json")


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda value: value.update(schema_version="future"), "schema_version"),
        (lambda value: value.pop("supported"), "missing required fields"),
        (lambda value: value.update(unsupported=-1), "non-negative integer"),
        (
            lambda value: value.update(
                unsupported=2,
                reasons={"unsupported_call": 1},
            ),
            "reason conservation failed",
        ),
        (
            lambda value: value.update(reasons={"unknown_reason": 1}),
            "unknown rejection reasons",
        ),
    ],
)
def test_static_recovery_schema_rejects_malformed_or_nonconserving_data(
    mutation, message
):
    """Guards static recovery schema rejects malformed or nonconserving data; prevents this evidence regression from false-passing or crashing."""
    value = StaticRecoveryMetrics().to_json()
    mutation(value)
    with pytest.raises(ValueError, match=message):
        StaticRecoveryMetrics.from_json(value)


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda value: value.update(schema_version="future"), "schema_version"),
        (lambda value: value.pop("corpus_sha256"), "missing required fields"),
        (lambda value: value.update(corpus_sha256="bad"), "lowercase SHA-256"),
        (lambda value: value.update(admitted_input_count=5), "conservation failed"),
        (lambda value: value.update(rejection_basis_points=3_999), "basis points"),
        (
            lambda value: value.update(bypass_findings_sha256="6" * 64),
            "identical finding claim",
        ),
        (
            lambda value: value.update(
                unavailable_reason_counts={"source-file-missing": 1}
            ),
            "unavailable reason accounting",
        ),
        (
            lambda value: value.update(unavailable_reason_counts={"other": 2}),
            "unavailable reason is invalid",
        ),
    ],
)
def test_bloom_evidence_rejects_malformed_or_nonconserving_data(
    mutation, message
):
    """Guards bloom evidence rejects malformed or nonconserving data; prevents this evidence regression from false-passing or crashing."""
    value = bloom_evidence().to_json()
    mutation(value)
    with pytest.raises(ValueError, match=message):
        BloomEvidence.from_json(value)


def test_legacy_v3_result_is_explicitly_supported_without_invented_metrics():
    """Guards legacy v3 result is explicitly supported without invented metrics; prevents this evidence regression from false-passing or crashing."""
    payload = RunResult().to_json()
    payload["schema_version"] = "bench-v3"
    payload.pop("static_recovery")
    payload.pop("bloom")
    payload.pop("hosted_binding")

    result = RunResult.from_json(payload, source="legacy.json")

    assert result.schema_version == "bench-v3"
    assert result.static_recovery is None
    assert "static_recovery" not in result.to_json()
    assert result.bloom is None
    assert "bloom" not in result.to_json()
    assert result.hosted_binding is None
    assert "hosted_binding" not in result.to_json()


def test_scanner_config_min_confidence_is_optional_and_off_the_matrix_key():
    """`min_confidence` is the harvest-only report-floor override. Unset (every
    leaderboard config) it is omitted from JSON and absent from `config_id`;
    set, it round-trips but STILL does not change `config_id`: a harvest scan
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
    """Guards per detector round trips with histograms; prevents this evidence regression from false-passing or crashing."""
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
    """Guards conf bin buckets and clamps; prevents this evidence regression from false-passing or crashing."""
    assert conf_bin(0.0) == 0
    assert conf_bin(0.049) == 0
    assert conf_bin(0.05) == 1
    assert conf_bin(0.99) == CONF_BINS - 1
    assert conf_bin(1.0) == CONF_BINS - 1  # clamp, never out of range
    assert conf_bin(1.7) == CONF_BINS - 1
    assert conf_bin(-0.3) == 0


def test_outcome_metrics_handle_zero_denominators():
    """Guards outcome metrics handle zero denominators; prevents this evidence regression from false-passing or crashing."""
    empty = Outcome()
    assert empty.precision() == 0.0
    assert empty.recall() == 0.0
    assert empty.f1() == 0.0

    outcome = Outcome(tp=3, fp=1, fn=2)
    assert round(outcome.precision(), 4) == 0.75
    assert round(outcome.recall(), 4) == 0.6
    assert round(outcome.f1(), 4) == 0.6667
