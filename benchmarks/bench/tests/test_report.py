import json

import pytest

from bench import report
from bench.schema import BloomEvidence, CorpusInfo, Detection, Host, Outcome, RunResult
from bench.schema import Scanner as ScannerRecord
from bench.schema import ScannerConfig, Speed, StaticRecoveryMetrics


def _result(scanner: str, hits: int, wall_ms: float) -> RunResult:
    """Test helper / contract verification."""
    overall = Outcome(tp=hits, fp=0, fn=5 - hits)
    per_category = (
        {"generic": Outcome(tp=hits, fp=0, fn=5 - hits)}
        if scanner == "keyhog"
        else {}
    )
    return RunResult(
        generated_at="2026-07-25T06:57:58Z",
        host=Host(
            hostname_hash="0123456789ab",
            os="TestOS 1",
            cpu="Test CPU",
        ),
        scanner=ScannerRecord(
            name=scanner,
            version="test",
            config=ScannerConfig(),
            detector_corpus_sha256="d" * 64,
            executable_sha256="e" * 64,
        ),
        corpus=CorpusInfo(name="mirror", fixture_count=10, labeled_positives=5, bytes=100),
        detection=Detection(overall=overall, per_category=per_category),
        speed=Speed(wall_ms=wall_ms, throughput_mb_s=1.0, peak_rss_kb=1024),
        finding_count=hits,
        static_recovery=(
            StaticRecoveryMetrics() if scanner == "keyhog" else None
        ),
    )

def _bloom_evidence() -> BloomEvidence:
    """Test helper / contract verification."""
    return BloomEvidence(
        schema_version="bloom-evidence-v1",
        corpus_name="samsung-creddata-fx-record-spans-v1",
        corpus_revision="f1de3f85dbdf42bf7b3467c0d273a4dfe44d56ee",
        fixture_sha256="1" * 64,
        corpus_sha256="2" * 64,
        detector_corpus_sha256="3" * 64,
        scanner_detector_digest="4" * 16,
        executable_sha256="6" * 64,
        workspace_detector_corpus_sha256="7" * 64,
        declared_input_count=12,
        unavailable_input_count=2,
        unavailable_reason_counts={"source-file-missing": 2},
        input_count=10,
        eligible_input_count=8,
        admitted_input_count=6,
        rejected_input_count=4,
        rejection_basis_points=4_000,
        populated_slots=18_437,
        total_slots=65_536,
        saturation_threshold_slots=39_322,
        density_basis_points=2_813,
        state="healthy",
        enabled_finding_count=7,
        bypass_finding_count=7,
        enabled_findings_sha256="5" * 64,
        bypass_findings_sha256="5" * 64,
        findings_identical=True,
    )


def _run_set(result: RunResult, path: str = "selected.json") -> report.RunSet:
    """Test helper / contract verification."""
    if not result.scanner.executable_sha256:
        result.scanner.executable_sha256 = "a" * 64
    declaration = report.RunDeclaration(
        scanner=result.scanner.name,
        config_id=result.scanner.config_id,
        path=path,
        generated_at=result.generated_at,
        executable_sha256=result.scanner.executable_sha256,
        hostname_hash=result.host.hostname_hash,
        fixture_count=result.corpus.fixture_count,
        labeled_positives=result.corpus.labeled_positives,
        corpus_bytes=result.corpus.bytes,
    )
    return report.RunSet(corpus=result.corpus.name, runs=(declaration,))


def test_report_renders_keyhog_leaderboard_row():
    """Test helper / contract verification."""
    text = report.render_leaderboard(
        [_result("betterleaks", 2, 10.0), _result("keyhog", 5, 20.0)],
        "mirror",
    )

    assert "**KeyHog**" in text
    assert "Betterleaks" in text
    assert "Corpus: **mirror**" in text


def test_complete_provenance_uses_each_selected_result_fields():
    """Regression: leaderboard evidence must identify every measured result."""
    keyhog = _result("keyhog", 5, 20.0)
    keyhog.scanner.executable_sha256 = "a" * 64
    betterleaks = _result("betterleaks", 2, 10.0)
    betterleaks.scanner.version = ""
    betterleaks.scanner.executable_sha256 = "b" * 64

    text = report.render_leaderboard([keyhog, betterleaks], "mirror")

    assert "### Result provenance" in text
    assert "version: test" in text
    assert f"executable SHA-256: `{'a' * 64}`" in text
    assert "_version not recorded_" in text
    assert f"executable SHA-256: `{'b' * 64}`" in text
    assert "mirror; 10 fixtures; 5 labeled positives; 100 bytes" in text
    assert "hostname SHA-256/12: `0123456789ab`" in text
    assert "2026-07-25T06:57:58Z" in text
    assert report.provenance_errors(
        report.canonical_leaderboard([keyhog, betterleaks], "mirror"),
        "mirror",
    ) == []


def test_missing_provenance_is_explicit_and_blocks_report_writes(tmp_path):
    """Regression: absent identities must never publish as an attributable run."""
    result = _result("keyhog", 5, 20.0)
    result.scanner.version = ""
    result.scanner.executable_sha256 = ""
    result.corpus.bytes = 0
    result.host.hostname_hash = ""
    result.generated_at = ""

    text = report.render_leaderboard([result], "mirror")

    assert "_version not recorded_" in text
    assert "_executable SHA-256 not recorded_" in text
    assert "_missing bytes_" in text
    assert "_missing or invalid hostname hash_" in text
    assert "| _missing or invalid_ |" in text
    with pytest.raises(report.ReportEmptyError) as exc:
        report.write_reports([result], "mirror", tmp_path / "reports")
    message = str(exc.value)
    assert "neither scanner version nor executable SHA-256" in message
    assert "corpus bytes is missing" in message
    assert "host identity (`hostname_hash`) is missing or invalid" in message
    assert "run date (`generated_at`) is missing" in message


def test_conflicting_corpus_provenance_blocks_report_writes(tmp_path):
    """Regression: rows from different corpus snapshots must not share a table."""
    keyhog = _result("keyhog", 5, 20.0)
    competitor = _result("betterleaks", 2, 10.0)
    competitor.corpus.bytes = 101

    with pytest.raises(
        report.ReportEmptyError,
        match="conflicting identities for corpus 'mirror'",
    ):
        report.write_reports(
            [keyhog, competitor],
            "mirror",
            tmp_path / "reports",
        )


def test_adversarial_provenance_cannot_forge_markdown_rows():
    """Regression: result metadata must not inject table cells or HTML content."""
    result = _result("keyhog", 5, 20.0)
    result.scanner.version = "v1| forged\n<script>alert(1)</script>"
    result.host.os = "TestOS | forged\n</td>"

    text = report.render_leaderboard([result], "mirror")

    assert "v1&#124; forged<br>&lt;script&gt;alert(1)&lt;/script&gt;" in text
    assert "TestOS &#124; forged<br>&lt;/td&gt;" in text
    assert "<script>" not in text
    assert "\n<script>" not in text


@pytest.mark.target_spec
def test_committed_run_set_matches_exact_result_artifacts():
    """Regression: committed reports must remain bound to their declared JSON rows."""
    results_dir = report._BENCH_ROOT / "results"
    results = report.load_results(results_dir)
    if not results:
        pytest.skip(f"no benchmark results found in {results_dir}")
    run_set = report.load_run_set(report._DEFAULT_RUN_SET)

    selected = report.select_declared_results(results, "mirror", run_set)
    assert {row.scanner.name for row in selected} == {
        "keyhog",
        "kingfisher",
        "betterleaks",
    }


def test_explicit_run_set_selects_path_instead_of_newest_timestamp():
    """Regression: an archived newer timestamp must not replace a declared row."""
    declared = _result("keyhog", 5, 20.0)
    declared._report_source = "selected.json"
    archived = _result("keyhog", 1, 10.0)
    archived.generated_at = "2099-01-01T00:00:00Z"
    archived.scanner.executable_sha256 = "b" * 64
    archived._report_source = "archive/newer.json"
    run_set = _run_set(declared)

    selected = report.select_declared_results(
        [archived, declared],
        "mirror",
        run_set,
    )

    assert selected == [declared]


def test_run_set_refresh_rebinds_declared_path_and_round_trips_exact_toml(tmp_path):
    """A release refresh must update identities without selecting a newer undeclared row."""
    previous = _result("keyhog", 5, 20.0)
    current = _result("keyhog", 5, 18.0)
    current.generated_at = "2026-07-31T00:19:20Z"
    current.host.hostname_hash = "abcdef012345"
    current.scanner.executable_sha256 = "b" * 64
    current.corpus.fixture_count = 15_000
    current.corpus.labeled_positives = 3_000
    current.corpus.bytes = 2_430_321
    current._report_source = "selected.json"
    undeclared = _result("keyhog", 1, 5.0)
    undeclared.generated_at = "2099-01-01T00:00:00Z"
    undeclared.scanner.executable_sha256 = "c" * 64
    undeclared._report_source = "archive/newer.json"

    refreshed = report.refresh_run_set(
        [undeclared, current],
        "mirror",
        _run_set(previous),
    )

    declaration = refreshed.runs[0]
    assert declaration.path == "selected.json"
    assert declaration.generated_at == "2026-07-31T00:19:20Z"
    assert declaration.executable_sha256 == "b" * 64
    assert declaration.hostname_hash == "abcdef012345"
    assert declaration.fixture_count == 15_000
    assert declaration.labeled_positives == 3_000
    assert declaration.corpus_bytes == 2_430_321
    inventory = tmp_path / "canonical.toml"
    inventory.write_text(report.render_run_set(refreshed), encoding="utf-8")
    assert report.load_run_set(inventory) == refreshed


@pytest.mark.parametrize(
    ("field", "value", "diagnostic"),
    [
        ("scanner.name", "other", "scanner='other'"),
        ("scanner.config.mode", "fast", "config_id='default-nocache-nodaemon-fast'"),
        ("scanner.executable_sha256", "", "executable_sha256 is invalid"),
        ("host.hostname_hash", "not-a-hash", "hostname_hash is invalid"),
        ("corpus.fixture_count", 0, "corpus identity counts are invalid"),
    ],
)
def test_run_set_refresh_rejects_identity_drift(field, value, diagnostic):
    """Malformed or substituted result identity must not rewrite the canonical inventory."""
    result = _result("keyhog", 5, 20.0)
    result.scanner.executable_sha256 = "a" * 64
    result._report_source = "selected.json"
    current = _run_set(result)
    target = result
    segments = field.split(".")
    for segment in segments[:-1]:
        target = getattr(target, segment)
    setattr(target, segments[-1], value)

    with pytest.raises(report.ResultSelectionError, match=diagnostic):
        report.refresh_run_set([result], "mirror", current)


@pytest.mark.parametrize("match_count", [0, 2])
def test_run_set_refresh_requires_one_current_declared_path(match_count):
    """A missing or duplicated result path must not produce ambiguous release evidence."""
    result = _result("keyhog", 5, 20.0)
    result.scanner.executable_sha256 = "a" * 64
    result._report_source = "selected.json"

    with pytest.raises(
        report.ResultSelectionError,
        match=f"expected one current result, found {match_count}",
    ):
        report.refresh_run_set([result] * match_count, "mirror", _run_set(result))


@pytest.mark.parametrize("match_count", [0, 2])
def test_run_set_requires_exactly_one_artifact_per_declared_path(match_count):
    """Regression: missing or duplicate inventory paths must fail closed."""
    result = _result("keyhog", 5, 20.0)
    result._report_source = "selected.json"
    run_set = _run_set(result)
    candidates = [result] * match_count

    with pytest.raises(
        report.ResultSelectionError,
        match=f"expected exactly one result, found {match_count}",
    ):
        report.select_declared_results(candidates, "mirror", run_set)


@pytest.mark.parametrize(
    ("field", "value", "diagnostic"),
    [
        ("corpus.name", "other", "corpus='other'"),
        ("scanner.config.mode", "fast", "config_id='default-nocache-nodaemon-fast'"),
    ],
)
def test_run_set_rejects_wrong_corpus_or_config(field, value, diagnostic):
    """Regression: an exact path cannot bless a result with a different identity."""
    result = _result("keyhog", 5, 20.0)
    result._report_source = "selected.json"
    run_set = _run_set(result)
    owner, attribute = field.split(".", 1)
    target = result
    for segment in owner.split("."):
        target = getattr(target, segment)
    if "." in attribute:
        nested, attribute = attribute.split(".", 1)
        target = getattr(target, nested)
    setattr(target, attribute, value)

    with pytest.raises(report.ResultSelectionError, match=diagnostic):
        report.select_declared_results([result], "mirror", run_set)

def test_select_declared_results_rejects_mixed_host_and_mixed_detector():
    """WHY: KH-2008 requires report loading to reject mixed-host and mixed-detector rows."""
    res1 = _result("keyhog", 5, 20.0)
    res1.scanner.executable_sha256 = "a" * 64
    res1.scanner.detector_corpus_sha256 = "d" * 64
    res1.host.hostname_hash = "h11111111111"
    res1._report_source = "res1.json"

    res2 = _result("kingfisher", 4, 10.0)
    res2.scanner.executable_sha256 = "b" * 64
    res2.scanner.detector_corpus_sha256 = "d" * 64
    res2.host.hostname_hash = "h22222222222"
    res2._report_source = "res2.json"

    decl1 = report.RunDeclaration("keyhog", res1.scanner.config_id, "res1.json", res1.generated_at, res1.scanner.executable_sha256, res1.host.hostname_hash, res1.corpus.fixture_count, res1.corpus.labeled_positives, res1.corpus.bytes)
    decl2 = report.RunDeclaration("kingfisher", res2.scanner.config_id, "res2.json", res2.generated_at, res2.scanner.executable_sha256, res2.host.hostname_hash, res2.corpus.fixture_count, res2.corpus.labeled_positives, res2.corpus.bytes)
    run_set = report.RunSet(corpus="mirror", runs=(decl1, decl2))

    with pytest.raises(report.ResultSelectionError, match="mixed-host"):
        report.select_declared_results([res1, res2], "mirror", run_set)

    # Fix host, vary detector
    res2.host.hostname_hash = "h11111111111"
    decl2_fixed = report.RunDeclaration("kingfisher", res2.scanner.config_id, "res2.json", res2.generated_at, res2.scanner.executable_sha256, "h11111111111", res2.corpus.fixture_count, res2.corpus.labeled_positives, res2.corpus.bytes)
    res2.scanner.detector_corpus_sha256 = "a" * 64
    run_set_fixed = report.RunSet(corpus="mirror", runs=(decl1, decl2_fixed))

    with pytest.raises(report.ResultSelectionError, match="mixed-detector"):
        report.select_declared_results([res1, res2], "mirror", run_set_fixed)
    # Test mixing None detector corpus sha256 with non-None
    res2.scanner.detector_corpus_sha256 = None
    run_set_fixed = report.RunSet(corpus="mirror", runs=(decl1, decl2_fixed))
    with pytest.raises(report.ResultSelectionError, match="detector corpus identity is missing"):
        report.select_declared_results([res1, res2], "mirror", run_set_fixed)
    # Test all None detector corpus sha256
    res1.scanner.detector_corpus_sha256 = None
    res2.scanner.detector_corpus_sha256 = None
    run_set_fixed = report.RunSet(corpus="mirror", runs=(decl1, decl2_fixed))
    with pytest.raises(report.ResultSelectionError, match="detector corpus identity is missing"):
        report.select_declared_results([res1, res2], "mirror", run_set_fixed)

def test_undeclared_duplicate_default_results_are_ambiguous():
    """Regression: generated_at must never act as a silent newest-row policy."""
    older = _result("keyhog", 5, 20.0)
    older.scanner.config.backend = "simd"
    older.generated_at = "2026-01-01T00:00:00Z"
    older._report_source = "older.json"
    newer = _result("keyhog", 4, 10.0)
    newer.scanner.config.backend = "simd"
    newer.generated_at = "2099-01-01T00:00:00Z"
    newer._report_source = "newer.json"

    with pytest.raises(
        report.ResultSelectionError,
        match="ambiguous keyhog default-config results",
    ):
        report.canonical_leaderboard([older, newer], "mirror")


@pytest.mark.parametrize("observed", [None, "bench-v999"])
def test_load_results_rejects_incompatible_result_schema(tmp_path, observed):
    """Test helper / contract verification."""
    payload = _result("keyhog", 5, 20.0).to_json()
    if observed is None:
        payload.pop("schema_version")
    else:
        payload["schema_version"] = observed
    artifact = tmp_path / "invalid-result.json"
    artifact.write_text(json.dumps(payload))

    with pytest.raises(report.ResultLoadError) as exc:
        report.load_results(tmp_path)

    message = str(exc.value)
    assert str(artifact) in message
    assert "supported='bench-v4'" in message
    assert "Rerun the benchmark" in message


def test_static_recovery_report_renders_exact_counts_and_sorted_reasons():
    """Test helper / contract verification."""
    result = _result("keyhog", 5, 20.0)
    result.static_recovery = StaticRecoveryMetrics(
        supported=4,
        unsupported=2,
        erroneous=3,
        reasons={
            "resource_limit": 1,
            "unsupported_call": 2,
            "json_utf8": 2,
        },
    )

    rendered = report.render_static_recovery([result], "mirror")

    assert "| Supported | 4 |" in rendered
    assert "| Unsupported | 2 |" in rendered
    assert "| Erroneous | 3 |" in rendered
    assert rendered.index("`json_utf8`") < rendered.index("`resource_limit`")
    assert rendered.index("`resource_limit`") < rendered.index("`unsupported_call`")
    assert "mirror" in rendered
    assert "2026-07-25T06:57:58Z" in rendered


def test_static_recovery_report_renders_exact_zero():
    """Test helper / contract verification."""
    rendered = report.render_static_recovery([_result("keyhog", 5, 20.0)], "mirror")

    assert "| Supported | 0 |" in rendered
    assert "| Unsupported | 0 |" in rendered
    assert "| Erroneous | 0 |" in rendered
    assert "| _none_ | 0 |" in rendered


def test_static_recovery_report_marks_legacy_artifact_without_fake_zeroes():
    """Test helper / contract verification."""
    result = _result("keyhog", 5, 20.0)
    result.schema_version = "bench-v3"
    result.static_recovery = None

    rendered = report.render_static_recovery([result], "mirror")

    assert "predates `static-recovery-v1`" in rendered
    assert "no zero values are inferred" in rendered
    assert "| Supported | 0 |" not in rendered


def test_bloom_report_renders_real_rejection_identity_and_parity() -> None:
    """Test helper / contract verification."""
    result = _result("keyhog", 5, 20.0)
    result.bloom = _bloom_evidence()

    rendered = report.render_bloom_evidence([result], "mirror")

    assert "`samsung-creddata-fx-record-spans-v1`" in rendered
    assert "**4/10 (40.00%)**; 6 admitted" in rendered
    assert "**IDENTICAL**; 7/7 findings" in rendered
    assert "`5555555555555555555555555555555555555555555555555555555555555555`" in rendered
    assert "2 explicitly unavailable of 12 declared" in rendered
    assert "reasons: source-file-missing=2" in rendered


def test_bloom_report_never_infers_missing_evidence_as_zero() -> None:
    """Test helper / contract verification."""
    rendered = report.render_bloom_evidence(
        [_result("keyhog", 5, 20.0)],
        "mirror",
    )

    assert "was not recorded" in rendered
    assert "no synthetic or zero-valued fallback is inferred" in rendered
    assert "0/0" not in rendered


def test_report_inject_replaces_marker_body():
    """Test helper / contract verification."""
    original = "a\n<!-- BENCH:perf:start -->\nold\n<!-- BENCH:perf:end -->\nz"

    updated = report.inject(original, "perf", "new")

    assert updated == "a\n<!-- BENCH:perf:start -->\nnew\n<!-- BENCH:perf:end -->\nz"


def test_written_reports_are_never_reported_stale(tmp_path):
    # Single-owner invariant: write_reports and stale_report_paths both consume
    # report_files(), so anything just written must NOT be flagged stale. This
    # fails if the two ever diverge (the byte-identical-dict drift risk removed
    # by factoring report_files).
    """Test helper / contract verification."""
    result = _result("keyhog", 5, 20.0)
    reports_dir = tmp_path / "reports"

    report.write_reports([result], "mirror", reports_dir)

    written = {p.name for p in reports_dir.iterdir()}
    assert "category-recall.md" in written, "category-recall dashboard must be written"
    assert written == set(report.report_files([result], "mirror")), (
        "write_reports must emit exactly the report_files() set"
    )
    assert report.stale_report_paths([result], "mirror", reports_dir) == [], (
        "freshly-written reports must not be flagged stale"
    )


def test_report_check_does_not_write_stale_reports(tmp_path, capsys):
    """Test helper / contract verification."""
    result = _result("keyhog", 5, 20.0)
    results_dir = tmp_path / "results"
    reports_dir = tmp_path / "reports"
    readme = tmp_path / "README.md"
    results_dir.mkdir()
    (results_dir / "run.json").write_text(json.dumps(result.to_json()), encoding="utf-8")

    text = "\n".join([
        "<!-- BENCH:leaderboard:start -->",
        "old",
        "<!-- BENCH:leaderboard:end -->",
        "<!-- BENCH:perf:start -->",
        "old",
        "<!-- BENCH:perf:end -->",
        "<!-- BENCH:gaps:start -->",
        "old",
        "<!-- BENCH:gaps:end -->",
        "<!-- BENCH:recovery:start -->",
        "old",
        "<!-- BENCH:recovery:end -->",
        "<!-- BENCH:bloom:start -->",
        "old",
        "<!-- BENCH:bloom:end -->",
        "",
    ])
    sections = report.build_sections([result], "mirror")
    for name, body in sections.items():
        text = report.inject(text, name, body)
    readme.write_text(text, encoding="utf-8")

    code = report._main([
        "--results",
        str(results_dir),
        "--reports",
        str(reports_dir),
        "--readme",
        str(readme),
        "--corpus",
        "mirror",
        "--check",
    ])

    assert code == 1
    assert not reports_dir.exists()
    assert "Benchmark reports are stale" in capsys.readouterr().err


def test_gap_report_shows_category_recall_gap_dashboard():
    """Test helper / contract verification."""
    keyhog = _result("keyhog", 3, 20.0)
    keyhog.detection.per_category = {"generic": Outcome(tp=1, fp=0, fn=2)}
    noisy = _result("betterleaks", 2, 10.0)
    noisy.detection.overall = Outcome(tp=2, fp=8, fn=3)
    noisy.detection.per_category = {"generic": Outcome(tp=3, fp=1, fn=0)}

    text = report.render_gaps([keyhog, noisy], "mirror")

    assert "KeyHog P/R/F1" in text
    assert "Recall gap" in text
    assert "| `generic` | 1.000 / 0.333 / 0.500 | 1/2 | Betterleaks 0.750 / 1.000 / 0.857 | +0.667 |" in text


def test_category_recall_gap_does_not_claim_overall_competitor_superiority():
    """A category recall win must retain the overall precision/F1 interpretation."""
    keyhog = _result("keyhog", 3, 20.0)
    keyhog.detection.per_category = {"generic": Outcome(tp=1, fp=0, fn=2)}
    noisy = _result("betterleaks", 2, 10.0)
    noisy.detection.overall = Outcome(tp=2, fp=80, fn=3)
    noisy.detection.per_category = {"generic": Outcome(tp=3, fp=0, fn=0)}

    text = report.render_recall_gap([keyhog, noisy], "mirror")

    assert "Diagnostic recall slice only" in text
    assert "Overall precision and F1 remain the comparison contract" in text
    assert "false positives are counted in their scored categories" in text


def test_primary_category_collapses_composite_labels_to_last_atom():
    """Test helper / contract verification."""
    assert report.primary_category("API:Anthropic API Key:Key") == "Key"
    assert report.primary_category("Token:UUID") == "UUID"
    assert report.primary_category("Password") == "Password"
    assert report.primary_category("") == "unknown"
    assert report.primary_category(None) == "unknown"


def test_collapse_per_category_sums_fragmented_cells_into_primary():
    """Test helper / contract verification."""
    per_cat = {
        "API:Anthropic API Key:Key": Outcome(tp=1, fp=2, fn=3),
        "AWS:Key": Outcome(tp=4, fp=0, fn=5),
        "Token:UUID": Outcome(tp=0, fp=0, fn=7),
    }
    collapsed = report.collapse_per_category(per_cat)
    assert collapsed["Key"].tp == 5
    assert collapsed["Key"].fp == 2
    assert collapsed["Key"].fn == 8
    assert collapsed["UUID"].fn == 7


def test_category_recall_dashboard_ranks_by_miss_count():
    """Test helper / contract verification."""
    keyhog = _result("keyhog", 3, 20.0)
    keyhog.corpus.name = "creddata"
    keyhog.detection.per_category = {
        "API:Key": Outcome(tp=80, fp=200, fn=3700),
        "Token:UUID": Outcome(tp=7, fp=10, fn=2260),
        "Password": Outcome(tp=1145, fp=985, fn=1221),
    }
    better = _result("betterleaks", 2, 10.0)
    better.corpus.name = "creddata"
    better.detection.per_category = {
        "API:Key": Outcome(tp=3300, fp=100, fn=500),
        "Password": Outcome(tp=1000, fp=50, fn=1366),
    }

    text = report.render_category_recall([keyhog, better], "creddata")
    lines = [ln for ln in text.splitlines() if ln.startswith("| `")]
    # Key has the most misses, so it must rank first; UUID second.
    assert lines[0].startswith("| `Key` |")
    assert lines[1].startswith("| `UUID` |")
    assert "| `Key` | 80/3700 | 0.021 | Betterleaks 0.868 |" in text
    # UUID has no competitor cell: say so explicitly instead of fabricating a
    # zero-recall winner or emitting punctuation that looks like corruption.
    assert "| `UUID` | 7/2260 | 0.003 | N/A |" in text


def test_class_recall_differential_requires_full_scanner_set():
    """Test helper / contract verification."""
    keyhog = _result("keyhog", 3, 20.0)
    keyhog.detection.per_category = {"generic": Outcome(tp=1, fp=0, fn=2)}
    better = _result("betterleaks", 2, 10.0)
    better.detection.per_category = {"generic": Outcome(tp=3, fp=1, fn=0)}

    with pytest.raises(ValueError, match="missing required scanner"):
        report.class_recall_differential(
            [keyhog, better],
            "mirror",
            report.FULL_DIFFERENTIAL_SCANNERS,
        )


def test_class_recall_differential_records_competitor_map():
    """Test helper / contract verification."""
    rows = []
    for name, tp in [
        ("keyhog", 1),
        ("betterleaks", 3),
        ("kingfisher", 2),
        ("trufflehog", 1),
        ("titus", 1),
        ("noseyparker", 0),
    ]:
        result = _result(name, tp, 10.0)
        result.detection.per_category = {"generic": Outcome(tp=tp, fp=0, fn=3 - tp)}
        rows.append(result)

    diff = report.class_recall_differential(
        rows,
        "mirror",
        report.FULL_DIFFERENTIAL_SCANNERS,
    )

    generic = diff["rows"]["generic"]
    assert diff["scanner_count"] == 6
    assert set(generic["competitors"]) == {
        "betterleaks",
        "kingfisher",
        "trufflehog",
        "titus",
        "noseyparker",
    }
    assert generic["best_competitor"]["scanner"] == "betterleaks"
    assert generic["recall_gap"] == 0.6667

def test_write_reports_refuses_empty_results(tmp_path):
    """A report with no measured rows must fail, not write placeholder markdown."""
    reports_dir = tmp_path / "reports"
    with pytest.raises(report.ReportEmptyError, match="leaderboard has no rows"):
        report.write_reports([], "mirror", reports_dir)
    assert not reports_dir.exists(), "write_reports must not create output on failure"


def test_report_main_exits_on_empty_results(tmp_path, capsys):
    """`_main` must return non-zero and print a useful error when results/ is empty."""
    results_dir = tmp_path / "results"
    reports_dir = tmp_path / "reports"
    readme = tmp_path / "README.md"
    results_dir.mkdir()
    code = report._main([
        "--results", str(results_dir),
        "--reports", str(reports_dir),
        "--readme", str(readme),
        "--corpus", "mirror",
    ])
    assert code == 1
    err = capsys.readouterr().err
    assert "cannot render reports for corpus 'mirror'" in err
    assert "leaderboard has no rows" in err
    assert not reports_dir.exists()


def test_report_main_exits_on_missing_keyhog(tmp_path, capsys):
    """A corpus measured only by competitors cannot render keyhog-specific reports."""
    results_dir = tmp_path / "results"
    reports_dir = tmp_path / "reports"
    results_dir.mkdir()
    better = _result("betterleaks", 2, 10.0)
    (results_dir / "betterleaks.json").write_text(json.dumps(better.to_json()))

    code = report._main([
        "--results", str(results_dir),
        "--reports", str(reports_dir),
        "--corpus", "mirror",
    ])
    assert code == 1
    assert "keyhog row missing" in capsys.readouterr().err
    assert not reports_dir.exists()


def test_report_renders_all_rollup_files_with_keyhog_and_competitor():
    """A real measurement populates leaderboard, perf, recall-gap, and category-recall."""
    keyhog = _result("keyhog", 3, 20.0)
    keyhog.detection.per_category = {"generic": Outcome(tp=1, fp=0, fn=2)}
    noisy = _result("betterleaks", 2, 10.0)
    noisy.detection.per_category = {"generic": Outcome(tp=3, fp=1, fn=0)}

    files = report.report_files([keyhog, noisy], "mirror")
    assert "leaderboard.md" in files
    assert "perf.md" in files
    assert "recall-gap.md" in files
    assert "category-recall.md" in files

    lb = files["leaderboard.md"]
    assert "KeyHog" in lb
    assert "Betterleaks" in lb
    assert "_No results" not in lb

    perf = files["perf.md"]
    assert "KeyHog" in perf
    assert "_No timed runs" not in perf

    gap = files["recall-gap.md"]
    assert "_No keyhog result" not in gap
    assert "KeyHog P/R/F1" in gap

    cat = files["category-recall.md"]
    assert "_No keyhog per-category" not in cat
    assert "| `generic` |" in cat


def test_written_reports_round_trip_through_stale_check(tmp_path):
    """write_reports -> stale_report_paths is empty; a mutation is detected."""
    result = _result("keyhog", 5, 20.0)
    reports_dir = tmp_path / "reports"
    report.write_reports([result], "mirror", reports_dir)

    assert report.stale_report_paths([result], "mirror", reports_dir) == []

    (reports_dir / "leaderboard.md").write_text("stale")
    stale = report.stale_report_paths([result], "mirror", reports_dir)
    assert len(stale) == 1
    assert stale[0].name == "leaderboard.md"


def test_load_results_skips_non_runresult_artifacts_and_rejects_bad_schema(tmp_path):
    """Malformed or non-RunResult JSON must be ignored; wrong schema raises."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    (results_dir / "list.json").write_text("[]")
    (results_dir / "string.json").write_text('"not a dict"')
    (results_dir / "missing_keys.json").write_text(
        json.dumps({"schema_version": "bench-v3"})
    )
    valid = _result("keyhog", 5, 20.0)
    (results_dir / "valid.json").write_text(json.dumps(valid.to_json()))

    loaded = report.load_results(results_dir)
    assert len(loaded) == 1
    assert loaded[0].scanner.name == "keyhog"

    (results_dir / "bad_schema.json").write_text(
        json.dumps({
            "schema_version": "bench-v999",
            "scanner": {"name": "keyhog"},
            "detection": {"overall": {}},
        })
    )
    with pytest.raises(report.ResultLoadError, match="Rerun the benchmark"):
        report.load_results(results_dir)


def test_perf_section_is_filtered_to_requested_corpus():
    """build_sections must only put rows for the selected corpus in the perf table."""
    mirror = _result("keyhog", 5, 20.0)
    creddata = _result("keyhog", 4, 30.0)
    creddata.corpus.name = "creddata"

    sections = report.build_sections([mirror, creddata], "mirror")
    assert "mirror" in sections["perf"]
    assert "creddata" not in sections["perf"]

    sections_all = report.build_sections([mirror, creddata], "creddata")
    assert "creddata" in sections_all["perf"]
    assert "mirror" not in sections_all["perf"]

def test_recall_gap_comparison_unavailable_without_keyhog():
    """If keyhog is missing, the gap report names the missing input."""
    better = _result("betterleaks", 2, 10.0)
    text = report.render_recall_gap([better], "mirror")
    assert "Per-category recall comparison unavailable" in text
    assert "no keyhog result" in text
    assert "matches" not in text.lower()


def test_recall_gap_comparison_unavailable_without_competitors():
    """If only keyhog measured, the report names the missing competitors."""
    keyhog = _result("keyhog", 3, 20.0)
    text = report.render_recall_gap([keyhog], "mirror")
    assert "Per-category recall comparison unavailable" in text
    assert "no competitor results" in text
    assert "matches or beats" not in text


def test_recall_gap_reports_no_measured_gap_neutrally():
    """When competitors exist but none beat keyhog, the message is evidence-backed."""
    keyhog = _result("keyhog", 5, 20.0)
    # betterleaks recall on generic is lower than keyhog's 1.0
    better = _result("betterleaks", 2, 10.0)
    better.detection.per_category = {"generic": Outcome(tp=1, fp=0, fn=4)}
    keyhog.detection.per_category = {"generic": Outcome(tp=5, fp=0, fn=0)}
    text = report.render_recall_gap([keyhog, better], "mirror")
    assert "No measured competitor exceeds KeyHog recall" in text
    assert "KeyHog" in text
    assert "matches or beats" not in text


def test_multi_corpus_provenance_deduplicates_scanners_with_combined_corpus_cell():
    """Provenance table must show one row per scanner with combined corpus identities."""
    keyhog_mirror = _result("keyhog", 5, 20.0)
    keyhog_mirror.scanner.executable_sha256 = "a" * 64
    keyhog_homefield = _result("keyhog", 4, 15.0)
    keyhog_homefield.corpus.name = "homefield"
    keyhog_homefield.corpus.fixture_count = 2399
    keyhog_homefield.corpus.labeled_positives = 1057
    keyhog_homefield.corpus.bytes = 772974
    keyhog_homefield.scanner.executable_sha256 = "a" * 64

    text = report.render_leaderboard([keyhog_mirror, keyhog_homefield], "mirror")
    assert "#### Synthetic SecretBench-shape mirror corpus" in text
    assert "#### Competitor homefield / home-turf rule corpus" in text
    # In provenance table, KeyHog should appear exactly once
    provenance_section = text.split("### Result provenance")[1]
    assert provenance_section.count("| KeyHog |") == 1
    assert "mirror; 10 fixtures; 5 labeled positives; 100 bytes<br>homefield; 2,399 fixtures; 1,057 labeled positives; 772,974 bytes" in provenance_section
