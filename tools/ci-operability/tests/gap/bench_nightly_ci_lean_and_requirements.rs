//! KH-GAP-081: bench-nightly runs on CPU-only `ubuntu-latest` and must build a
//! keyhog binary that does not try to load `libcuda`. The 2026-07-24 run
//! (santhreal/keyhog/actions/runs/30073950405) failed in
//! `test_fused_autoroute_calibration_cache_replay_matches_simd` because the
//! release binary was built with the default feature set; the benchmark `auto`
//! backend then triggered a cudarc panic on the GPU-less runner:
//!
//!   Unable to dynamically load the "cuda" shared library
//!
//! Building with `--no-default-features --features ci-lean` keeps
//! SIMD/Hyperscan but drops the GPU dispatch stack, matching the `ci.yml`
//! strict-runner job. The workflow must also install the full
//! `benchmarks/requirements.txt` (pyarrow + pytest) before running the bench
//! package, use the production `make leaderboard`/`make report` targets so
//! empty/unavailable results fail closed, and set `if-no-files-found: error`
//! on the artifact upload.

use super::support::read_workflow;

#[test]
fn bench_nightly_is_ci_lean_and_rejects_empty_or_stale_artifacts() {
    let text = read_workflow("bench-nightly.yml");

    assert!(
        text.contains("runs-on: ubuntu-latest"),
        "bench-nightly is pinned to hosted CPU-only runners"
    );

    let build_step = text
        .split("name: Build keyhog release binary")
        .nth(1)
        .expect("bench-nightly must have a 'Build keyhog release binary' step");
    let run_block = build_step
        .split("run:")
        .nth(1)
        .unwrap_or(build_step)
        .lines()
        .take(10)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        run_block.contains("--no-default-features") && run_block.contains("--features ci-lean"),
        "bench-nightly must build keyhog with --no-default-features --features ci-lean on \
         CPU-only ubuntu-latest; the default GPU feature set aborts when libcuda is absent"
    );
    assert!(
        text.contains("python3 -m pip install -r benchmarks/requirements.txt"),
        "bench-nightly must install the complete pinned benchmark requirements"
    );

    let clean = text
        .find("rm -rf benchmarks/results-nightly benchmarks/results-ioc-recovery")
        .expect("bench-nightly must remove its isolated generated artifacts");
    let leaderboard = text
        .find("make -C benchmarks leaderboard SCANNERS=keyhog,trufflehog OUT=results-nightly")
        .expect("bench-nightly must write the exact scanner set to isolated nightly results");
    let run_set = text
        .find("name: Declare exact nightly report run set")
        .expect("bench-nightly must declare the exact fresh-run identities before rendering");
    let report = text
        .find("python3 -m bench report --results results-nightly --reports reports")
        .expect("bench-nightly must render its isolated explicit fresh-run inventory");
    let validate = text
        .find("name: Validate benchmark artifacts")
        .expect("bench-nightly must validate result and report contents before upload");
    let upload = text
        .find("uses: actions/upload-artifact@")
        .expect("bench-nightly must upload generated artifacts");
    assert!(
        clean < leaderboard
            && leaderboard < run_set
            && run_set < report
            && report < validate
            && validate < upload,
        "bench-nightly must clean stale artifacts, measure, declare exact run identities, render, \
         and validate non-empty output before uploading"
    );
    assert!(
        text.contains("RunResult.from_json")
            && text.contains("row.finding_count <= 0")
            && text.contains("not path.read_text().strip()"),
        "bench-nightly publication guard must reject invalid/empty results and reports"
    );
    assert!(
        text.contains(r#"expected = {"keyhog", "trufflehog"}"#)
            && text.contains("observed != expected")
            && text.contains("row.scanner.executable_sha256")
            && text.contains("row.host.hostname_hash")
            && text.contains("benchmarks/nightly-run-set.toml"),
        "bench-nightly must fail closed unless its exact scanner inventory and provenance-bound \
         run set are complete, then publish that declaration with the results"
    );
    assert!(
        text.contains("mirror-keyhog-simd-nocache-nodaemon-full.json")
            && text.contains("mirror-trufflehog-default-nocache-nodaemon-no-verify.json")
            && text.contains("observed_files != set(files)")
            && text.contains("--run-set nightly-run-set.toml")
            && !text.contains(" --inject"),
        "nightly reporting must resolve deterministic expected paths through its explicit run set, \
         never a glob/newest fallback, and must not inject ad-hoc results into the README"
    );
    assert!(
        text.contains("if-no-files-found: error"),
        "bench-nightly upload-artifact must set if-no-files-found: error"
    );
    assert!(
        !text.contains("if: always()"),
        "bench-nightly must never publish artifacts from a failed benchmark job"
    );
}

/// KH-GAP-081 also applies to the differential nightly: it executes KeyHog on
/// the same GPU-less hosted runner. This test locks the whole publication chain
/// to the strict production targets and canonical baseline inventory.
#[test]
fn differential_bench_is_cpu_truthful_canonical_and_fail_closed() {
    let text = read_workflow("differential-bench.yml");

    assert!(text.contains("runs-on: ubuntu-latest"));
    assert!(
        text.contains("--no-default-features --features ci-lean"),
        "differential-bench must explicitly compile the CPU-only ci-lean scanner"
    );
    assert!(
        text.contains("python3 -m pip install -r benchmarks/requirements.txt"),
        "differential-bench must install the complete pinned benchmark requirements"
    );

    let clean = text
        .find("rm -rf benchmarks/results")
        .expect("differential-bench must remove stale generated results");
    let leaderboard = text
        .find("make -C benchmarks leaderboard SCANNERS=keyhog,betterleaks,kingfisher")
        .expect("differential-bench must use the strict production leaderboard target");
    let gate = text
        .find("make -C benchmarks gate")
        .expect("differential-bench must use the production gate target");
    let validate = text
        .find("name: validate differential artifacts")
        .expect("differential-bench must validate artifacts before publication");
    let upload = text
        .find("uses: actions/upload-artifact@")
        .expect("differential-bench must have an artifact upload");
    assert!(
        clean < leaderboard && leaderboard < gate && gate < validate && validate < upload,
        "differential-bench must clean, strictly measure, gate, and validate before upload"
    );
    assert!(
        text.contains("BASELINE=baselines")
            && !text.contains("--baseline baselines/")
            && !text.contains("BASELINE=baselines/"),
        "the gate must resolve the mirror baseline through baselines/canonical.toml"
    );
    assert!(
        text.contains("RunResult.from_json")
            && text.contains("row.finding_count <= 0")
            && text.contains("if: success()")
            && text.contains("if-no-files-found: error"),
        "differential upload must reject invalid/empty rows and run only after success"
    );
    assert!(
        !text.contains("if: always()"),
        "differential-bench must never publish failed or partial benchmark results"
    );
}
