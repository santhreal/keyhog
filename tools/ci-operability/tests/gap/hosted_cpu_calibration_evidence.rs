use super::support::read_workflow;

const UPLOAD_ARTIFACT: &str =
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";

fn step_block<'a>(workflow: &'a str, name: &str) -> &'a str {
    let marker = format!("      - name: {name}");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("workflow is missing step {name:?}"));
    let after_marker = start + marker.len();
    let end = workflow[after_marker..]
        .find("\n      - name: ")
        .map_or(workflow.len(), |offset| after_marker + offset);
    &workflow[start..end]
}

fn step_names(workflow: &str) -> Vec<&str> {
    workflow
        .lines()
        .filter_map(|line| line.strip_prefix("      - name: "))
        .collect()
}

fn upload_paths(step: &str) -> Vec<&str> {
    let mut lines = step.lines();
    lines
        .find(|line| line.trim() == "path: |")
        .expect("upload step must use a literal path block");
    lines
        .take_while(|line| line.starts_with("            "))
        .map(str::trim)
        .collect()
}

fn assert_contiguous(names: &[&str], expected: &[&str]) {
    assert!(
        names.windows(expected.len()).any(|window| window == expected),
        "expected contiguous workflow steps {expected:?}, got {names:?}"
    );
}

/// GitHub rejects workflow dispatch when either the workflow-level or
/// job-level `env` evaluates the runner context. Export temporary paths from a
/// step after runner assignment so calibration reaches execution.
#[test]
fn runner_temp_paths_are_exported_at_step_runtime_accepted_by_github_dispatch() {
    for (workflow_name, setup_name) in [
        ("bench-nightly.yml", "Configure hosted temporary paths"),
        (
            "differential-bench.yml",
            "configure hosted temporary paths",
        ),
    ] {
        let workflow = read_workflow(workflow_name);
        assert!(
            !workflow.contains("${{ runner.temp }}"),
            "{workflow_name} cannot evaluate the runner context in workflow YAML"
        );
        let setup = step_block(&workflow, setup_name);
        for contract in [
            "KEYHOG_BENCH_SOURCE_ROOT=$RUNNER_TEMP/keyhog-bench-sources",
            "KEYHOG_BENCH_SNAPSHOT_ROOT=$RUNNER_TEMP/keyhog-bench-snapshots",
            "KEYHOG_BENCH_MIRROR=$RUNNER_TEMP/keyhog-bench-sources/mirror",
            ">> \"$GITHUB_ENV\"",
        ] {
            assert!(
                setup.contains(contract),
                "{workflow_name} temporary-path setup is missing {contract:?}"
            );
        }
    }
}

#[test]
fn dispatch_calibration_runs_immediately_after_raw_generation_and_before_hosted_gate() {
    let nightly = read_workflow("bench-nightly.yml");
    assert_contiguous(
        &step_names(&nightly),
        &[
            "Render leaderboard + per-detector reports",
            "Validate untrusted nightly calibration evidence",
            "Upload untrusted nightly calibration evidence",
            "Validate benchmark artifacts",
        ],
    );

    let differential = read_workflow("differential-bench.yml");
    assert_contiguous(
        &step_names(&differential),
        &[
            "run leaderboard (keyhog + required competitors)",
            "validate untrusted differential calibration evidence",
            "upload untrusted differential calibration evidence",
            "differential + regression gate (keyhog must lead and not regress)",
            "validate differential artifacts",
        ],
    );

    for step in [
        step_block(&nightly, "Validate untrusted nightly calibration evidence"),
        step_block(&nightly, "Upload untrusted nightly calibration evidence"),
        step_block(
            &differential,
            "validate untrusted differential calibration evidence",
        ),
        step_block(
            &differential,
            "upload untrusted differential calibration evidence",
        ),
    ] {
        assert!(step.contains("if: github.event_name == 'workflow_dispatch'"));
        assert!(!step.contains("if: success()"));
    }
}

#[test]
fn calibration_uploads_bind_untrusted_run_identity_and_exact_inventory() {
    let nightly = read_workflow("bench-nightly.yml");
    let nightly_upload = step_block(&nightly, "Upload untrusted nightly calibration evidence");
    assert!(nightly_upload.contains(&format!("uses: {UPLOAD_ARTIFACT}")));
    assert!(nightly_upload.contains(
        "name: untrusted-calibration-evidence-github-ubuntu-24.04-4core-nightly-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}"
    ));
    assert_eq!(
        upload_paths(nightly_upload),
        [
            "benchmarks/results-nightly/mirror-keyhog-simd-nocache-nodaemon-full.json",
            "benchmarks/results-nightly/mirror-trufflehog-default-nocache-nodaemon-no-verify.json",
            "benchmarks/results-creddata/creddata-keyhog-simd-nocache-nodaemon-full.json",
            "benchmarks/results-ioc-recovery/ioc-recovery-keyhog-simd-nocache-nodaemon-fast.json",
            "benchmarks/results-ioc-recovery/ioc-recovery-keyhog-simd-nocache-nodaemon-full.json",
            "benchmarks/results-ioc-recovery/ioc-recovery-keyhog-simd-nocache-nodaemon-deep.json",
            "benchmarks/results-ioc-recovery/ioc-recovery-keyhog-simd-nocache-nodaemon-precision.json",
            "benchmarks/hosted-cpu-context.json",
            "benchmarks/hosted-cpu-supply.json",
            "benchmarks/hosted-cpu-immutability.json",
            "benchmarks/unicode-parity.json",
        ]
    );

    let differential = read_workflow("differential-bench.yml");
    let differential_upload = step_block(
        &differential,
        "upload untrusted differential calibration evidence",
    );
    assert!(differential_upload.contains(&format!("uses: {UPLOAD_ARTIFACT}")));
    assert!(differential_upload.contains(
        "name: untrusted-calibration-evidence-github-ubuntu-24.04-4core-differential-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}"
    ));
    assert_eq!(
        upload_paths(differential_upload),
        [
            "benchmarks/results/mirror-keyhog-simd-nocache-nodaemon-full.json",
            "benchmarks/results/mirror-betterleaks-default-nocache-nodaemon-no-validate.json",
            "benchmarks/results/mirror-kingfisher-default-nocache-nodaemon-low-no-validate.json",
            "benchmarks/hosted-cpu-context.json",
            "benchmarks/hosted-cpu-supply.json",
            "benchmarks/hosted-cpu-immutability.json",
            "benchmarks/unicode-parity.json",
        ]
    );

    for upload in [nightly_upload, differential_upload] {
        assert!(upload.contains("if-no-files-found: error"));
        assert!(!upload.contains('*'), "calibration inventory must not use globs");
        assert!(!upload.contains("KEYHOG_BENCH_SOURCE_ROOT"));
        assert!(!upload.contains("KEYHOG_BENCH_SNAPSHOT_ROOT"));
        assert!(!upload.contains("benchmarks/corpora/"));
        assert!(!upload.contains("cpu-gates/"));
        assert!(!upload.contains("credentials"));
    }
}

#[test]
fn calibration_validation_parses_regular_files_and_run_identity_without_a_verdict() {
    let nightly = read_workflow("bench-nightly.yml");
    let differential = read_workflow("differential-bench.yml");
    for (workflow, validation_name, profile) in [
        (
            nightly.as_str(),
            "Validate untrusted nightly calibration evidence",
            "github-ubuntu-24.04-4core-nightly",
        ),
        (
            differential.as_str(),
            "validate untrusted differential calibration evidence",
            "github-ubuntu-24.04-4core-differential",
        ),
    ] {
        let validation = step_block(workflow, validation_name);
        for contract in [
            "observed_results != expected_results",
            "stat.S_ISREG(path.lstat().st_mode)",
            "parse_constant=reject_json_constant",
            "RunResult.from_json",
            "row.hosted_binding.to_json() != expected_binding",
            "hashlib.sha256(",
            "hosted-cpu-context.json",
            "hosted-cpu-supply.json",
            "hosted-cpu-immutability.json",
            "unicode-parity.json",
            "context.get(\"supply\") != supply",
            "context.get(\"immutability\") != immutability",
            "os.environ[\"GITHUB_SHA\"]",
            "os.environ[\"GITHUB_REPOSITORY\"]",
            "os.environ[\"GITHUB_WORKFLOW_REF\"]",
            "os.environ[\"GITHUB_WORKFLOW_SHA\"]",
            "os.environ[\"GITHUB_RUN_ID\"]",
            "os.environ[\"GITHUB_RUN_ATTEMPT\"]",
            "os.environ[\"GITHUB_JOB\"]",
        ] {
            assert!(
                validation.contains(contract),
                "{validation_name} is missing {contract:?}"
            );
        }
        assert!(validation.contains(profile));
        assert!(!validation.contains("hosted_cpu_gate gate"));
        assert!(!validation.contains("--policy"));
        assert!(!validation.contains("min_recall"));
        assert!(!validation.contains("max_wall"));
    }
}

#[test]
fn authoritative_hosted_gate_still_controls_the_unchanged_success_publication() {
    let nightly = read_workflow("bench-nightly.yml");
    let nightly_calibration = nightly
        .find("name: Upload untrusted nightly calibration evidence")
        .unwrap();
    let nightly_gate = nightly.find("python3 -B -m bench.hosted_cpu_gate gate").unwrap();
    let nightly_publication = nightly.find("name: Upload benchmark results and reports").unwrap();
    assert!(nightly_calibration < nightly_gate && nightly_gate < nightly_publication);
    let nightly_publication_step = step_block(&nightly, "Upload benchmark results and reports");
    assert!(nightly_publication_step.contains("name: bench-unified-results"));
    assert!(!nightly_publication_step.contains("if: always()"));
    assert!(nightly.contains(
        "--policy-sha256 93dfa46fde14b47d85497297633cdfce38713644dadc4557ea3bd03042aee205"
    ));

    let differential = read_workflow("differential-bench.yml");
    let differential_calibration = differential
        .find("name: upload untrusted differential calibration evidence")
        .unwrap();
    let differential_gate = differential
        .find("python3 -B -m bench.hosted_cpu_gate gate")
        .unwrap();
    let differential_publication = differential.find("name: upload results artifact").unwrap();
    assert!(
        differential_calibration < differential_gate
            && differential_gate < differential_publication
    );
    let differential_publication_step = step_block(&differential, "upload results artifact");
    assert!(differential_publication_step.contains("if: success()"));
    assert!(differential_publication_step.contains(
        "name: differential-results-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.sha }}"
    ));
    assert!(differential.contains(
        "--policy-sha256 563fb8f51ca496ec294436276366c07ef0432148ad5899ee5aded3ede38cfc89"
    ));
}
