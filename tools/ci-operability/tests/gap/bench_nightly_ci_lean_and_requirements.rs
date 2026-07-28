//! KH-GAP-081: bench-nightly runs its scanner in a CPU-only build mode on
//! `ubuntu-24.04`; it must not load `libcuda`. The 2026-07-24 run
//! (santhreal/keyhog/actions/runs/30073950405) failed in
//! `test_fused_autoroute_calibration_cache_replay_matches_simd` because the
//! release binary was built with the default feature set; the benchmark `auto`
//! backend then triggered a cudarc panic on the accelerator-disabled runner:
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

use super::support::{read_workflow, repo_root};

#[test]
fn bench_nightly_is_ci_lean_and_rejects_empty_or_stale_artifacts() {
    let text = read_workflow("bench-nightly.yml");

    assert!(
        text.contains("runs-on: ubuntu-24.04") && !text.contains("runs-on: ubuntu-latest"),
        "bench-nightly must pin the hosted CPU image instead of following *-latest"
    );
    assert!(
        text.contains("uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8")
            && text.contains("toolchain: 1.89.0")
            && !text.contains("toolchain: stable")
            && !text.contains("toolchain: nightly"),
        "bench-nightly must use the immutable Rust 1.89.0 toolchain"
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
        "bench-nightly must build the CPU-only ci-lean binary"
    );
    assert!(
        text.contains("python3 -m pip install --require-hashes --only-binary=:all:")
            && text.contains("-r benchmarks/requirements.txt"),
        "bench-nightly must require hashes for the binary-only benchmark lock"
    );
    assert!(
        text.contains("--require-hashes --only-binary=:all:")
            && text.contains("-r scripts/requirements-marketplace.txt")
            && text.contains("yaml.__version__ == \"6.0.3\""),
        "bench-nightly must install the exact Marketplace verifier parser before source gates"
    );
    assert!(
        text.contains("/sys/fs/cgroup/cpu.max")
            && text.contains("/proc/self/cgroup")
            && text.contains("/proc/self/mountinfo"),
        "bench-nightly must emit actionable CPU-controller evidence when host capture fails"
    );
    assert!(
        text.contains("releases/download/v${version}/trufflehog_${version}_linux_amd64.tar.gz")
            && text.contains("5d836eae522540a32ca0f1a1e00efd4c3153a52462466a4b4008fac1e6c1a548")
            && text.contains("sha256sum --check --strict")
            && !text.contains("raw.githubusercontent.com/trufflesecurity/trufflehog")
            && !text.contains("scripts/install.sh"),
        "bench-nightly must install a versioned, digest-verified TruffleHog release"
    );

    let regression = text
        .find("name: Benchmark regression tests")
        .expect("bench-nightly must run benchmark regression tests");
    let clean = text
        .find("rm -rf benchmarks/results-nightly benchmarks/results-ioc-recovery")
        .expect("bench-nightly must remove its isolated generated artifacts");
    let leaderboard = text
        .find("make -C benchmarks leaderboard SCANNERS=keyhog,trufflehog OUT=results-nightly")
        .expect("bench-nightly must write the exact scanner set to isolated nightly results");
    let run_set = text
        .find("name: Declare exact nightly report run set")
        .expect("bench-nightly must declare exact fresh-run identities");
    let report = text
        .find("--reports reports-nightly --corpus mirror")
        .expect("bench-nightly must render into its fresh isolated report directory");
    let validate = text
        .find("name: Validate benchmark artifacts")
        .expect("bench-nightly must validate artifacts before upload");
    let upload = text
        .find("name: Upload benchmark results and reports")
        .expect("bench-nightly must upload generated artifacts after the gate");
    assert!(
        regression < clean,
        "bench-nightly must test committed benchmark fixtures before cleaning generated artifacts"
    );
    assert!(
        clean < leaderboard
            && leaderboard < run_set
            && run_set < report
            && report < validate
            && validate < upload,
        "bench-nightly must clean, measure, identify, render, validate, then upload"
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
        "bench-nightly must bind the exact scanner inventory and provenance"
    );
    assert!(
        text.contains("mirror-keyhog-simd-nocache-nodaemon-full.json")
            && text.contains("mirror-trufflehog-default-nocache-nodaemon-no-verify.json")
            && text.contains("observed_files != set(files)")
            && text.contains("--run-set nightly-run-set.toml")
            && !text.contains(" --inject"),
        "nightly reporting must use deterministic expected result paths"
    );
    for report in [
        "leaderboard.md",
        "perf.md",
        "recall-gap.md",
        "category-recall.md",
        "static-recovery.md",
        "bloom.md",
    ] {
        assert!(
            text.contains(&format!("benchmarks/reports-nightly/{report}")),
            "nightly upload must explicitly allow {report}"
        );
    }
    assert!(
        text.contains("observed_reports != expected_reports")
            && text.contains("test ! -e benchmarks/reports-nightly")
            && !text.contains("benchmarks/reports-nightly/**")
            && !text.contains("benchmarks/reports/**"),
        "nightly reports must be fresh, exact, and never recursively published"
    );
    assert!(
        text.contains("if-no-files-found: error")
            && text.contains("name: Unmount and remove private benchmark snapshots")
            && text.contains("if: always()"),
        "nightly publication must fail closed while cleanup still runs after failure"
    );
}

/// KH-GAP-081 also applies to the differential nightly: it executes a CPU-only
/// KeyHog build with accelerator dispatch disabled. This test locks the whole
/// publication chain to the strict production targets and baseline inventory.
#[test]
fn differential_bench_is_cpu_truthful_canonical_and_fail_closed() {
    let text = read_workflow("differential-bench.yml");

    assert!(
        text.contains("runs-on: ubuntu-24.04") && !text.contains("runs-on: ubuntu-latest"),
        "differential-bench must pin the hosted CPU image"
    );
    assert!(
        text.contains("uses: dtolnay/rust-toolchain@29eef336d9b2848a0b548edc03f92a220660cdb8")
            && text.contains("toolchain: 1.89.0")
            && !text.contains("toolchain: stable")
            && !text.contains("toolchain: nightly"),
        "differential-bench must use the immutable Rust 1.89.0 toolchain"
    );
    assert!(
        text.contains("name: install exact Rust 1.94.0 competitor toolchain")
            && text.contains("toolchain: 1.94.0"),
        "differential-bench must build pinned Kingfisher with its exact supported Rust toolchain"
    );
    assert!(
        text.contains("name: install exact Go 1.25.10 competitor toolchain")
            && text.contains("go-version: \"1.25.10\""),
        "differential-bench must build pinned Betterleaks with its exact supported Go toolchain"
    );
    assert!(
        text.contains("libboost-dev=1.83.0.1ubuntu2")
            && text.contains("dpkg-query -W -f='${Version}' libboost-dev"),
        "differential-bench must pin and verify Kingfisher's native Boost dependency"
    );
    let context = text
        .find("name: capture current low-core hosted CPU context")
        .expect("differential-bench must capture hosted CPU context");
    let competitors = text
        .find("name: install required competitors")
        .expect("differential-bench must install required competitors");
    assert!(
        context < competitors,
        "differential-bench must reject a mismatched host before the expensive competitor build"
    );
    assert!(
        text.contains("--no-default-features --features ci-lean"),
        "differential-bench must explicitly compile the CPU-only ci-lean scanner"
    );
    assert!(
        text.contains("/sys/fs/cgroup/cpu.max")
            && text.contains("/proc/self/cgroup")
            && text.contains("/proc/self/mountinfo"),
        "differential-bench must emit actionable CPU-controller evidence when host capture fails"
    );
    assert!(
        text.contains("python3 -m pip install --require-hashes --only-binary=:all:")
            && text.contains("-r benchmarks/requirements.txt"),
        "differential-bench must require hashes for the binary-only benchmark lock"
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
        .find("name: upload results artifact")
        .expect("differential-bench must publish its success-only artifact after validation");
    assert!(
        clean < leaderboard && leaderboard < gate && gate < validate && validate < upload,
        "differential-bench must clean, strictly measure, gate, validate, then upload"
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
            && text.contains("if-no-files-found: error")
            && text.contains("name: unmount and remove private benchmark snapshots")
            && text.contains("if: always()"),
        "differential publication must reject failed/empty results and always clean mounts"
    );
}

/// A self-authored context/policy once allowed replay and workload substitution.
/// Lock both hosted workflows to reviewed policy digests, trusted GitHub run
/// inputs, private snapshot roots, and the exact parity binary contract.
#[test]
fn hosted_cpu_workflows_bind_reviewed_policy_run_and_snapshot_identity() {
    let nightly = read_workflow("bench-nightly.yml");
    let differential = read_workflow("differential-bench.yml");

    for (name, text, digest) in [
        (
            "bench-nightly",
            nightly,
            "93dfa46fde14b47d85497297633cdfce38713644dadc4557ea3bd03042aee205",
        ),
        (
            "differential-bench",
            differential,
            "563fb8f51ca496ec294436276366c07ef0432148ad5899ee5aded3ede38cfc89",
        ),
    ] {
        assert!(
            text.contains(&format!("--policy-sha256 {digest}"))
                && text.contains("--trusted-now \"${trusted_now}\"")
                && text.contains("--repository \"${GITHUB_REPOSITORY}\"")
                && text.contains("--workflow-ref \"${GITHUB_WORKFLOW_REF}\"")
                && text.contains("--workflow-sha \"${GITHUB_WORKFLOW_SHA}\"")
                && text.contains("--run-id \"${GITHUB_RUN_ID}\"")
                && text.contains("--run-attempt \"${GITHUB_RUN_ATTEMPT}\"")
                && text.contains("--job \"${GITHUB_JOB}\""),
            "{name} must bind gate authority to reviewed policy and current GitHub run"
        );
        assert!(
            text.contains("--snapshot-root \"${snapshot_root}\"")
                && text.contains("KEYHOG_BENCH_HOSTED_CONTEXT=$GITHUB_WORKSPACE/")
                && text.contains("KEYHOG_BENCH_MIRROR=$RUNNER_TEMP/")
                && text.contains("--policy cpu-gates/")
                && text.contains("--binary "),
            "{name} must scan private context-bound snapshots and bind parity inputs"
        );
    }
}

/// A source root that aliases the destination can make snapshot equality pass
/// by comparing a workload to itself. Require an absent, distinct destination
/// at capture and export only the captured roots to the later scanner steps.
#[test]
fn hosted_cpu_workflows_separate_sources_from_fresh_exported_snapshots() {
    let nightly = read_workflow("bench-nightly.yml");
    let differential = read_workflow("differential-bench.yml");

    for (name, text, scan_marker) in [
        (
            "bench-nightly",
            nightly.as_str(),
            "name: Require exact Unicode CPU/SIMD parity",
        ),
        (
            "differential-bench",
            differential.as_str(),
            "name: require exact Unicode CPU/SIMD parity",
        ),
    ] {
        assert!(
            text.contains("KEYHOG_BENCH_SOURCE_ROOT=$RUNNER_TEMP/keyhog-bench-sources")
                && text.contains(
                    "KEYHOG_BENCH_SNAPSHOT_ROOT=$RUNNER_TEMP/keyhog-bench-snapshots"
                )
                && text.contains(
                    "KEYHOG_BENCH_MIRROR=$RUNNER_TEMP/keyhog-bench-sources/mirror"
                ),
            "{name} must generate the mirror under a dedicated source root"
        );
        assert!(
            text.contains("test ! -e \"${snapshot_root}\"")
                && text.contains("[[ \"${source_root}\" == \"${snapshot_root}\" ]]")
                && text.contains("source and snapshot roots must differ")
                && (text.contains("\"$(realpath \"${snapshot_root}/mirror\")\"")
                    || (text.contains("for workload in mirror creddata ioc-recovery")
                        && text.contains("\"$(realpath \"${snapshot_root}/${workload}\")\"")))
                && text.contains("--snapshot-root \"${snapshot_root}\""),
            "{name} must exclusively create and compare a distinct snapshot destination"
        );

        let capture = text
            .find("bench.hosted_cpu_gate context")
            .expect("hosted workflow must capture context");
        let export = text
            .find("KEYHOG_BENCH_MIRROR=${snapshot_root}/mirror")
            .expect("hosted workflow must export the captured mirror");
        let scan = text
            .find(scan_marker)
            .expect("hosted workflow must scan after capture");
        assert!(
            capture < export && export < scan,
            "{name} must export snapshot roots only after context capture and before scans"
        );
    }

    assert!(
        nightly.contains("KEYHOG_BENCH_CREDDATA=$RUNNER_TEMP/keyhog-bench-sources/creddata")
            && nightly.contains("KEYHOG_BENCH_CREDDATA=${snapshot_root}/creddata")
            && nightly.contains(
                "mv benchmarks/corpora/ioc-recovery-v3 \\\n            \"${KEYHOG_BENCH_SOURCE_ROOT}/ioc-recovery\""
            )
            && nightly.contains(
                "ln -s \"${KEYHOG_BENCH_SOURCE_ROOT}/ioc-recovery\""
            ),
        "nightly must source CredData and recovery outside the snapshot destination"
    );
}

/// chmod-only evidence false-passes when the workflow user owns the tree and
/// can restore write bits. The measurement interval needs a root-owned
/// read-only mount, a rejected write probe, and a guarded post-upload unmount.
#[test]
fn hosted_cpu_workflows_enforce_interval_immutability_with_read_only_mounts() {
    for (name, text, lock_name, upload_name, cleanup_name) in [
        (
            "bench-nightly",
            read_workflow("bench-nightly.yml"),
            "name: Lock captured snapshots read-only for the measurement interval",
            "name: Upload benchmark results and reports",
            "name: Unmount and remove private benchmark snapshots",
        ),
        (
            "differential-bench",
            read_workflow("differential-bench.yml"),
            "name: lock captured snapshots read-only for the measurement interval",
            "name: upload results artifact",
            "name: unmount and remove private benchmark snapshots",
        ),
    ] {
        assert!(
            text.contains("sudo chown -R root:root \"${snapshot_root}\"")
                && text.contains("sudo mount --bind \"${snapshot_root}\" \"${snapshot_root}\"")
                && text.contains("sudo mount -o remount,bind,ro \"${snapshot_root}\"")
                && text.contains("findmnt --mountpoint \"${snapshot_root}\"")
                && text.contains("touch \"${snapshot_root}/.immutability-probe\"")
                && text.contains("\"write_probe\": \"rejected\""),
            "{name} must prove kernel-enforced snapshot immutability, not permissions alone"
        );
        assert!(
            text.contains("if mountpoint -q \"${snapshot_root}\"")
                && text.contains("sudo umount \"${snapshot_root}\"")
                && text.contains("sudo rm -rf --one-file-system \"${snapshot_root}\"")
                && text.contains("if: always()"),
            "{name} must safely unmount and clean the private snapshot"
        );
        let lock = text.find(lock_name).expect("missing snapshot lock step");
        let upload = text
            .find(upload_name)
            .expect("missing evidence upload step");
        let cleanup = text
            .find(cleanup_name)
            .expect("missing snapshot cleanup step");
        assert!(
            lock < upload && upload < cleanup,
            "{name} must hold the read-only mount through publication"
        );
    }
}

/// A version printed to logs is not consumable evidence, and a dev-package pin
/// alone says nothing about the runtime object loaded by KeyHog. Require an
/// uploaded pre-capture receipt with exact tool/package identities and libhs
/// path plus digest.
#[test]
fn hosted_cpu_workflows_capture_pinned_supply_receipts_before_context() {
    for (name, text, go_version) in [
        (
            "bench-nightly",
            read_workflow("bench-nightly.yml"),
            "1.22.2",
        ),
        (
            "differential-bench",
            read_workflow("differential-bench.yml"),
            "1.25.10",
        ),
    ] {
        assert!(
            text.contains("uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97")
                && text.contains("python-version: \"3.12.11\"")
                && text.contains("uses: actions/setup-go@44694675825211faa026b3c33043df3e48a5fa00")
                && text.contains(&format!("go-version: \"{go_version}\"")),
            "{name} must SHA-pin setup actions and exact CPython/Go versions"
        );
        assert!(
            text.contains(&format!("test \"${{go_version}}\" = \"go{go_version}\""))
                && text.contains("go_version=\"${go_version#go}\"")
                && text.contains(&format!(
                    "\"go\": {{\"requested\": \"{go_version}\", \"observed\": go_version}}"
                )),
            "{name} supply receipt must normalize and bind the exact active Go compiler"
        );
        assert!(
            text.contains("libhyperscan-dev=5.4.2-2")
                && text.contains("libhyperscan5=5.4.2-2")
                && text.contains("pkg-config=1.8.1-2build1")
                && text.contains("dpkg-query -W -f='${Version}' libhyperscan5"),
            "{name} must pin and verify exact Hyperscan/pkg-config packages"
        );
        assert!(
            text.contains("test -n \"${ImageOS:-}\" && test -n \"${ImageVersion:-}\"")
                && text.contains("\"schema_version\": \"hosted-cpu-supply-v1\"")
                && text.contains("\"runner_image\":")
                && text.contains("\"libhs_runtime\":")
                && text.contains("\"sha256\": libhs_sha256")
                && text.contains("KEYHOG_BENCH_SUPPLY_RECEIPT=$GITHUB_WORKSPACE/")
                && text.contains("benchmarks/hosted-cpu-supply.json"),
            "{name} must emit consumable runner-image and runtime-libhs evidence"
        );
        let receipt = text
            .find("name: Record pinned hosted CPU supply receipt")
            .or_else(|| text.find("name: record pinned hosted CPU supply receipt"))
            .expect("hosted workflow must record supply receipt");
        let capture = text
            .find("bench.hosted_cpu_gate context")
            .expect("hosted workflow must capture context");
        let scan = text
            .find("bench.unicode_parity")
            .expect("hosted workflow must run parity scan");
        assert!(
            receipt < capture && capture < scan,
            "{name} must create supply evidence before capture and all scans"
        );
    }
}

#[test]
fn benchmark_requirements_are_a_complete_hashed_python_312_linux_lock() {
    let requirements = std::fs::read_to_string(repo_root().join("benchmarks/requirements.txt"))
        .expect("read benchmarks/requirements.txt");

    assert!(
        requirements.contains("--require-hashes")
            && requirements.contains("--only-binary=:all:")
            && requirements.contains("CPython 3.12")
            && requirements.contains("Linux x86_64"),
        "requirements must declare the binary-only Python 3.12/Linux hash lock"
    );
    let expected = [
        "iniconfig==2.0.0",
        "numpy==1.26.4",
        "packaging==24.1",
        "pluggy==1.5.0",
        "pyarrow==16.1.0",
        "pytest==8.2.2",
    ];
    for dependency in expected {
        assert!(
            requirements.contains(dependency),
            "complete lock is missing {dependency}"
        );
    }
    assert_eq!(
        requirements
            .lines()
            .filter(|line| line.contains("=="))
            .count(),
        expected.len(),
        "lock must not contain an undeclared or floating dependency"
    );
    assert_eq!(
        requirements.matches("--hash=sha256:").count(),
        expected.len(),
        "every locked dependency must have one authenticated Linux wheel"
    );
    assert!(
        !requirements.contains(">=")
            && !requirements.contains("~=")
            && !requirements.contains("--trusted-host"),
        "lock must reject floating constraints and index trust bypasses"
    );
}
