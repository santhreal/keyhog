use super::support::repo_root;

fn glibc_dockerfile() -> String {
    std::fs::read_to_string(repo_root().join("tests/docker/Dockerfile.glibc"))
        .expect("glibc Docker integration definition readable")
}

/// Prevents hosted-runner timing jitter from making the glibc integration image
/// intermittently uncalibrated while retaining real scan and parity probes.
#[test]
fn glibc_autoroute_calibration_uses_the_authorized_ci_timing_fixture() {
    let dockerfile = glibc_dockerfile();
    assert!(
        dockerfile.contains("--no-default-features --features ci-lean"),
        "the timing fixture is compiled only into the documented ci-lean build"
    );

    let fixture = dockerfile
        .find("RUN export KEYHOG_CI_AUTOROUTE_TIMING_FIXTURE=confidence-separated-v1")
        .expect("the glibc calibration layer selects deterministic confidence-separated timings");
    let authorization = dockerfile
        .find("KEYHOG_CI_AUTOROUTE_FIXTURE_AUTH=bench-backend-parity-v1")
        .expect("the test-only timing fixture carries its explicit authorization token");
    let calibration = dockerfile
        .find("keyhog scan --autoroute-calibrate --autoroute-gpu")
        .expect("the image still runs the production autoroute calibration command");

    assert!(fixture < authorization && authorization < calibration);
    assert!(
        !dockerfile.contains("ENV KEYHOG_CI_AUTOROUTE"),
        "test timing controls must remain scoped to the calibration RUN layer"
    );
}

/// Locks out a fake green Docker build that suppresses an inconclusive or
/// parity-failing calibration instead of rejecting the image.
#[test]
fn glibc_autoroute_calibration_still_fails_on_nonzero_probe_status() {
    let dockerfile = glibc_dockerfile();
    let failure_branch = if let Some(pos) = dockerfile.find("case \"$rc\" in") {
        let tail = &dockerfile[pos..];
        let arm_start = tail.find("*)").expect("case statement must have default failure arm");
        let arm_end = tail.find("esac").expect("case statement must terminate with esac");
        &tail[arm_start..arm_end]
    } else if let Some(pos) = dockerfile.find("if [ \"$rc\" != 0 ]; then") {
        let tail = &dockerfile[pos..];
        let end = tail.find("fi").expect("if statement must terminate with fi");
        &tail[..end]
    } else {
        panic!("Dockerfile must contain case \"$rc\" in or if [ \"$rc\" != 0 ]; then");
    };

    assert!(
        failure_branch.contains("autoroute calibration failed (exit $rc)"),
        "failure branch must print calibration error message"
    );
    assert!(
        failure_branch.contains("exit 1"),
        "failure branch must exit 1"
    );
    assert!(
        !dockerfile.contains(
            "--autoroute-calibrate --autoroute-gpu \"$@\" --format json >/dev/null || true"
        )
    );
}
