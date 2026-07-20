use keyhog::testing::{CliTestApi as _, API};

#[test]
fn doctor_shadow_check_keeps_original_path_when_canonicalize_fails() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let missing = dir.path().join("missing").join("keyhog");

    assert_eq!(
        API.doctor_canonicalize_for_shadow_check(missing.clone()),
        missing,
        "doctor PATH-shadow diagnostics must keep the original path when canonicalization fails"
    );
}

#[test]
fn doctor_running_binary_shadow_check_does_not_drop_canonicalize_failures() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/doctor.rs"
    ));

    assert!(
        source.contains(".map(canonicalize_for_shadow_check)")
            && !source.contains(".and_then(|p| std::fs::canonicalize(&p).ok())"),
        "doctor must not convert a current_exe canonicalization failure into None and hide PATH shadowing"
    );
}

#[test]
fn doctor_gpu_self_test_failure_is_unhealthy() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/doctor.rs"
    ));
    let gpu_branch = source
        .split("let region_presence = keyhog_scanner::gpu::gpu_region_presence_self_test();")
        .nth(1)
        .and_then(|tail| {
            tail.split("match keyhog_scanner::gpu::vyre_gpu_self_test()")
                .next()
        })
        .expect("gpu self-test branch extractable");

    assert!(
        gpu_branch.contains("healthy = false")
            && gpu_branch.contains("style::fail(\"FAIL\"")
            && gpu_branch.contains("GPU routes are unavailable until fixed")
            && gpu_branch.contains("auto scans fail closed rather than silently route to CPU/SIMD")
            && !gpu_branch.contains("warned = true")
            && !gpu_branch.contains("style::warn(\"WARN\""),
        "doctor must mark a failed GPU scan path unhealthy, not warn-and-pass"
    );
}

#[test]
fn doctor_keeps_direct_literal_diagnostic_nonfatal() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/doctor.rs"
    ));
    let gpu_branch = source
        .split("match keyhog_scanner::gpu::vyre_gpu_self_test()")
        .nth(1)
        .and_then(|tail| {
            tail.split("match keyhog_scanner::gpu::gpu_self_test()")
                .next()
        })
        .expect("gpu literal self-test branch extractable");

    assert!(
        gpu_branch.contains("_vyre_match_leader")
            && gpu_branch.contains("canonical pre-emit lowering")
            && gpu_branch.contains("subgroup_ballot")
            && gpu_branch.matches("warned = true").count() >= 2
            && gpu_branch.contains("style::warn(\"WARN\"")
            && gpu_branch.contains("production region-presence path is checked separately")
            && gpu_branch.contains("production scan eligibility is determined by the region-presence probe above")
            && !gpu_branch.contains("healthy = false")
            && !gpu_branch.contains("style::fail(\"FAIL\""),
        "the direct VYRE diagnostic must remain visible but nonfatal; production region presence owns scan eligibility"
    );
}

#[test]
fn doctor_runs_gpu_moe_self_test_and_surfaces_parity_degrade_as_warning() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/doctor.rs"
    ));
    let gpu_branch = source
        .split("match keyhog_scanner::gpu::gpu_self_test()")
        .nth(1)
        .and_then(|tail| tail.split("// \u{2500}\u{2500} Summary").next())
        .expect("gpu MoE self-test branch extractable");

    assert!(
        gpu_branch.contains("diverges from the CPU MoE reference")
            && gpu_branch.contains("warned = true")
            && gpu_branch.contains("style::warn(\"WARN\"")
            && gpu_branch.contains("GPU ML acceleration is disabled")
            && gpu_branch.contains("healthy = false")
            && gpu_branch.contains("style::fail(\"FAIL\""),
        "doctor must run the MoE GPU self-test, warn on parity-gated ML acceleration, and fail on dispatch/unavailable errors"
    );
}
