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
        .split("match keyhog_scanner::gpu::vyre_ac_kernel_self_test()")
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
fn doctor_runs_gpu_literal_self_test_and_aligns_known_lowering_with_backend() {
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
            && gpu_branch.contains("warned = true")
            && gpu_branch.contains("style::warn(\"WARN\"")
            && gpu_branch.contains("scans use the AC kernel path")
            && gpu_branch.contains("healthy = false")
            && gpu_branch.contains("style::fail(\"FAIL\"")
            && gpu_branch.contains("GPU routes are unavailable until fixed"),
        "doctor must run the literal-set GPU self-test, warn for the known vyre lowering gap, and fail hard on unknown literal-set GPU faults"
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
