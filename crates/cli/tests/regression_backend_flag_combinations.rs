//! WHY: CLI backend override and GPU policy flag matrix total contract (Row 98):
//! Every combination of --backend and GPU policy flags (--no-gpu, --require-gpu) must be
//! either strictly honored or rejected at argument parsing time with a named error.
//! No contradictory combination may be silently accepted and ignored, and platform-impossible
//! backends (e.g. gpu-metal on Linux/Windows) must be rejected before scanning begins.
//!
//! WHAT IT DOES NOT CATCH:
//! GPU driver crashes inside external closed-source proprietary kernel modules.

use keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES;

#[test]
fn all_backend_override_values_enumerated_at_runtime() {
    assert!(
        !BACKEND_OVERRIDE_VALUES.is_empty(),
        "backend override values must be available from scanner hw_probe"
    );
    for &backend in &BACKEND_OVERRIDE_VALUES {
        assert!(!backend.is_empty(), "backend label must not be empty");
    }
}

#[test]
fn no_gpu_with_gpu_backend_is_rejected_at_parse_time() {
    let gpu_backends: Vec<&str> = BACKEND_OVERRIDE_VALUES
        .iter()
        .copied()
        .filter(|&backend| backend.starts_with("gpu"))
        .collect();
    assert!(!gpu_backends.is_empty());

    for &backend in &gpu_backends {
        let args = ["keyhog", "scan", "--backend", backend, "--no-gpu", "."];
        let result = keyhog::args::try_parse_from(args);
        assert!(
            result.is_err(),
            "--backend {} with --no-gpu must be rejected at parse time",
            backend
        );
        let err = result.err().expect("must be error").to_string();
        assert!(
            err.contains("--no-gpu") && err.contains("--backend"),
            "error must name both conflicting flags: got: {}",
            err
        );
    }
}

#[test]
fn no_gpu_with_cpu_backends_is_accepted_at_parse_time() {
    let non_gpu_backends = ["cpu", "simd-regex", "auto"];

    for &backend in &non_gpu_backends {
        let args = ["keyhog", "scan", "--backend", backend, "--no-gpu", "."];
        let result = keyhog::args::try_parse_from(args);
        assert!(
            result.is_ok(),
            "--backend {} with --no-gpu should parse successfully: {:?}",
            backend,
            result.err()
        );
    }
}
#[test]
fn no_gpu_with_require_gpu_is_rejected_at_parse_time() {
    let args = ["keyhog", "scan", "--no-gpu", "--require-gpu", "."];
    let result = keyhog::args::try_parse_from(args);
    assert!(
        result.is_err(),
        "--no-gpu with --require-gpu must be rejected at parse time"
    );
    let err = result.err().expect("must be error").to_string();
    assert!(
        err.contains("--no-gpu") && err.contains("--require-gpu"),
        "error must name both conflicting flags: got: {}",
        err
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn metal_backend_on_non_macos_is_rejected_before_scan() {
    for &backend in &["gpu-metal", "gpu-metal-region-presence"] {
        let args = ["keyhog", "scan", "--backend", backend, "."];
        let result = keyhog::args::try_parse_from(args);
        assert!(
            result.is_err(),
            "--backend {} on non-macOS must be rejected at parse",
            backend
        );
        let err = result.err().expect("must be error").to_string();
        assert!(
            err.contains("only supported on macOS"),
            "error must state that metal is only supported on macOS: got: {}",
            err
        );
    }
}
#[test]
fn require_gpu_with_auto_and_gpu_backends_is_accepted_at_parse_time() {
    let accepted_backends = ["auto", "gpu-wgpu", "gpu-wgpu-region-presence"];
    for &backend in &accepted_backends {
        let args = ["keyhog", "scan", "--backend", backend, "--require-gpu", "."];
        let result = keyhog::args::try_parse_from(args);
        assert!(
            result.is_ok(),
            "--backend {} with --require-gpu should parse successfully: {:?}",
            backend,
            result.err()
        );
    }
}

#[test]
fn require_gpu_with_no_gpu_is_rejected_at_parse_time() {
    let args = ["keyhog", "scan", "--require-gpu", "--no-gpu", "."];
    let result = keyhog::args::try_parse_from(args);
    assert!(
        result.is_err(),
        "--require-gpu with --no-gpu must be rejected at parse time"
    );
    let err = result.err().expect("must be error").to_string();
    assert!(
        err.contains("--no-gpu") && err.contains("--require-gpu"),
        "error must name both conflicting flags: got: {}",
        err
    );
}

#[test]
fn require_gpu_with_non_gpu_backend_is_rejected_at_parse_time() {
    for &backend in &["cpu", "simd-regex"] {
        let args = ["keyhog", "scan", "--backend", backend, "--require-gpu", "."];
        let result = keyhog::args::try_parse_from(args);
        assert!(
            result.is_err(),
            "--backend {} with --require-gpu must be rejected at parse time",
            backend
        );
        let err = result.err().expect("must be error").to_string();
        assert!(
            err.contains("--require-gpu") && err.contains("--backend"),
            "error must name both conflicting flags: got: {}",
            err
        );
    }
}
