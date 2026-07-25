#[test]
fn gpu_moe_degrades_keep_continuous_structured_telemetry() {
    let diagnostics = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gpu/backend/diagnostics.rs"
    ))
    .expect("read GPU diagnostics source");
    let runtime = diagnostics
        .split("fn moe_runtime_degrade(")
        .nth(1)
        .and_then(|tail| tail.split("fn moe_nonfinite_degrade(").next())
        .expect("runtime degrade function extractable");
    let nonfinite = diagnostics
        .split("fn moe_nonfinite_degrade(")
        .nth(1)
        .and_then(|tail| tail.split("fn moe_numeric_divergence_degrade(").next())
        .expect("nonfinite degrade function extractable");

    assert!(
        diagnostics.contains("static MOE_RUNTIME_DEGRADE_WARNED: AtomicBool")
            && diagnostics.contains("static MOE_NONFINITE_WARNED: AtomicBool"),
        "GPU MoE warning latches must be AtomicBool, not OnceLock test-polluting one-shots"
    );
    assert!(
        !diagnostics.contains("static MOE_RUNTIME_DEGRADE_WARNED: OnceLock")
            && !diagnostics.contains("static MOE_NONFINITE_WARNED: OnceLock"),
        "GPU MoE degrade warning latches must not use OnceLock"
    );
    assert!(
        runtime.contains("tracing::warn!") && runtime.contains("MOE_RUNTIME_DEGRADE_WARNED.swap"),
        "runtime GPU MoE degrade must trace every event while rate-limiting only stderr"
    );
    assert!(
        nonfinite.contains("tracing::error!") && nonfinite.contains("MOE_NONFINITE_WARNED.swap"),
        "non-finite GPU MoE scores must trace every correctness fault while rate-limiting only stderr"
    );
}

#[test]
fn gpu_moe_numeric_parity_probe_is_one_shot_not_per_batch_diag() {
    let gpu = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu.rs"))
        .expect("read GPU facade source");
    let execution = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gpu/backend/execution.rs"
    ))
    .expect("read GPU execution source");
    let diagnostics = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gpu/backend/diagnostics.rs"
    ))
    .expect("read GPU diagnostics source");
    let batch_score = execution
        .split("pub(crate) fn batch_score_features(")
        .nth(1)
        .and_then(|tail| tail.split("fn dispatch_moe_batch(").next())
        .expect("batch_score_features body extractable");

    assert!(
        execution.contains("static MOE_NUMERIC_TRUST: OnceLock<Result<bool, GpuBackendError>>")
            && execution.contains("fn gpu_moe_numerically_trustworthy(")
            && execution.contains("fn gpu_moe_parity_probe_features(")
            && batch_score.contains("gpu_moe_numerically_trustworthy(readback_timeout)"),
        "GPU MoE dispatch must run a typed, one-shot CPU/GPU parity probe before trusting shader scores"
    );
    assert!(
        !gpu.contains("TEMP-DIAG GPU vs CPU MoE divergence scope")
            && !gpu.contains("let cpu = score_features_on_cpu();"),
        "GPU MoE parity diagnostics must not recompute CPU scores inside every production GPU batch"
    );
    assert!(
        diagnostics.contains("fn moe_numeric_divergence_degrade(")
            && diagnostics.contains("Refusing to silently score confidence on the CPU MoE")
            && diagnostics.contains("GPU MoE parity probe diverged from CPU MoE"),
        "GPU MoE numeric divergence must be operator-visible and hard-fail under --require-gpu"
    );
}
