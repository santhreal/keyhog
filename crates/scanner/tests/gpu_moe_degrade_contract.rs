#[test]
fn gpu_moe_degrades_keep_continuous_structured_telemetry() {
    let backend =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/backend.rs"))
            .expect("read gpu backend source");
    let runtime = backend
        .split("fn moe_runtime_degrade(")
        .nth(1)
        .and_then(|tail| tail.split("fn moe_nonfinite_degrade(").next())
        .expect("runtime degrade function extractable");
    let nonfinite = backend
        .split("fn moe_nonfinite_degrade(")
        .nth(1)
        .and_then(|tail| tail.split("pub(crate) fn batch_score_features(").next())
        .expect("nonfinite degrade function extractable");

    assert!(
        backend.contains("static MOE_RUNTIME_DEGRADE_WARNED: AtomicBool")
            && backend.contains("static MOE_NONFINITE_WARNED: AtomicBool"),
        "GPU MoE warning latches must be AtomicBool, not OnceLock test-polluting one-shots"
    );
    assert!(
        !backend.contains("static MOE_RUNTIME_DEGRADE_WARNED: OnceLock")
            && !backend.contains("static MOE_NONFINITE_WARNED: OnceLock"),
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
