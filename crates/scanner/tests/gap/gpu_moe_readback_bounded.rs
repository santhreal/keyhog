//! PERF-02: GPU MoE readback must never park a scan worker forever.

#[test]
fn gpu_moe_readback_uses_bounded_polling() {
    let execution_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gpu/backend/execution.rs"
    );
    let execution =
        std::fs::read_to_string(execution_path).expect("GPU execution source readable");
    let config_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/scanner_config.rs");
    let config = std::fs::read_to_string(config_path).expect("config source readable");
    let gpu_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu.rs");
    let gpu = std::fs::read_to_string(gpu_path).expect("gpu source readable");

    assert!(
        config.contains("pub gpu_moe_timeout_ms: Option<u64>")
            && config.contains("const GPU_MOE_TIMEOUT_MS_DEFAULT: u64 = 30_000"),
        "GPU MoE readback timeout must be explicit scanner tuning with a bounded compiled default"
    );
    assert!(
        gpu.contains("batch_ml_inference_with_timeout")
            && gpu.contains("GPU_MOE_TIMEOUT_MS_DEFAULT"),
        "public GPU inference must use the compiled default and production scans must pass explicit tuning"
    );
    assert!(
        execution.contains("readback_timeout: Duration")
            && execution.contains("let timeout = readback_timeout")
            && !execution.contains("KEYHOG_GPU_MOE_TIMEOUT_MS")
            && !execution.contains("u64_at_least_or_default"),
        "GPU MoE execution must consume caller-provided timeout, not ambient env"
    );

    let dispatch = execution
        .split_once("fn dispatch_moe_batch(")
        .and_then(|(_, rest)| rest.split_once("\n}\n\n///").map(|(body, _)| body))
        .expect("dispatch_moe_batch body must remain inspectable");
    assert!(
        dispatch.contains("let deadline = Instant::now() + timeout")
            && dispatch.contains("Instant::now() >= deadline")
            && dispatch.contains("wgpu::PollType::Poll")
            && dispatch.contains("TryRecvError::Empty")
            && dispatch.contains(
                "backoff.wait(deadline.saturating_duration_since(Instant::now()))"
            ),
        "GPU MoE readback must nonblockingly poll with caller-owned deadline and bounded backoff"
    );
    assert!(
        !dispatch.contains("wgpu::PollType::Wait")
            && !dispatch.contains("PollType::WaitForSubmissionIndex")
            && !dispatch.contains("receiver.recv()")
            && !dispatch.contains("std::thread::sleep"),
        "GPU MoE dispatch must not use blocking device polling, unbounded receive, or a fixed sleep"
    );

    let checkout = dispatch
        .split_once("let bufs = match bufs {")
        .and_then(|(_, rest)| {
            rest.split_once("// Each checked-out set")
                .map(|(body, _)| body)
        })
        .expect("MoE buffer checkout and bind-group block must remain inspectable");
    assert!(
        checkout.contains("resource: params.as_entire_binding()")
            && dispatch.contains("queue.write_buffer(&bufs.params")
            && dispatch.contains("Each checked-out set owns its params buffer")
            && !dispatch.contains("gpu.params_buf"),
        "a checked-out GPU MoE buffer set must bind and upload its own params buffer so concurrent batches cannot race batch_size"
    );
}
