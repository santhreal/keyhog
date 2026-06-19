//! PERF-02: GPU MoE readback must never park a scan worker forever.

#[test]
fn gpu_moe_readback_uses_bounded_polling() {
    let backend_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/backend.rs");
    let backend = std::fs::read_to_string(backend_path).expect("backend source readable");
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
        backend.contains("readback_timeout: Duration")
            && backend.contains("let timeout = readback_timeout")
            && !backend.contains("KEYHOG_GPU_MOE_TIMEOUT_MS")
            && !backend.contains("u64_at_least_or_default"),
        "GPU MoE backend must consume caller-provided timeout, not ambient env"
    );
    assert!(
        backend.contains("wgpu::PollType::Poll"),
        "GPU MoE readback must poll with a deadline instead of blocking wait"
    );
    assert!(
        backend.contains("TryRecvError::Empty"),
        "GPU MoE readback must use nonblocking channel checks inside the deadline loop"
    );
    assert!(
        !backend.contains("wgpu::PollType::Wait"),
        "GPU MoE readback must not use unbounded device.poll(Wait)"
    );
    assert!(
        !backend.contains("receiver.recv()"),
        "GPU MoE readback must not use unbounded receiver.recv()"
    );
}
