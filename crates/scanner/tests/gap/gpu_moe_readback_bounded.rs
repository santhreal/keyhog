//! PERF-02: GPU MoE readback must never park a scan worker forever.

#[test]
fn gpu_moe_readback_uses_bounded_polling() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/backend.rs");
    let src = std::fs::read_to_string(path).expect("source readable");

    assert!(
        src.contains("DEFAULT_GPU_MOE_TIMEOUT_MS"),
        "GPU MoE readback must have a bounded default timeout"
    );
    assert!(
        src.contains("KEYHOG_GPU_MOE_TIMEOUT_MS"),
        "GPU MoE readback timeout must be operator-tunable"
    );
    assert!(
        src.contains("wgpu::PollType::Poll"),
        "GPU MoE readback must poll with a deadline instead of blocking wait"
    );
    assert!(
        src.contains("TryRecvError::Empty"),
        "GPU MoE readback must use nonblocking channel checks inside the deadline loop"
    );
    assert!(
        !src.contains("wgpu::PollType::Wait"),
        "GPU MoE readback must not use unbounded device.poll(Wait)"
    );
    assert!(
        !src.contains("receiver.recv()"),
        "GPU MoE readback must not use unbounded receiver.recv()"
    );
}
