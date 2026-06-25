#[test]
fn require_gpu_preflight_proves_production_ac_kernel() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/gpu/policy.rs"
    ));
    let preflight = source
        .split("pub fn require_gpu_preflight() -> Result<(), String> {")
        .nth(1)
        .and_then(|tail| tail.split("pub(crate) fn gpu_disabled_by_policy()").next())
        .expect("require_gpu_preflight source extractable");

    let moe_index = preflight
        .find("super::gpu_self_test()")
        .expect("required-GPU preflight must prove the GPU MoE self-test");
    let ac_index = preflight
        .find("super::vyre_ac_kernel_self_test()")
        .expect("required-GPU preflight must prove the production AC scan kernel");

    assert!(
        moe_index < ac_index
            && preflight.contains("GPU MoE self-test failed")
            && preflight.contains("GPU AC kernel self-test failed")
            && preflight.contains("refusing to run on CPU"),
        "--require-gpu preflight must fail closed before scanning unless both GPU MoE and the production AC scan kernel self-tests pass"
    );
}
