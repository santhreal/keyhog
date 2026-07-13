#[test]
fn require_gpu_preflight_proves_production_region_presence() {
    let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/policy.rs"));
    let preflight = source
        .split("pub fn require_gpu_preflight() -> Result<(), String> {")
        .nth(1)
        .and_then(|tail| tail.split("pub(crate) fn gpu_disabled_by_policy()").next())
        .expect("require_gpu_preflight source extractable");

    let moe_index = preflight
        .find("super::gpu_self_test()")
        .expect("required-GPU preflight must prove the GPU MoE self-test");
    let region_index = preflight
        .find("super::gpu_region_presence_self_test()")
        .expect("required-GPU preflight must prove the production region-presence path");

    assert!(
        moe_index < region_index
            && preflight.contains("GPU MoE self-test failed")
            && preflight.contains("GPU region-presence self-test failed")
            && preflight.contains("refusing to run on CPU"),
        "--require-gpu preflight must fail closed unless both GPU MoE and production region-presence self-tests pass"
    );
}
