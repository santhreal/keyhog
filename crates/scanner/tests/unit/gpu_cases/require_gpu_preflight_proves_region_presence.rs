#[test]
fn require_gpu_preflight_proves_production_region_presence() {
    let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/policy.rs"));
    let preflight = source
        .split("pub fn require_gpu_preflight() -> Result<(), String> {")
        .nth(1)
        .and_then(|tail| tail.split("pub(crate) fn gpu_disabled_by_policy()").next())
        .expect("require_gpu_preflight source extractable");

    assert!(
        preflight.contains("super::gpu_region_presence_self_test()")
            && !preflight.contains("super::gpu_self_test()")
            && preflight.contains("production GPU peer set")
            && preflight.contains("refusing to run on CPU"),
        "--require-gpu preflight must fail closed unless every acquired production GPU peer passes region-presence parity"
    );
}
