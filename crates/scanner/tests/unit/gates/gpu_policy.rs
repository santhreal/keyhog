#[test]
fn gpu_probe_honors_disabled_policy_before_adapter_identity() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/policy.rs"));
    let fn_start = src
        .find("pub(crate) fn gpu_probe() -> GpuRuntimeProbe")
        .expect("gpu_probe owner present");
    let body = &src[fn_start..];
    let policy_gate = body
        .find("gpu_disabled_by_policy()")
        .expect("gpu_probe checks resolved GPU runtime policy");
    let adapter_probe = body
        .find("super::gpu_adapter_probe()")
        .expect("gpu_probe owns adapter identity collection");

    assert!(
        policy_gate < adapter_probe,
        "gpu_probe must return an empty receipt for --no-gpu before probing adapter identity"
    );
}
