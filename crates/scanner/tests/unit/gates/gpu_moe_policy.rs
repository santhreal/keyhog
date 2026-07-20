#[test]
fn gpu_moe_honors_disabled_policy_before_adapter_probe() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/backend.rs"));
    let fn_start = src
        .find("pub(crate) fn batch_score_features")
        .expect("batch_score_features owner present");
    let body = &src[fn_start..];
    let policy_gate = body
        .find("super::gpu_disabled_by_policy()")
        .expect("GPU MoE backend checks resolved GPU runtime policy");
    let adapter_probe = body
        .find("let gpu = get_gpu()?;")
        .expect("GPU MoE backend still owns adapter access");

    assert!(
        policy_gate < adapter_probe,
        "--no-gpu must return to CPU MoE before get_gpu()/init_gpu can probe a \
         broken adapter stack"
    );
}

#[test]
fn public_gpu_available_uses_the_policy_checked_probe() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu.rs"));
    let fn_start = src
        .find("pub fn gpu_available() -> bool")
        .expect("gpu_available owner present");
    let body = &src[fn_start..];
    assert!(
        body.starts_with("pub fn gpu_available() -> bool {\n    gpu_probe().available\n}"),
        "gpu_available must consume the policy-checked typed GPU probe"
    );
}

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
