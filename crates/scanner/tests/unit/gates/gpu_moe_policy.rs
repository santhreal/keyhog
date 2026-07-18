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
fn public_gpu_available_honors_disabled_policy_before_adapter_probe() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu.rs"));
    let fn_start = src
        .find("pub fn gpu_available() -> bool")
        .expect("gpu_available owner present");
    let body = &src[fn_start..];
    let policy_gate = body
        .find("gpu_disabled_by_policy()")
        .expect("public gpu_available checks resolved GPU runtime policy");
    let adapter_probe = body
        .find("gpu_adapter_probe().is_some_and")
        .expect("gpu_available still owns adapter availability check");

    assert!(
        policy_gate < adapter_probe,
        "gpu_available must return false for --no-gpu before get_gpu()/init_gpu can probe a \
         broken adapter stack"
    );
}

#[test]
fn gpu_runtime_identity_honors_disabled_policy_before_adapter_probe() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/gpu/policy.rs"));
    let fn_start = src
        .find("pub(crate) fn gpu_runtime_identity() -> Option<String>")
        .expect("gpu_runtime_identity owner present");
    let body = &src[fn_start..];
    let policy_gate = body
        .find("gpu_disabled_by_policy()")
        .expect("gpu_runtime_identity checks resolved GPU runtime policy");
    let adapter_probe = body
        .find("super::gpu_adapter_probe()")
        .expect("gpu_runtime_identity still owns adapter identity check");

    assert!(
        policy_gate < adapter_probe,
        "gpu_runtime_identity must return None for --no-gpu before get_gpu()/init_gpu can probe \
         a broken adapter stack"
    );
}
