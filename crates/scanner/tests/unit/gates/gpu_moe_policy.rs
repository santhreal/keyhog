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
