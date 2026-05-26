use keyhog_scanner::gpu::gpu_self_test;
#[test]
fn gpu_self_test_returns_result() {
    let result = gpu_self_test();
    if result.is_ok() {
        let info = result.unwrap();
        assert!(!info.adapter_name.is_empty());
        assert_eq!(info.scores, 64);
    }
}
