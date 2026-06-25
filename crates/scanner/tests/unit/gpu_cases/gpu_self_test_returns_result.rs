use keyhog_scanner::gpu::gpu_self_test;
#[test]
fn gpu_self_test_returns_result() {
    let result = gpu_self_test();
    if result.is_ok() {
        let info = result.expect("checked ok");
        assert!(!info.adapter_name.is_empty());
        assert!(
            info.scores > 0,
            "GPU self-test should report the number of production-sized probe scores"
        );
    }
}
