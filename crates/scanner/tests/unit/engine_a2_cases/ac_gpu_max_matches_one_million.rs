use keyhog_scanner::engine::AC_GPU_MAX_MATCHES_PER_DISPATCH;
#[test]
fn ac_gpu_max_matches_one_million() {
    assert_eq!(AC_GPU_MAX_MATCHES_PER_DISPATCH, 1_000_000);
}
