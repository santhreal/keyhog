use keyhog_scanner::engine::AC_GPU_MAX_MATCHES_PER_DISPATCH;
#[test]
fn ac_gpu_max_matches_is_dense_prefix_cap() {
    assert_eq!(AC_GPU_MAX_MATCHES_PER_DISPATCH, 32_768);
}
