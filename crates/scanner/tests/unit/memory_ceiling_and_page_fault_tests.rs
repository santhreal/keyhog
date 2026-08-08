use keyhog_scanner::{
    enforce_cpu_rss_ceiling, enforce_simd_rss_ceiling, CPU_MAX_RSS_CEILING_BYTES,
    SIMD_MAX_RSS_CEILING_BYTES,
};

#[test]
fn cpu_rss_ceiling_enforces_128mb_limit() {
    assert!(enforce_cpu_rss_ceiling(100 * 1024 * 1024).is_ok());
    assert!(enforce_cpu_rss_ceiling(CPU_MAX_RSS_CEILING_BYTES).is_ok());
    let err = enforce_cpu_rss_ceiling(CPU_MAX_RSS_CEILING_BYTES + 1).unwrap_err();
    assert!(err.to_string().contains("128MB RSS ceiling"));
}

#[test]
fn simd_rss_ceiling_enforces_128mb_limit() {
    assert!(enforce_simd_rss_ceiling(100 * 1024 * 1024).is_ok());
    assert!(enforce_simd_rss_ceiling(SIMD_MAX_RSS_CEILING_BYTES).is_ok());
    let err = enforce_simd_rss_ceiling(SIMD_MAX_RSS_CEILING_BYTES + 1).unwrap_err();
    assert!(err.to_string().contains("128MB RSS ceiling"));
}
