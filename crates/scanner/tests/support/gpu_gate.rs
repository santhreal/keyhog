//! Hard-fail gate when GPU validation is mandatory.

/// When `KEYHOG_REQUIRE_GPU=1`, panic if no compatible adapter is present.
pub fn require_gpu_or_panic(context: &str) {
    let require = std::env::var("KEYHOG_REQUIRE_GPU").ok();
    let strict = matches!(require.as_deref(), Some("1") | Some("true") | Some("yes"));
    if !strict {
        return;
    }
    if !keyhog_scanner::gpu::gpu_available() {
        panic!(
            "{context}: KEYHOG_REQUIRE_GPU=1 but no compatible GPU adapter — \
             fail loudly instead of skipping GPU gates"
        );
    }
}

/// Hard-fail when GPU scan returned zero findings but a reference backend found matches.
pub fn assert_gpu_not_silent_empty(
    gpu_empty: bool,
    reference_finding_count: usize,
    context: &str,
) {
    if gpu_empty && reference_finding_count > 0 {
        panic!(
            "{context}: GPU returned zero findings vs {reference_finding_count} reference findings — \
             adapter init failure or silent CPU fallback must fail loudly, not skip"
        );
    }
}
