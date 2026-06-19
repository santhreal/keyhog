//! Hard-fail gate when GPU validation is mandatory.

/// When the explicit GPU runtime policy requires a GPU, panic if no compatible
/// adapter is present.
pub fn require_gpu_or_panic(context: &str) {
    if !keyhog_scanner::gpu::env_require_gpu() {
        return;
    }
    if !keyhog_scanner::gpu::gpu_available() {
        panic!(
            "{context}: --require-gpu requested but no compatible GPU adapter - \
             fail loudly instead of skipping GPU gates"
        );
    }
}

/// Hard-fail when GPU scan returned zero findings but a reference backend found matches.
pub fn assert_gpu_not_silent_empty(gpu_empty: bool, reference_finding_count: usize, context: &str) {
    if gpu_empty && reference_finding_count > 0 {
        panic!(
            "{context}: GPU returned zero findings vs {reference_finding_count} reference findings - \
             adapter init failure or silent CPU fallback must fail loudly, not skip"
        );
    }
}
