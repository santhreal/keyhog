use std::sync::Arc;

static GPU_MATCHER_CACHE_UNAVAILABLE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
static GPU_LITERAL_MATCHER_UNAVAILABLE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn report_gpu_matcher_cache_unavailable(error: &super::gpu_cache::GpuMatcherCacheDirError) {
    tracing::warn!(
        target: "keyhog::routing",
        %error,
        "GPU matcher disk cache unavailable; compiling literal set without cache"
    );
    if GPU_MATCHER_CACHE_UNAVAILABLE_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: GPU matcher disk cache unavailable ({error}); compiling the matcher \
without persistence, so this process may pay the GPU matcher compile cost again. \
Fix the OS user cache directory or set XDG_CACHE_HOME to a writable directory."
        );
    }
}

/// Shared decode of a `catch_unwind` panic payload into an owned detail string.
/// Single owner for the literal and artifact compile paths.
pub(super) fn catch_unwind_panic_detail(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = panic.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else {
        "non-string panic payload".to_string()
    }
}

pub(super) fn report_gpu_literal_matcher_unavailable(error: &crate::error::ScanError) {
    tracing::warn!(
        target: "keyhog::routing",
        %error,
        "GPU literal matcher unavailable; CPU/SIMD routes remain authoritative"
    );
    if GPU_LITERAL_MATCHER_UNAVAILABLE_WARNED.set(()).is_ok() {
        eprintln!(
            "keyhog: GPU literal matcher unavailable ({error}); this scanner \
cannot use that GPU matcher and will route through CPU/SIMD validation instead. \
Use --require-gpu when GPU acceleration is mandatory."
        );
    }
}

pub(super) fn compile_gpu_literal_set(
    literals: &Arc<Vec<Vec<u8>>>,
    cache_prefix: &str,
) -> crate::error::Result<vyre_libs::scan::GpuLiteralSet> {
    let literal_refs: Vec<&[u8]> = literals.iter().map(|v| v.as_slice()).collect();
    let cache_key =
        super::gpu_cache::gpu_matcher_cache_key_with_prefix(cache_prefix, &literal_refs);
    let started = std::time::Instant::now();
    let matcher = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match super::gpu_cache::gpu_matcher_cache_dir() {
            Ok(cache_dir) => vyre_libs::scan::cached_load_or_compile(&cache_dir, &cache_key, || {
                vyre_libs::scan::GpuLiteralSet::compile(&literal_refs)
            }),
            Err(error) => {
                report_gpu_matcher_cache_unavailable(&error);
                vyre_libs::scan::GpuLiteralSet::compile(&literal_refs)
            }
        }
    }))
    .map_err(|panic| {
        let detail = catch_unwind_panic_detail(panic);
        crate::error::ScanError::Gpu(format!(
            "GPU literal-set compile panicked for cache prefix {cache_prefix} with {} patterns: {detail}. Fix: reduce literal rows, increase Vyre's DFA budget, or shard the literal set; matcher disabled for this scanner build.",
            literal_refs.len()
        ))
    })?;
    tracing::debug!(
        target: "keyhog::routing",
        patterns = literal_refs.len(),
        cache_prefix,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "GpuLiteralSet ready (warm cache or compiled)"
    );
    Ok(matcher)
}
