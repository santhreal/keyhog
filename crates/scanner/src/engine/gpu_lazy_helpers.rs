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

pub(super) fn report_gpu_matcher_unavailable(error: &crate::error::ScanError, matcher_kind: &str) {
    tracing::warn!(
        target: "keyhog::routing",
        %error,
        "GPU {matcher_kind} matcher unavailable; CPU/SIMD routes remain authoritative"
    );
    let warned = match matcher_kind {
        "literal" => &GPU_LITERAL_MATCHER_UNAVAILABLE_WARNED,
        _ => &GPU_LITERAL_MATCHER_UNAVAILABLE_WARNED,
    };
    if warned.set(()).is_ok() {
        eprintln!(
            "keyhog: GPU {matcher_kind} matcher unavailable ({error}); this scanner \
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
    let cache_key = format!(
        "{cache_prefix}-{}",
        super::gpu_cache::gpu_matcher_cache_key(&literal_refs)
    );
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
        let detail = if let Some(message) = panic.downcast_ref::<String>() {
            message.as_str()
        } else if let Some(message) = panic.downcast_ref::<&'static str>() {
            message
        } else {
            "non-string panic payload"
        };
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
