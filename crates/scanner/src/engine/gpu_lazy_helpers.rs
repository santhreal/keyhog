use std::sync::Arc;

static GPU_MATCHER_CACHE_UNAVAILABLE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
static GPU_LITERAL_MATCHER_UNAVAILABLE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

fn report_gpu_matcher_cache_unavailable(error: &super::gpu_cache::GpuMatcherCacheDirError) {
    tracing::warn!(target: "keyhog::routing", %error, "GPU matcher disk cache unavailable; compiling literal set without cache");
    if GPU_MATCHER_CACHE_UNAVAILABLE_WARNED.set(()).is_ok() {
        eprintln!("keyhog: GPU matcher disk cache unavailable ({error}); compiling the matcher without persistence, so this process may pay the GPU matcher compile cost again. Fix the OS user cache directory or set XDG_CACHE_HOME to a writable directory.");
    }
}

pub(super) fn report_gpu_literal_matcher_unavailable(error: &crate::error::ScanError) {
    tracing::warn!(target: "keyhog::routing", %error, "GPU literal matcher unavailable; CPU/SIMD routes remain authoritative");
    if GPU_LITERAL_MATCHER_UNAVAILABLE_WARNED.set(()).is_ok() {
        eprintln!("keyhog: GPU literal matcher unavailable ({error}); this scanner cannot use that GPU matcher and will route through CPU/SIMD validation instead. Use --require-gpu when GPU acceleration is mandatory.");
    }
}

pub(super) fn compile_gpu_literal_set(
    literals: &Arc<Vec<Vec<u8>>>,
    cache_prefix: &str,
) -> crate::error::Result<vyre::scan::GpuLiteralSet> {
    crate::gpu_literal_artifacts::record_runtime_gpu_literal_compiler_invocation();
    let literal_refs: Vec<&[u8]> = literals.iter().map(|v| v.as_slice()).collect();
    let cache_key =
        super::gpu_cache::gpu_matcher_cache_key_with_prefix(cache_prefix, &literal_refs);
    // Compiling the literal set is charged to the profiler's backend-dispatch stage.
    let _compile_span = keyhog_profile::span(keyhog_profile::Stage::BackendDispatch);
    let matcher = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match super::gpu_cache::gpu_matcher_cache_dir() {
            Ok(cache_dir) => {
                let cache_file = cache_dir.join(&cache_key);
                let cache_file_bin = cache_dir.join(format!("{cache_key}.bin"));
                let is_hit = cache_file.exists() || cache_file_bin.exists();
                if is_hit {
                    keyhog_profile::record_cache_hit(keyhog_profile::CacheId::GpuProgram);
                } else {
                    keyhog_profile::record_cache_miss(keyhog_profile::CacheId::GpuProgram);
                }
                let res = vyre::scan::cached_load_or_compile(&cache_dir, &cache_key, || {
                    vyre::scan::GpuLiteralSet::compile_case_insensitive(&literal_refs)
                });
                if !is_hit {
                    crate::cache_eviction::evict_cache_dir_with_policy(
                        &cache_dir,
                        keyhog_core::CacheKind::GpuPrograms,
                        keyhog_core::CacheKind::GpuPrograms.default_policy(),
                    );
                }
                res
            }
            Err(error) => {
                keyhog_profile::record_cache_miss(keyhog_profile::CacheId::GpuProgram);
                report_gpu_matcher_cache_unavailable(&error);
                vyre::scan::GpuLiteralSet::compile_case_insensitive(&literal_refs)
            }
        }
    }))
    .map_err(|panic| {
        let detail = crate::error::panic_payload_detail(panic);
        crate::error::ScanError::Gpu(format!(
            "GPU literal-set compile panicked for cache prefix {cache_prefix} with {} patterns: {detail}. Fix: reduce literal rows, increase VYRE's DFA budget, or shard the literal set; matcher disabled for this scanner build.",
            literal_refs.len()
        ))
    })?;
    tracing::debug!(target: "keyhog::routing", patterns = literal_refs.len(), cache_prefix, "GpuLiteralSet ready (warm cache or compiled)");
    Ok(matcher)
}
