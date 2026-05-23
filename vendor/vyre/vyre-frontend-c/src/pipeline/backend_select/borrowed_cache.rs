use super::*;

pub(crate) fn dispatch_borrowed_cached_into(
    backend: &dyn VyreBackend,
    program: &Program,
    inputs: &[&[u8]],
    config: &DispatchConfig,
    outputs: &mut Vec<Vec<u8>>,
) -> Result<(), vyre::BackendError> {
    #[allow(clippy::type_complexity)]
    static PIPELINES: OnceLock<
        Mutex<BoundedPipelineCache<BackendProgramPipelineCacheKey, Arc<dyn CompiledPipeline>>>,
    > = OnceLock::new();
    let key = (
        backend_pipeline_cache_key(backend.id()),
        vyre_foundation::optimizer::pipeline_fingerprint_bytes(program),
    );
    let cache = PIPELINES.get_or_init(|| Mutex::new(BoundedPipelineCache::default()));
    if let Some(pipeline) = cache
        .lock()
        .map_err(|error| vyre::BackendError::DispatchFailed {
            code: None,
            message: format!("frontend C pipeline cache lock poisoned: {error}"),
        })?
        .get_cloned(&key)
    {
        return pipeline.dispatch_borrowed_into(inputs, config, outputs);
    }

    let Some(pipeline) = backend.compile_native(program, config)? else {
        if backend.id() == "cuda" && vyre_driver::grid_sync::contains_grid_sync(program) {
            return backend.dispatch_borrowed_into(program, inputs, config, outputs);
        }
        return Err(vyre::BackendError::DispatchFailed {
            code: None,
            message: format!(
                "{} backend did not return a compiled native pipeline for `{}`. Fix: repair native compilation/cache integration; the C frontend must not silently downgrade to uncached dispatch.",
                backend.id(),
                program.entry_op_id.as_deref().unwrap_or("<anonymous>")
            ),
        });
    };
    let mut guard = cache
        .lock()
        .map_err(|error| vyre::BackendError::DispatchFailed {
            code: None,
            message: format!("frontend C pipeline cache lock poisoned while inserting: {error}"),
        })?;
    let cache_bytes = compiled_pipeline_cache_estimated_bytes(program);
    guard.insert_with_cost(
        key,
        Arc::clone(&pipeline),
        COMPILED_PIPELINE_CACHE_MAX_ENTRIES,
        cache_bytes,
        COMPILED_PIPELINE_CACHE_MAX_BYTES,
    );
    pipeline.dispatch_borrowed_into(inputs, config, outputs)
}

pub(crate) fn stage_pipeline_cache_key(stage: &str, params: &[u64]) -> StagePipelineCacheKey {
    let mut hash = blake3::Hasher::new();
    blake3_128_update_len_prefixed(&mut hash, stage.as_bytes());
    hash.update(&(params.len() as u64).to_le_bytes());
    for param in params {
        hash.update(&param.to_le_bytes());
    }
    blake3_128_from_hasher(&hash)
}

pub(super) fn stage_pipeline_cache_key_hex(key: StagePipelineCacheKey) -> String {
    let mut out = String::with_capacity(32);
    for byte in key {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn dispatch_borrowed_stage_cached_into<F>(
    backend: &dyn VyreBackend,
    stage_key: StagePipelineCacheKey,
    build_program: F,
    inputs: &[&[u8]],
    config: &DispatchConfig,
    outputs: &mut Vec<Vec<u8>>,
) -> Result<(), vyre::BackendError>
where
    F: FnOnce() -> Result<Program, String>,
{
    #[allow(clippy::type_complexity)]
    static PIPELINES: OnceLock<
        Mutex<BoundedPipelineCache<BackendStagePipelineCacheKey, Arc<dyn CompiledPipeline>>>,
    > = OnceLock::new();
    let key = (backend_pipeline_cache_key(backend.id()), stage_key);
    let cache = PIPELINES.get_or_init(|| Mutex::new(BoundedPipelineCache::default()));
    if let Some(pipeline) = cache
        .lock()
        .map_err(|error| vyre::BackendError::DispatchFailed {
            code: None,
            message: format!("frontend C stage pipeline cache lock poisoned: {error}"),
        })?
        .get_cloned(&key)
    {
        return pipeline.dispatch_borrowed_into(inputs, config, outputs);
    }

    let program = build_program().map_err(|message| vyre::BackendError::DispatchFailed {
        code: None,
        message,
    })?;
    let Some(pipeline) = backend.compile_native(&program, config)? else {
        if backend.id() == "cuda" && vyre_driver::grid_sync::contains_grid_sync(&program) {
            return backend.dispatch_borrowed_into(&program, inputs, config, outputs);
        }
        return Err(vyre::BackendError::DispatchFailed {
            code: None,
            message: format!(
                "{} backend did not return a compiled native pipeline for `{}`. Fix: repair native compilation/cache integration; the C frontend must not silently downgrade to uncached dispatch.",
                backend.id(),
                program.entry_op_id.as_deref().unwrap_or("<anonymous>")
            ),
        });
    };
    let mut guard = cache
        .lock()
        .map_err(|error| vyre::BackendError::DispatchFailed {
            code: None,
            message: format!(
                "frontend C stage pipeline cache lock poisoned while inserting: {error}"
            ),
        })?;
    let cache_bytes = compiled_pipeline_cache_estimated_bytes(&program);
    guard.insert_with_cost(
        key,
        Arc::clone(&pipeline),
        COMPILED_PIPELINE_CACHE_MAX_ENTRIES,
        cache_bytes,
        COMPILED_PIPELINE_CACHE_MAX_BYTES,
    );
    pipeline.dispatch_borrowed_into(inputs, config, outputs)
}

#[cfg(test)]
mod tests {
    use super::{backend_pipeline_cache_key, stage_pipeline_cache_key};

    #[test]
    fn stage_pipeline_cache_key_uses_128_bit_stage_and_param_identity() {
        let key = stage_pipeline_cache_key("stage", &[1, 2, 3]);
        assert_eq!(key.len(), 16);
        assert_ne!(key, stage_pipeline_cache_key("stage", &[1, 23]));
        assert_ne!(key, stage_pipeline_cache_key("other-stage", &[1, 2, 3]));
    }

    #[test]
    fn backend_pipeline_cache_key_uses_128_bit_backend_identity() {
        let cuda = backend_pipeline_cache_key("cuda");
        let wgpu = backend_pipeline_cache_key("wgpu");
        assert_eq!(cuda.len(), 16);
        assert_eq!(cuda, backend_pipeline_cache_key("cuda"));
        assert_ne!(cuda, wgpu);
    }
}
