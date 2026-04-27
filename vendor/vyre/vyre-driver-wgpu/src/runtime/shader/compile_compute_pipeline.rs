use dashmap::DashMap;
use std::sync::LazyLock;
use vyre_driver::error::Result;

/// Compile a WGSL compute shader into a `wgpu` compute pipeline.
///
/// This helper is **uncached**. Callers that want caching own their own
/// backend-scoped cache (see `crate::WgpuBackend::pipeline_cache` — the
/// single-source-of-truth in-memory pipeline cache for 0.6). The pre-0.6
/// process-wide `static PIPELINES: DashMap` that lived here was a second,
/// uncoordinated cache that leaked `wgpu::Device` references across
/// backend instances — removed per the 0.6 "one in-memory cache" rule.
///
/// Callers outside the backend dispatch path (e.g. `ext.rs` WGSL eval
/// helpers) pay the compile cost on every call, which is correct: the
/// WGSL eval helper is not a dispatch hot path.
///
/// # Errors
///
/// Returns an error if the shader module cannot be created or if the
/// pipeline compilation fails on the GPU.
#[inline]
pub fn compile_compute_pipeline(
    device: &wgpu::Device,
    label: &str,
    wgsl_source: &str,
    entry_point: &str,
) -> Result<wgpu::ComputePipeline> {
    compile_compute_pipeline_with_layout(device, label, wgsl_source, entry_point, None)
}

/// Compile a WGSL compute shader with an explicit pipeline layout.
///
/// Uncached. See [`compile_compute_pipeline`] for the caching rationale.
///
/// # Errors
///
/// Returns an actionable GPU error if the shader compiler rejects the
/// source or if the device refuses the pipeline descriptor.
#[inline]
pub fn compile_compute_pipeline_with_layout(
    device: &wgpu::Device,
    label: &str,
    wgsl_source: &str,
    entry_point: &str,
    layout: Option<&wgpu::PipelineLayout>,
) -> Result<wgpu::ComputePipeline> {
    super::dump_wgsl_if_requested(label, wgsl_source).map_err(|error| {
        vyre_driver::error::Error::Gpu {
            message: format!(
                "failed to dump WGSL for `{label}`: {error}. Fix: set VYRE_DUMP_WGSL to a writable directory or unset it"
            ),
        }
    })?;
    let driver_cache = if device.features().contains(wgpu::Features::PIPELINE_CACHE) {
        Some(driver_pipeline_cache(device, label)?)
    } else {
        None
    };
    device.push_error_scope(wgpu::ErrorFilter::Validation);
    let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some(label),
        source: wgpu::ShaderSource::Wgsl(wgsl_source.into()),
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some(label),
        layout,
        module: &module,
        entry_point: Some(entry_point),
        compilation_options: wgpu::PipelineCompilationOptions::default(),
        cache: driver_cache.as_ref(),
    });
    match device.poll(wgpu::Maintain::Wait) {
        wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
    }
    if let Some(error) = pollster::block_on(device.pop_error_scope()) {
        return Err(vyre_driver::error::Error::Gpu {
            message: format!(
                "WGSL compute pipeline `{label}` failed validation: {error}. Fix: validate the lowered WGSL and adapter limits before compiling."
            ),
        });
    }
    Ok(pipeline)
}

fn driver_pipeline_cache(device: &wgpu::Device, _label: &str) -> Result<wgpu::PipelineCache> {
    static DRIVER_CACHES: LazyLock<DashMap<wgpu::Device, wgpu::PipelineCache>> =
        LazyLock::new(DashMap::new);

    if let Some(cache) = DRIVER_CACHES.get(device) {
        return Ok(cache.clone());
    }

    let cache = {
        #[allow(unsafe_code)]
        // SAFETY: data=None forbids untrusted bytes; fallback=true lets wgpu substitute an empty cache on backends without pipeline-cache support.
        unsafe {
            device.create_pipeline_cache(&wgpu::PipelineCacheDescriptor {
                label: Some("vyre wgpu pipeline cache"),
                data: None,
                fallback: true,
            })
        }
    };
    DRIVER_CACHES.insert(device.clone(), cache.clone());
    Ok(cache)
}
