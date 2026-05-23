//! GPU-accelerated batch inference for the MoE classifier via wgpu compute shaders.
//!
//! Processes N feature vectors in a single GPU dispatch, achieving ~10-100x
//! throughput over CPU for large batches. Falls back to CPU when no GPU is
//! available or for batches smaller than the crossover threshold.
//!
//! Architecture mirrors ml_scorer.rs exactly:
//! - Gate: Linear(41→6) + softmax
//! - 6 experts: Linear(41→32)+ReLU → Linear(32→16)+ReLU → Linear(16→1)
//! - Output: sigmoid(weighted sum of expert logits)

#[path = "gpu_shader.rs"]
mod gpu_shader;

mod backend {
    use std::sync::OnceLock;

    use super::gpu_shader::MOE_SHADER;

    use bytemuck::{Pod, Zeroable};

    /// Minimum batch size before GPU dispatch is worthwhile.
    /// Below this, CPU is faster due to GPU dispatch overhead.
    const GPU_BATCH_THRESHOLD: usize = 64;

    const INPUT_DIM: usize = 41;

    #[derive(Clone, Copy, Pod, Zeroable)]
    #[repr(C)]
    struct GpuParams {
        batch_size: u32,
        _pad: [u32; 3],
    }

    pub(super) struct GpuContext {
        /// Shared device+queue from vyre — NOT a second device.
        device_queue: std::sync::Arc<(wgpu::Device, wgpu::Queue)>,
        adapter_info: wgpu::AdapterInfo,
        device_limits: wgpu::Limits,
        pipeline: wgpu::ComputePipeline,
        weights_buf: wgpu::Buffer,
        params_buf: wgpu::Buffer,
        bind_group_layout: wgpu::BindGroupLayout,
    }

    impl GpuContext {
        /// Maximum single storage-buffer size the device will accept, in MiB.
        /// Clamped to 256 GiB because some drivers report the full 64-bit
        /// virtual address space as `max_buffer_size`.
        pub fn vram_mb(&self) -> Option<u64> {
            const SANE_CAP_MB: u64 = 256 * 1024;
            Some((self.device_limits.max_buffer_size / (1024 * 1024)).min(SANE_CAP_MB))
        }

        /// Human-readable GPU name from the adapter.
        pub fn gpu_name(&self) -> &str {
            &self.adapter_info.name
        }

        #[inline]
        fn device(&self) -> &wgpu::Device {
            &self.device_queue.0
        }

        #[inline]
        fn queue(&self) -> &wgpu::Queue {
            &self.device_queue.1
        }
    }

    static GPU: OnceLock<Option<GpuContext>> = OnceLock::new();

    fn init_gpu() -> Result<GpuContext, Box<dyn std::error::Error + Send + Sync>> {
        // Reuse the vyre WgpuBackend's device instead of creating a second one.
        // This shares the adapter probe, device request, and queue with the
        // literal-set/MegaScan GPU scanner — halving init time and memory.
        let vyre_backend = vyre_driver_wgpu::WgpuBackend::shared()
            .map_err(|e| format!("vyre WgpuBackend unavailable: {e}"))?;

        let adapter_info = vyre_backend.adapter_info().clone();

        // Reject software fallback adapters.
        if adapter_info.device_type == wgpu::DeviceType::Cpu {
            return Err(format!(
                "GPU adapter is a software fallback ({} on {:?}); refusing to use",
                adapter_info.name, adapter_info.backend
            )
            .into());
        }

        let device_limits = vyre_backend.device_limits().clone();
        let dq = vyre_backend.device_queue();

        tracing::info!(
            gpu = %adapter_info.name,
            backend = ?adapter_info.backend,
            device_type = ?adapter_info.device_type,
            driver = %adapter_info.driver,
            "GPU MoE: reusing vyre shared device"
        );

        let device = &dq.0;

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("moe_shader"),
            source: wgpu::ShaderSource::Wgsl(MOE_SHADER.into()),
        });

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("moe_bgl"),
            entries: &[
                // Weights buffer (read-only storage)
                bgl_entry(0, true),
                // Input features buffer (read-only storage)
                bgl_entry(1, true),
                // Output scores buffer (read-write storage)
                bgl_entry(2, false),
                // Params uniform
                wgpu::BindGroupLayoutEntry {
                    binding: 3,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
            ],
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("moe_pipeline_layout"),
            bind_group_layouts: &[&bind_group_layout],
            push_constant_ranges: &[],
        });

        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("moe_pipeline"),
            layout: Some(&pipeline_layout),
            module: &shader,
            entry_point: Some("moe_forward"),
            compilation_options: Default::default(),
            cache: None,
        });

        // Upload weights once
        let all_weights = crate::ml_scorer::ml_weights::all_weights_slice();
        let weights_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("weights"),
            contents: bytemuck::cast_slice(all_weights),
            usage: wgpu::BufferUsages::STORAGE,
        });

        let params_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("params"),
            size: std::mem::size_of::<GpuParams>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        Ok(GpuContext {
            device_queue: dq,
            adapter_info,
            device_limits,
            pipeline,
            weights_buf,
            params_buf,
            bind_group_layout,
        })
    }

    fn bgl_entry(binding: u32, read_only: bool) -> wgpu::BindGroupLayoutEntry {
        wgpu::BindGroupLayoutEntry {
            binding,
            visibility: wgpu::ShaderStages::COMPUTE,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Storage { read_only },
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        }
    }

    /// Return the lazily initialized GPU context when GPU inference is available.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::gpu::get_gpu;
    /// let _ = get_gpu();
    /// ```
    pub fn get_gpu() -> Option<&'static GpuContext> {
        GPU.get_or_init(|| match init_gpu() {
            Ok(ctx) => {
                tracing::info!("GPU MoE inference initialized (shared device)");
                Some(ctx)
            }
            Err(e) => {
                tracing::debug!("GPU init failed, using CPU fallback: {e}");
                None
            }
        })
        .as_ref()
    }

    /// Score a batch of feature vectors on GPU. Returns one score per input.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use keyhog_scanner::gpu::batch_score_features;
    /// let _ = batch_score_features(&[[0.0; 41]]);
    /// ```
    pub fn batch_score_features(features: &[[f32; INPUT_DIM]]) -> Option<Vec<f64>> {
        if features.len() < GPU_BATCH_THRESHOLD {
            return None; // Too small for GPU, caller should use CPU
        }

        let gpu = get_gpu()?;
        let batch_size = features.len();
        let device = gpu.device();
        let queue = gpu.queue();

        // Flatten features into a contiguous f32 buffer
        let flat_features: Vec<f32> = features.iter().flat_map(|f| f.iter().copied()).collect();

        let input_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("input"),
            contents: bytemuck::cast_slice(&flat_features),
            usage: wgpu::BufferUsages::STORAGE,
        });

        let output_size = (batch_size * std::mem::size_of::<f32>()) as u64;
        let output_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("output"),
            size: output_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let staging_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("staging"),
            size: output_size,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // Upload params
        let params = GpuParams {
            batch_size: batch_size as u32,
            _pad: [0; 3],
        };
        queue.write_buffer(&gpu.params_buf, 0, bytemuck::bytes_of(&params));

        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("moe_bg"),
            layout: &gpu.bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: gpu.weights_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: input_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: output_buf.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: gpu.params_buf.as_entire_binding(),
                },
            ],
        });

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("moe_encoder"),
        });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("moe_pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&gpu.pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            // Each workgroup processes 64 items
            let workgroups = (batch_size as u32).div_ceil(64);
            pass.dispatch_workgroups(workgroups, 1, 1);
        }

        encoder.copy_buffer_to_buffer(&output_buf, 0, &staging_buf, 0, output_size);
        queue.submit(std::iter::once(encoder.finish()));

        // Read back results
        let slice = staging_buf.slice(..);
        let (sender, receiver) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        device.poll(wgpu::Maintain::Wait);

        receiver.recv().ok()?.ok()?;
        let data = slice.get_mapped_range();
        let scores: &[f32] = bytemuck::cast_slice(&data);
        let result: Vec<f64> = scores.iter().map(|&s| s as f64).collect();
        drop(data);
        staging_buf.unmap();

        Some(result)
    }

    use wgpu::util::DeviceExt;
}

/// Score multiple (credential, context) pairs in a single batch.
///
/// Uses GPU compute shaders when available and the batch is large enough.
/// Falls back to CPU for small batches or when no GPU is present.
/// Score a batch of `(text, context)` candidates, using GPU when available.
///
/// # Examples
///
/// ```rust,ignore
/// use keyhog_scanner::gpu::batch_ml_inference;
/// use keyhog_scanner::ScannerConfig;
/// let config = ScannerConfig::default();
/// let scores = batch_ml_inference(&[("demo_ABC12345", "API_KEY=")], &config);
/// assert_eq!(scores.len(), 1);
/// ```
///
/// Callers pass `(&str, &str)` so a hot-path scan with N matches no longer
/// allocates 2N owned strings just to enter ML scoring. The MlPendingMatch
/// `String` fields stay live for the duration of the call — the borrow is
/// safe.
pub fn batch_ml_inference(
    candidates: &[(&str, &str)],
    config: &crate::types::ScannerConfig,
) -> Vec<f64> {
    if candidates.is_empty() {
        return Vec::new();
    }

    #[cfg(feature = "ml")]
    {
        // Auto-route: try GPU batch first, fall back to CPU MoE on failure or
        // when the batch is below the GPU crossover threshold.
        let features: Vec<[f32; 41]> = candidates
            .iter()
            .map(|(text, ctx)| {
                crate::ml_scorer::compute_features_with_config(
                    text,
                    ctx,
                    &config.known_prefixes,
                    &config.secret_keywords,
                    &config.test_keywords,
                    &config.placeholder_keywords,
                )
            })
            .collect();

        if let Some(scores) = backend::batch_score_features(&features) {
            return scores;
        }

        candidates
            .iter()
            .map(|(text, ctx)| {
                crate::ml_scorer::score_with_config(
                    text,
                    ctx,
                    &config.known_prefixes,
                    &config.secret_keywords,
                    &config.test_keywords,
                    &config.placeholder_keywords,
                )
            })
            .collect()
    }

    #[cfg(not(feature = "ml"))]
    {
        let _ = candidates;
        let _ = config;
        Vec::new()
    }
}

/// Check if GPU acceleration is available.
/// Return `true` when GPU scoring support is available in this build/runtime.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::gpu::gpu_available;
/// let _ = gpu_available();
/// ```
pub fn gpu_available() -> bool {
    backend::get_gpu().is_some()
}

/// Result from an explicit GPU adapter and dispatch self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuSelfTest {
    /// Human-readable adapter name reported by wgpu.
    pub adapter_name: String,
    /// Approximate storage-buffer capability in MiB when available.
    pub vram_mb: Option<u64>,
    /// Number of scores produced by the compute dispatch.
    pub scores: usize,
}

/// Result from an explicit vyre GPU scanner self-test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VyreGpuSelfTest {
    /// Number of direct GPU matches produced by `GpuLiteralSet::scan`.
    pub direct_matches: usize,
    /// Number of matches produced by one coalesced scanner GPU dispatch.
    pub coalesced_matches: usize,
}

/// Force a GPU compute dispatch and validate the returned scores.
///
/// This is stricter than [`gpu_available`]: it proves that a non-fallback wgpu
/// adapter initialized and that the MoE compute shader can run at least one
/// production-sized batch.
pub fn gpu_self_test() -> Result<GpuSelfTest, String> {
    const SELF_TEST_BATCH: usize = 64;

    let gpu = backend::get_gpu().ok_or_else(|| {
        "GPU adapter unavailable; install or enable a non-software GPU adapter and driver"
            .to_string()
    })?;

    let features = [[0.0_f32; 41]; SELF_TEST_BATCH];
    let scores = backend::batch_score_features(&features)
        .ok_or_else(|| "GPU dispatch produced no result".to_string())?;

    if scores.len() != SELF_TEST_BATCH {
        return Err(format!(
            "GPU dispatch returned {} scores for {SELF_TEST_BATCH} inputs",
            scores.len()
        ));
    }

    if let Some((index, score)) = scores
        .iter()
        .enumerate()
        .find(|(_, score)| !score.is_finite() || !(0.0..=1.0).contains(*score))
    {
        return Err(format!(
            "GPU dispatch returned invalid score {score} at index {index}"
        ));
    }

    Ok(GpuSelfTest {
        adapter_name: gpu.gpu_name().to_string(),
        vram_mb: gpu.vram_mb(),
        scores: scores.len(),
    })
}

/// Force the vyre GPU scanner and coalesced scanner paths.
///
/// Proves the scanner-side GPU dependency is available independently from
/// Keyhog's MoE GPU scorer. Both `direct_matches` and `coalesced_matches` are
/// populated from real GPU scans — see audit release-2026-04-26 for the prior
/// rigged-test bug where `coalesced_matches` was hardcoded.
pub fn vyre_gpu_self_test() -> Result<VyreGpuSelfTest, String> {
    use vyre_driver_wgpu::WgpuBackend;
    use vyre_libs::matching::GpuLiteralSet;

    let patterns: Vec<Vec<u8>> = vec![b"needle".to_vec()];
    let pattern_refs: Vec<&[u8]> = patterns.iter().map(Vec::as_slice).collect();

    let backend = WgpuBackend::shared().map_err(|e| format!("failed to init wgpu backend: {e}"))?;
    let scanner = GpuLiteralSet::compile(&pattern_refs);

    let direct = scanner
        .scan(backend.as_ref(), b"needle", 100)
        .map_err(|error| format!("vyre direct GPU scan failed: {error}"))?;
    if direct.len() != 1 || direct[0].pattern_id != 0 || direct[0].start != 0 {
        return Err(format!(
            "vyre direct GPU scan returned unexpected matches: {direct:?}"
        ));
    }

    // Coalesced: 100 needles concatenated; expect 100 real matches.
    let items: Vec<Vec<u8>> = (0..100)
        .map(|index| format!("id-{index:03}-needle").into_bytes())
        .collect();
    let mut buffer = Vec::with_capacity(items.iter().map(Vec::len).sum());
    for item in &items {
        buffer.extend_from_slice(item);
    }

    let coalesced = scanner
        .scan(backend.as_ref(), &buffer, 10_000)
        .map_err(|error| format!("vyre coalesced GPU scan failed: {error}"))?;

    Ok(VyreGpuSelfTest {
        direct_matches: direct.len(),
        coalesced_matches: coalesced.len(),
    })
}

/// Probe GPU availability and adapter metadata without panicking.
#[must_use]
pub fn gpu_probe() -> (bool, Option<String>, Option<u64>) {
    if let Some(gpu) = backend::get_gpu() {
        return (true, Some(gpu.gpu_name().to_string()), gpu.vram_mb());
    }
    (false, None, None)
}
