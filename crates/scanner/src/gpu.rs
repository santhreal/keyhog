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

    /// Per-OS preferred wgpu backend mask. Returns the union of the OS-native
    /// backend (DX12/Metal/Vulkan) and a portable fallback (Vulkan/GL) so a
    /// missing native ICD still surfaces *some* adapter rather than dropping
    /// straight to CpuFallback.
    pub(super) fn preferred_backends() -> wgpu::Backends {
        #[cfg(target_os = "windows")]
        {
            wgpu::Backends::DX12 | wgpu::Backends::VULKAN
        }
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            wgpu::Backends::METAL
        }
        #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
        {
            wgpu::Backends::VULKAN | wgpu::Backends::GL
        }
        #[cfg(not(any(unix, target_os = "windows", target_os = "macos", target_os = "ios")))]
        {
            wgpu::Backends::all()
        }
    }

    const INPUT_DIM: usize = 41;

    #[derive(Clone, Copy, Pod, Zeroable)]
    #[repr(C)]
    struct GpuParams {
        batch_size: u32,
        _pad: [u32; 3],
    }

    pub(super) struct GpuContext {
        device: wgpu::Device,
        queue: wgpu::Queue,
        adapter_info: wgpu::AdapterInfo,
        pipeline: wgpu::ComputePipeline,
        weights_buf: wgpu::Buffer,
        params_buf: wgpu::Buffer,
        bind_group_layout: wgpu::BindGroupLayout,
    }

    impl GpuContext {
        /// Maximum single storage-buffer size the device will accept, in MiB.
        /// This is the practical ceiling on a GPU batch — not actual VRAM
        /// (wgpu/WebGPU does not standardize VRAM queries), but the right
        /// number for sizing scan batches. Clamped to 256 GiB because some
        /// drivers (NVIDIA in particular) report the full 64-bit virtual
        /// address space (≈18 EB) as `max_buffer_size`, which is technically
        /// correct but useless to display.
        pub fn vram_mb(&self) -> Option<u64> {
            const SANE_CAP_MB: u64 = 256 * 1024;
            let limits = self.device.limits();
            Some((limits.max_buffer_size / (1024 * 1024)).min(SANE_CAP_MB))
        }

        /// Human-readable GPU name from the adapter.
        pub fn gpu_name(&self) -> &str {
            &self.adapter_info.name
        }
    }

    static GPU: OnceLock<Option<GpuContext>> = OnceLock::new();

    fn init_gpu() -> Result<GpuContext, Box<dyn std::error::Error + Send + Sync>> {
        // Offload blocking wgpu initialization to a dedicated OS thread so we
        // don't starve the calling thread's async runtime (e.g. tokio workers).
        let handle = std::thread::spawn(|| {
            // Per-OS native backend preference — wgpu maps to:
            //   Linux/BSD → Vulkan (also covers Steam Deck / proton / mesa)
            //   Windows   → DX12 (native) + Vulkan (NVIDIA/AMD on Win11)
            //   macOS/iOS → Metal (only first-class API on Apple silicon)
            //   Other     → all backends, let wgpu pick
            // We OR with GL as a last-resort so headless Linux servers
            // without a real Vulkan ICD still get *something*. Backends::all()
            // is the union; we just rank-bias the pickone via env override
            // (`WGPU_BACKEND=vulkan` etc) for diagnostics.
            let backends = preferred_backends();
            let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
                backends,
                ..Default::default()
            });

            let adapter =
                pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                    power_preference: wgpu::PowerPreference::HighPerformance,
                    compatible_surface: None,
                    force_fallback_adapter: false,
                }))
                .ok_or("No GPU adapter found")?;

            let adapter_info = adapter.get_info();

            // Reject software fallback adapters at the wgpu layer too —
            // hw_probe's name-based check (llvmpipe/lavapipe/swiftshader)
            // catches the common ones, but `device_type == Cpu` is the
            // authoritative signal. Returning Err here drops us straight
            // to SimdCpu without ever instantiating an unusable device.
            if adapter_info.device_type == wgpu::DeviceType::Cpu {
                return Err(format!(
                    "GPU adapter is a software fallback ({} on {:?}); refusing to use",
                    adapter_info.name, adapter_info.backend
                )
                .into());
            }

            // Request the adapter's full limits — wgpu's `Limits::default()`
            // caps `max_storage_buffer_binding_size` at 128 MiB which is far
            // smaller than the actual GPU capacity (e.g. 32 GB on an RTX 5090).
            // Using adapter limits unlocks larger batch dispatches; if the
            // adapter is constrained we still get the right effective ceiling.
            let adapter_limits = adapter.limits();
            let (device, queue) = pollster::block_on(adapter.request_device(
                &wgpu::DeviceDescriptor {
                    label: Some("keyhog-moe"),
                    required_features: wgpu::Features::empty(),
                    required_limits: adapter_limits,
                    ..Default::default()
                },
                None,
            ))?;
            tracing::info!(
                gpu = %adapter_info.name,
                backend = ?adapter_info.backend,
                device_type = ?adapter_info.device_type,
                driver = %adapter_info.driver,
                "GPU device initialized"
            );

            let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
                label: Some("moe_shader"),
                source: wgpu::ShaderSource::Wgsl(MOE_SHADER.into()),
            });

            let bind_group_layout =
                device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
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
                device,
                queue,
                adapter_info,
                pipeline,
                weights_buf,
                params_buf,
                bind_group_layout,
            })
        });
        // 2-second timeout: never block startup waiting for GPU.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if handle.is_finished() {
                return handle.join().map_err(|_| "GPU init thread panicked")?;
            }
            if std::time::Instant::now() > deadline {
                return Err("GPU init timed out — falling back to CPU".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
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
                tracing::info!("GPU MoE inference initialized");
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
    /// Score a batch of precomputed feature vectors on the GPU.
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

        // Flatten features into a contiguous f32 buffer
        let flat_features: Vec<f32> = features.iter().flat_map(|f| f.iter().copied()).collect();

        let input_buf = gpu
            .device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("input"),
                contents: bytemuck::cast_slice(&flat_features),
                usage: wgpu::BufferUsages::STORAGE,
            });

        let output_size = (batch_size * std::mem::size_of::<f32>()) as u64;
        let output_buf = gpu.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("output"),
            size: output_size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let staging_buf = gpu.device.create_buffer(&wgpu::BufferDescriptor {
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
        gpu.queue
            .write_buffer(&gpu.params_buf, 0, bytemuck::bytes_of(&params));

        let bind_group = gpu.device.create_bind_group(&wgpu::BindGroupDescriptor {
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

        let mut encoder = gpu
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
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
        gpu.queue.submit(std::iter::once(encoder.finish()));

        // Read back results
        let slice = staging_buf.slice(..);
        let (sender, receiver) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        gpu.device.poll(wgpu::Maintain::Wait);

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

#[cfg(test)]
mod tests {
    use super::backend::preferred_backends;

    #[test]
    fn preferred_backends_picks_native_per_os() {
        let backends = preferred_backends();
        // Whatever the host OS is, the union must be non-empty so wgpu has
        // at least one backend to try. Software-only fallback avoidance is
        // handled at adapter-selection time (force_fallback_adapter=false +
        // device_type==Cpu rejection).
        assert!(
            !backends.is_empty(),
            "preferred_backends must enable at least one backend; got empty mask"
        );

        // OS-native backend assertions: each platform must have its
        // first-class API in the mask, otherwise we are leaving perf on
        // the table by routing through a translation layer.
        #[cfg(target_os = "windows")]
        assert!(
            backends.contains(wgpu::Backends::DX12),
            "Windows must include DX12"
        );
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        assert!(
            backends.contains(wgpu::Backends::METAL),
            "Apple must include Metal"
        );
        #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
        assert!(
            backends.contains(wgpu::Backends::VULKAN),
            "Linux/BSD must include Vulkan"
        );
    }
}
