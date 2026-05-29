//! MoE GPU inference backend (wgpu compute).

use super::gpu_shader::MOE_SHADER;

use bytemuck::{Pod, Zeroable};
use std::sync::OnceLock;
use wgpu::util::DeviceExt;

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
    /// Shared device+queue from vyre - NOT a second device.
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
    // literal-set/MegaScan GPU scanner - halving init time and memory.
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
            // No silent fallbacks. If the user has a GPU and we
            // can't use it, they need to know - otherwise they'll
            // sit at CPU throughput and assume that's what
            // "GPU-accelerated keyhog" means.
            // env_no_gpu() covers both the explicit env var AND
            // the auto-detected CI environment - on CI the GPU
            // probe was guaranteed to fail and the warning would
            // be noise.
            let no_gpu = super::env_no_gpu();
            let require_gpu = std::env::var("KEYHOG_REQUIRE_GPU").as_deref() == Ok("1");
            if require_gpu {
                eprintln!("keyhog: KEYHOG_REQUIRE_GPU=1 but GPU MoE init failed: {e}");
                std::process::exit(2);
            }
            // Only surface the CPU-fallback notice when a GPU is physically
            // PRESENT but unusable - that's the actionable case (driver/init
            // problem the user can fix). The GPU-less majority (laptops,
            // containers, CI, most servers) is the expected default path, not
            // a degraded one; printing "no usable GPU" to stderr on every
            // single scan there is pure noise. Suppressed unless a device was
            // actually detected. The full diagnostic stays at debug level.
            let gpu_present = crate::hw_probe::probe_hardware().gpu_available;
            if !no_gpu && gpu_present {
                eprintln!(
                    "keyhog: a GPU was detected but could not be initialized; using the \
CPU/SIMD scan path. Set KEYHOG_NO_GPU=1 to silence this, or KEYHOG_REQUIRE_GPU=1 to fail instead."
                );
            }
            tracing::debug!("GPU MoE init failed, using CPU fallback: {e}");
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
    // wgpu 25 replaced `Maintain::Wait` (infallible) with `PollType::Wait`
    // returning `Result<PollStatus, PollError>`. A poll error here means the
    // device was lost or the wait timed out, so the map callback below would
    // never fire — surface it and fall back to CPU MoE rather than block.
    if let Err(error) = device.poll(wgpu::PollType::Wait) {
        tracing::warn!(
            ?error,
            "GPU MoE device.poll() failed; falling back to CPU MoE for this scan"
        );
        return None;
    }

    // GPU MoE staging-buffer read. The double `.ok()?` here used
    // to swallow BOTH the channel `recv` failure (the wgpu callback
    // was never invoked) AND the `map_async` failure (driver
    // rejected the map) silently, falling back to the CPU MoE
    // path without any breadcrumb. Surface both as a warn so the
    // operator can see why their RTX-class card stopped accelerating
    // confidence scoring mid-scan.
    let map_recv = match receiver.recv() {
        Ok(r) => r,
        Err(error) => {
            tracing::warn!(%error, "GPU MoE staging-buffer recv() failed; falling back to CPU MoE for this scan");
            return None;
        }
    };
    if let Err(error) = map_recv {
        tracing::warn!(
            ?error,
            "GPU MoE staging-buffer map_async failed; falling back to CPU MoE for this scan"
        );
        return None;
    }
    let data = slice.get_mapped_range();
    let scores: &[f32] = bytemuck::cast_slice(&data);
    // kimi-confidence audit: a GPU driver bug, shader miscompile, or
    // adversarial weights buffer can produce NaN/Inf in the f32
    // staging buffer. The previous flow forwarded those values
    // verbatim into the confidence pipeline, where `.clamp(0, 1)`
    // does NOT sanitize NaN (Rust f64::clamp leaves NaN as NaN),
    // and the NaN propagated all the way to SARIF `confidence: NaN`.
    // Sanitize at the GPU boundary so every downstream consumer
    // sees a finite probability in [0, 1].
    let result: Vec<f64> = scores
        .iter()
        .map(|&s| {
            let v = s as f64;
            if v.is_finite() {
                v.clamp(0.0, 1.0)
            } else {
                // NaN or +/-Inf: treat as "no signal" sentinel and
                // fall back to the neutral 0.5. The heuristic-only
                // path will dominate the blend (see engine/mod.rs
                // line 1185) so the finding still surfaces with
                // the score the rule alone would have produced.
                0.5
            }
        })
        .collect();
    drop(data);
    staging_buf.unmap();

    Some(result)
}
