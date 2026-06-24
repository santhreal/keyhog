//! MoE GPU inference backend (wgpu compute).

use super::gpu_shader::MOE_SHADER;

use bytemuck::{Pod, Zeroable};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use wgpu::util::DeviceExt;

/// Minimum batch size before GPU dispatch is worthwhile. Below this, CPU is
/// faster due to GPU dispatch overhead. Single source of truth lives in
/// `ml_scorer` so the host-side serial/parallel crossover and this GPU-engage
/// gate stay locked together.
use crate::ml_scorer::GPU_BATCH_THRESHOLD;

// Single source of truth for the feature width: the MoE input dimension is the
// ML feature-vector length. Kept in lockstep with the WGSL `INPUT_DIM` in
// gpu_shader.rs and the host-side feature extractor.
const INPUT_DIM: usize = crate::ml_scorer::NUM_FEATURES;

const GPU_READBACK_SPIN_LIMIT: u32 = 32;
const GPU_READBACK_YIELD_LIMIT: u32 = 64;
const GPU_READBACK_INITIAL_SLEEP_US: u64 = 2;
const GPU_READBACK_MAX_SLEEP_US: u64 = 256;

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct GpuParams {
    batch_size: u32,
    _pad: [u32; 3],
}

pub(crate) struct GpuContext {
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
    pub(crate) fn vram_mb(&self) -> Option<u64> {
        const SANE_CAP_MB: u64 = 256 * 1024;
        Some((self.device_limits.max_buffer_size / (1024 * 1024)).min(SANE_CAP_MB))
    }

    /// Human-readable GPU name from the adapter.
    pub(crate) fn gpu_name(&self) -> &str {
        &self.adapter_info.name
    }

    /// Stable-enough runtime identity for calibration caches: wgpu backend,
    /// device type, PCI/vendor IDs where available, and driver strings.
    pub(super) fn runtime_identity(&self) -> String {
        format!(
            "wgpu:{:?}:type={:?}:vendor={:04x}:device={:04x}:driver={}:info={}",
            self.adapter_info.backend,
            self.adapter_info.device_type,
            self.adapter_info.vendor,
            self.adapter_info.device,
            self.adapter_info.driver,
            self.adapter_info.driver_info
        )
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

struct ReadbackWaitBackoff {
    iterations: u32,
    sleep_us: u64,
}

impl ReadbackWaitBackoff {
    fn new() -> Self {
        Self {
            iterations: 0,
            sleep_us: GPU_READBACK_INITIAL_SLEEP_US,
        }
    }

    fn wait(&mut self, remaining: Duration) {
        self.iterations = self.iterations.saturating_add(1);
        if self.iterations <= GPU_READBACK_SPIN_LIMIT {
            std::hint::spin_loop();
            return;
        }
        if self.iterations <= GPU_READBACK_YIELD_LIMIT {
            std::thread::yield_now();
            return;
        }

        let sleep = Duration::from_micros(self.sleep_us).min(remaining);
        if !sleep.is_zero() {
            std::thread::sleep(sleep);
        }
        self.sleep_us = self
            .sleep_us
            .saturating_mul(2)
            .min(GPU_READBACK_MAX_SLEEP_US);
    }
}

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
pub(crate) fn get_gpu() -> Option<&'static GpuContext> {
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
            // gpu_disabled_by_policy() is the resolved GPU runtime policy.
            // When GPU is explicitly disabled, this path stays
            // quiet because CPU/SIMD is the requested route.
            let no_gpu = super::gpu_disabled_by_policy();
            let require_gpu = super::gpu_required_by_policy();
            if require_gpu {
                crate::process_exit::require_gpu_unmet(format!(
                    "--require-gpu requested but GPU MoE init failed: {e}"
                ));
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
CPU/SIMD scan path. Use --no-gpu to silence this, or --require-gpu to fail instead."
                );
            }
            tracing::debug!("GPU MoE init failed, using CPU fallback: {e}"); // LAW10: NOT the sole surface — the degrade is loud at line ~230 (eprintln when a GPU is actually present) + the MOE_RUNTIME_DEGRADE_WARNED once-guard; CPU MoE is recall-preserving. This debug line is supplementary detail only.
            None
        }
    })
    .as_ref()
}

pub(super) fn gpu_runtime_identity() -> Option<String> {
    get_gpu().map(GpuContext::runtime_identity)
}

/// One-shot guard so a *runtime* GPU-MoE dispatch failure surfaces once per
/// process, not once per batch on a multi-thousand-batch scan.
static MOE_RUNTIME_DEGRADE_WARNED: AtomicBool = AtomicBool::new(false);

/// One-shot guard for the distinct NaN/Inf-score case (a GPU correctness fault,
/// not a dispatch failure); surfaced once per process by [`moe_nonfinite_degrade`].
static MOE_NONFINITE_WARNED: AtomicBool = AtomicBool::new(false);

static MOE_NUMERIC_TRUST: OnceLock<bool> = OnceLock::new();
static MOE_NUMERIC_DIVERGENCE_WARNED: AtomicBool = AtomicBool::new(false);

/// Surface a runtime GPU-MoE dispatch failure that is about to degrade the
/// affected batch(es) to the CPU MoE. This mirrors `engine::gpu_forced`'s
/// posture exactly so the MoE path is coherent with the literal-set/MegaScan
/// paths under the no-silent-fallback rule:
///
///   * `--require-gpu` -> hard-fail (`exit 12`). The init-time check in
///     [`get_gpu`] cannot catch this: acquisition succeeded, then a *specific
///     dispatch* (driver timeout, lost device, map_async error) failed deep in
///     the scan. Without this, `REQUIRE_GPU` silently degraded to CPU per batch.
///   * ordinary run -> a single loud stderr line (the scores are numerically
///     identical to GPU, but the operator who believes the scan is
///     GPU-accelerated must know it isn't, since throughput collapses).
///   * `--no-gpu` -> stay quiet (CPU is the requested path there).
///
/// Distinct from the below-threshold `None` (a legitimate routing choice, not a
/// failure) and from init failure (already handled loudly in [`get_gpu`]).
fn moe_runtime_degrade(reason: &str) {
    let no_gpu = super::gpu_disabled_by_policy();
    let require_gpu = super::gpu_required_by_policy();
    if require_gpu {
        crate::process_exit::require_gpu_unmet(format!(
            "--require-gpu requested but the GPU MoE dispatch failed at runtime \
({reason}). Refusing to silently degrade to the CPU MoE."
        ));
    }
    if no_gpu {
        return;
    }
    tracing::warn!(
        reason,
        "GPU MoE dispatch failed at runtime; affected batches are scored on the CPU MoE"
    );
    if !MOE_RUNTIME_DEGRADE_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "keyhog: GPU MoE dispatch failed at runtime ({reason}); affected batches in \
this scan are scored on the CPU MoE (identical scores, lower throughput). Set \
--no-gpu to silence, or --require-gpu to hard-fail next time."
        );
    }
}

/// Surface NaN / ±Inf scores returned by the GPU MoE staging buffer. A
/// non-finite probability is not a routing choice — it can only come from a GPU
/// driver bug, a shader miscompile, or a corrupt weights buffer, i.e. a GPU
/// CORRECTNESS fault. Each bad value is sanitized to a neutral `0.5` at the GPU
/// boundary (so downstream `confidence` math never sees NaN and the finding
/// still surfaces on its heuristic score), but Law 10 forbids doing that
/// silently: the operator must be told their GPU produced garbage. Gating
/// mirrors [`moe_runtime_degrade`] — hard-fail under `--require-gpu` (a GPU
/// emitting NaN is exactly the malfunction that flag exists to catch), one loud
/// stderr line on an ordinary run, and quiet under `--no-gpu` where the CPU MoE
/// is the intended path anyway.
fn moe_nonfinite_degrade(nonfinite: usize, total: usize) {
    let no_gpu = super::gpu_disabled_by_policy();
    let require_gpu = super::gpu_required_by_policy();
    if require_gpu {
        crate::process_exit::require_gpu_unmet(format!(
            "--require-gpu requested but the GPU MoE returned {nonfinite}/{total} \
non-finite (NaN/Inf) confidence score(s) — a GPU driver/shader/weights malfunction. \
Refusing to silently sanitize and continue."
        ));
    }
    if no_gpu {
        return;
    }
    tracing::error!(
        nonfinite,
        total,
        "GPU MoE produced non-finite confidence scores; scores were sanitized to neutral 0.5"
    );
    if !MOE_NONFINITE_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "keyhog: GPU MoE produced {nonfinite}/{total} non-finite (NaN/Inf) confidence \
score(s); each was sanitized to a neutral 0.5 so the finding still surfaces on its \
heuristic score, but this indicates a GPU driver/shader/weights bug worth investigating. \
Use --no-gpu to score on the CPU MoE, or --require-gpu to hard-fail next time."
        );
    }
}

fn moe_numeric_divergence_degrade(reason: &str) {
    let no_gpu = super::gpu_disabled_by_policy();
    let require_gpu = super::gpu_required_by_policy();
    if require_gpu {
        crate::process_exit::require_gpu_unmet(format!(
            "--require-gpu requested but the GPU MoE failed the CPU parity probe ({reason}). \
Refusing to silently score confidence on the CPU MoE.",
        ));
    }
    if no_gpu {
        return;
    }
    tracing::error!(
        reason,
        "GPU MoE parity probe diverged from CPU MoE; scoring batches on CPU"
    );
    if !MOE_NUMERIC_DIVERGENCE_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "keyhog: GPU MoE parity probe failed ({reason}); confidence batches are scored on \
the CPU MoE instead. Use --require-gpu to hard-fail until the GPU shader/driver/weights are fixed.",
        );
    }
}

/// Score a batch of feature vectors on GPU. Returns one score per input.
///
/// # Examples
///
/// ```rust,ignore
/// use keyhog_scanner::gpu::batch_score_features;
/// let _ = batch_score_features(&[[0.0; 42]], std::time::Duration::from_millis(30_000));
/// ```
pub(crate) fn batch_score_features(
    features: &[[f32; INPUT_DIM]],
    readback_timeout: Duration,
) -> Option<Vec<f64>> {
    if features.len() < GPU_BATCH_THRESHOLD {
        return None; // Too small for GPU, caller should use CPU
    }

    // Honor the resolved GPU runtime policy BEFORE touching `get_gpu()` /
    // `init_gpu()`, exactly as `gpu_probe()` does. Without this gate a
    // `--no-gpu` scan that reaches a large MoE batch still triggers the wgpu
    // adapter probe inside `init_gpu()` — which the team's own `gpu_probe`
    // comment notes "can block for minutes on broken driver stacks." Policy
    // disabled => return None so the caller scores this batch on CPU (identical
    // scores), and the adapter is never probed. Mirrors the gpu_probe guard so
    // the disabled-GPU path can never drift back into an unconditional probe.
    if super::gpu_disabled_by_policy() {
        return None;
    }

    // The GPU compute shader MUST reproduce the CPU MoE (`ml_scorer::score_features`
    // — the reference every confidence floor is tuned and benched against) within
    // tolerance. A shader miscompile, weights-packing mismatch, or driver bug that
    // makes the GPU score DIVERGE from CPU would silently change findings vs the
    // CPU/SIMD path (a Law-10 recall bug: a real secret the CPU scores ~1.0 gets a
    // GPU ~0.0 and is dropped) AND make autoroute calibration nondeterministic (the
    // readback-timeout degrade swaps the broken GPU score for the correct CPU one
    // between trials, flipping a floor-straddling finding). Probe ONCE per process;
    // on divergence FAIL CLOSED — return None so every batch scores on the correct,
    // deterministic CPU path, loudly, instead of trusting a broken accelerator.
    if !gpu_moe_numerically_trustworthy(readback_timeout) {
        return None;
    }

    dispatch_moe_batch(features, readback_timeout)
}

/// Raw GPU MoE dispatch: upload features, run the compute shader, read back and
/// sanitize the per-candidate scores. Split out of [`batch_score_features`] so
/// the parity self-test ([`gpu_moe_parity_max_divergence`]) can exercise the
/// exact production dispatch without re-entering the trustworthiness gate (which
/// would recurse). Callers own the size/policy/trust guards.
fn dispatch_moe_batch(
    features: &[[f32; INPUT_DIM]],
    readback_timeout: Duration,
) -> Option<Vec<f64>> {
    let gpu = get_gpu()?;
    let batch_size = features.len();
    let device = gpu.device();
    let queue = gpu.queue();

    // `&[[f32; INPUT_DIM]]` is already a contiguous `f32` block, so reinterpret
    // it in place rather than copying every feature into a fresh `Vec<f32>`
    // (the old `flat_map().collect()` allocated batch_size * INPUT_DIM * 4 bytes
    // per GPU dispatch for no reason). `[f32; N]` is `Pod`, so the cast is sound.
    let input_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("input"),
        contents: bytemuck::cast_slice(features),
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
        let _ = sender.send(result); // LAW10: map-async callback; receiver-dropped => the await already timed out/abandoned (handled below), nothing to deliver; recall-irrelevant
    });
    let timeout = readback_timeout;
    let deadline = Instant::now() + timeout;
    let mut backoff = ReadbackWaitBackoff::new();
    let map_recv = loop {
        match receiver.try_recv() {
            Ok(result) => break result,
            Err(TryRecvError::Disconnected) => {
                tracing::warn!(
                    "GPU MoE staging-buffer callback disconnected; falling back to CPU MoE for this scan"
                );
                moe_runtime_degrade("staging-buffer callback disconnected");
                return None;
            }
            Err(TryRecvError::Empty) => {}
        }

        if Instant::now() >= deadline {
            tracing::warn!(
                ?timeout,
                "GPU MoE staging-buffer readback timed out; falling back to CPU MoE for this scan"
            );
            moe_runtime_degrade("staging-buffer readback timed out");
            return None;
        }

        if let Err(error) = device.poll(wgpu::PollType::Poll) {
            tracing::warn!(
                ?error,
                "GPU MoE device.poll() failed; falling back to CPU MoE for this scan"
            );
            moe_runtime_degrade("device.poll() failed");
            return None;
        }

        if let Ok(result) = receiver.try_recv() {
            // LAW10: empty try_recv only means the GPU callback is still pending; timeout/device-error branches below stay loud.
            break result;
        }

        backoff.wait(deadline.saturating_duration_since(Instant::now()));
    };
    if let Err(error) = map_recv {
        tracing::warn!(
            ?error,
            "GPU MoE staging-buffer map_async failed; falling back to CPU MoE for this scan"
        );
        moe_runtime_degrade("staging-buffer map_async failed");
        return None;
    }
    let data = slice.get_mapped_range();
    let scores: &[f32] = bytemuck::cast_slice(&data);
    if scores.len() != batch_size {
        tracing::warn!(
            expected = batch_size,
            actual = scores.len(),
            "GPU MoE score count mismatch; routing batch to CPU MoE for this scan"
        );
        moe_runtime_degrade("score count mismatch");
        drop(data);
        staging_buf.unmap();
        return None;
    }
    // kimi-confidence audit: a GPU driver bug, shader miscompile, or
    // adversarial weights buffer can produce NaN/Inf in the f32
    // staging buffer. The previous flow forwarded those values
    // verbatim into the confidence pipeline, where `.clamp(0, 1)`
    // does NOT sanitize NaN (Rust f64::clamp leaves NaN as NaN),
    // and the NaN propagated all the way to SARIF `confidence: NaN`.
    // Sanitize at the GPU boundary so every downstream consumer
    // sees a finite probability in [0, 1].
    let mut nonfinite = 0usize;
    let result: Vec<f64> = scores
        .iter()
        .map(|&s| {
            let v = s as f64;
            if v.is_finite() {
                v.clamp(0.0, 1.0)
            } else {
                // NaN or +/-Inf: a GPU correctness fault. Sanitize to the neutral
                // 0.5 sentinel so the heuristic score dominates the downstream
                // blend (the finding still surfaces on the rule's own score), but
                // COUNT it so the operator is told loudly below rather than the
                // garbage being silently swallowed (Law 10).
                nonfinite += 1;
                0.5
            }
        })
        .collect();
    drop(data);
    staging_buf.unmap();

    // Law 10: never sanitize NaN/Inf silently. If the GPU emitted any non-finite
    // score, surface it (hard-fail under --require-gpu, one loud line
    // otherwise) so a driver/shader/weights bug is visible, not invisible.
    if nonfinite > 0 {
        moe_nonfinite_degrade(nonfinite, result.len());
    }

    Some(result)
}

/// Maximum tolerated GPU-vs-CPU MoE score divergence on the parity probe. The
/// GPU shader is a re-implementation of `ml_scorer::score_features`; both compute
/// the same f32 MoE, so a faithful shader matches the CPU reference to well within
/// this bound (the only legitimate gap is `exp()`/rounding differences in the
/// softmax). A divergence above this is a shader/weights/driver fault — NOT
/// acceptable precision noise — because the GPU score then gates findings
/// differently from the CPU/SIMD path.
pub(crate) const GPU_MOE_PARITY_TOLERANCE: f64 = 0.01;

/// Probe inputs for the GPU-vs-CPU MoE parity self-test. A deterministic spread
/// that MUST include high-confidence real secrets (so a GPU that collapses every
/// score toward 0 — the observed failure mode — diverges visibly from the CPU
/// reference) alongside obvious non-secrets (so a GPU stuck near 1.0 is caught
/// too). Cycled to `GPU_BATCH_THRESHOLD` so the probe drives the exact production
/// dispatch path; sub-threshold batches never reach the GPU.
fn gpu_moe_parity_probe_features() -> Vec<[f32; INPUT_DIM]> {
    const PROBES: &[(&str, &str)] = &[
        (
            "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
            "stripe_secret_key = \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"",
        ),
        (
            "AKIAQYLPMN5HFIQR7XYA",
            "aws_access_key_id = \"AKIAQYLPMN5HFIQR7XYA\"",
        ),
        (
            "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",
            "github_token = \"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\"",
        ),
        (
            "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "aws_secret_access_key = \"wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY\"",
        ),
        (
            "xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx",
            "slack_bot_token = \"xoxb-1234567890-1234567890-AbCdEfGhIjKlMnOpQrStUvWx\"",
        ),
        ("example", "display_name = \"example\""),
        ("localhost", "db_host = \"localhost\""),
        ("true", "feature_enabled = true"),
    ];
    (0..GPU_BATCH_THRESHOLD)
        .map(|i| {
            let (text, ctx) = PROBES[i % PROBES.len()];
            crate::ml_scorer::compute_features_with_config(text, ctx, &[], &[], &[], &[])
        })
        .collect()
}

/// Run the production GPU MoE dispatch on the parity probe and return the maximum
/// absolute divergence from the CPU MoE reference across all probe inputs, or an
/// error if the GPU could not be dispatched at all. Single source of truth for
/// "does the GPU MoE reproduce the CPU MoE on this device?" — shared by the
/// runtime trust gate and `gpu_self_test` (so doctor reports the same verdict the
/// scan path enforces).
pub(crate) fn gpu_moe_parity_max_divergence(readback_timeout: Duration) -> Result<f64, String> {
    let probe = gpu_moe_parity_probe_features();
    let gpu_scores = dispatch_moe_batch(&probe, readback_timeout)
        .ok_or_else(|| "GPU MoE dispatch produced no result for the parity probe".to_string())?;
    if gpu_scores.len() != probe.len() {
        return Err(format!(
            "GPU MoE parity probe returned {} scores for {} inputs",
            gpu_scores.len(),
            probe.len()
        ));
    }
    let mut max_abs = 0.0f64;
    for (gpu, feat) in gpu_scores.iter().zip(probe.iter()) {
        let cpu = crate::ml_scorer::score_features(feat);
        max_abs = max_abs.max((gpu - cpu).abs());
    }
    Ok(max_abs)
}

/// One-time, process-wide GPU MoE trust gate. The GPU MoE is trusted for scoring
/// ONLY if it reproduces the CPU MoE within [`GPU_MOE_PARITY_TOLERANCE`] on the
/// parity probe. On divergence (or dispatch failure) it is permanently distrusted
/// for the process and every batch falls to the correct, deterministic CPU path,
/// with one loud line. Cached so the probe runs at most once.
fn gpu_moe_numerically_trustworthy(readback_timeout: Duration) -> bool {
    *MOE_NUMERIC_TRUST.get_or_init(|| match gpu_moe_parity_max_divergence(readback_timeout) {
        Ok(max_abs) if max_abs <= GPU_MOE_PARITY_TOLERANCE => {
            tracing::info!(
                target: "keyhog::gpu",
                max_abs_diff = max_abs,
                tolerance = GPU_MOE_PARITY_TOLERANCE,
                "GPU MoE parity probe matched CPU MoE"
            );
            true
        }
        Ok(max_abs) => {
            moe_numeric_divergence_degrade(&format!(
                "max_abs_diff={max_abs:.6}, tolerance={GPU_MOE_PARITY_TOLERANCE:.6}"
            ));
            false
        }
        Err(reason) => {
            moe_numeric_divergence_degrade(&reason);
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_moe_parity_probe_covers_dispatch_threshold_with_varied_features() {
        let features = gpu_moe_parity_probe_features();

        assert_eq!(
            features.len(),
            GPU_BATCH_THRESHOLD,
            "GPU MoE parity probe must exercise the production dispatch threshold"
        );
        assert!(
            features.iter().flatten().any(|value| *value > 0.0)
                && features.windows(2).any(|pair| pair[0] != pair[1]),
            "GPU MoE parity probe must include varied real feature vectors, not all-zero repeats"
        );
        let cpu_scores: Vec<f64> = features
            .iter()
            .map(crate::ml_scorer::score_features)
            .collect();
        assert!(
            cpu_scores.iter().copied().all(f64::is_finite),
            "CPU MoE scores for the GPU parity probe must be finite"
        );
        assert!(
            cpu_scores.windows(2).any(|pair| pair[0] != pair[1]),
            "GPU MoE parity probe must exercise distinct CPU MoE outputs"
        );
    }
}
