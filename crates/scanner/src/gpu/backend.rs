//! MoE GPU inference backend (wgpu compute).

use super::gpu_shader::moe_shader;

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

// Host-side feature width for GPU buffer sizing: the MoE input dimension is the
// ML feature-vector length. This and the WGSL shader both derive from the single
// owner `model_arch::INPUT_DIM` (the shader via `gpu_shader::moe_shader`'s
// generated header), so host allocation and device layout cannot drift.
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

/// Why GPU MoE init failed, carrying whether a *real* (non-software) GPU adapter
/// was physically acquired. The failure path in [`get_gpu`] runs while BOTH the
/// `GPU` and (transitively) `HW_PROBE` OnceLocks are mid-init, so it cannot ask
/// `probe_hardware()`/`get_gpu()` "is a GPU present?", that re-enters an
/// initializing OnceLock and DEADLOCKS the scan thread, and is circular anyway
/// (`HardwareCaps::gpu_available` is itself `get_gpu().is_some()`). `init_gpu`
/// therefore reports adapter presence directly, in-band, so the operator notice
/// is decided without touching either lock.
struct GpuInitError {
    /// True only when a non-software GPU adapter was acquired but a LATER MoE
    /// init step failed, the actionable "GPU present but unusable" case. False
    /// when no adapter exists or it is a software renderer (the expected quiet
    /// CPU-only majority: laptops, containers, CI with llvmpipe/lavapipe).
    adapter_present: bool,
    detail: Box<dyn std::error::Error + Send + Sync>,
}

impl GpuInitError {
    /// No usable hardware adapter: nothing was acquired, or it was a software
    /// renderer. Stays quiet (this is the ordinary CPU-only path).
    fn no_adapter(detail: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            adapter_present: false,
            detail: detail.into(),
        }
    }

    /// A real GPU adapter was acquired but the MoE compute path could not be
    /// built on it (the actionable driver/limits fault worth a loud notice).
    fn adapter_unusable(detail: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            adapter_present: true,
            detail: detail.into(),
        }
    }
}

/// Operator-facing outcome of a GPU MoE init failure. A PURE function of the
/// structured error + the already-resolved GPU policy so it touches NO OnceLock
/// (the deadlock this whole split fixes) and is unit-testable off the GPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GpuInitFailureAction {
    /// `--require-gpu`: hard-fail (exit 12). Acquisition/compute failed but the
    /// operator forbade a CPU degrade.
    HardFail,
    /// A real GPU is present but unusable: print the loud CPU-fallback notice.
    WarnCpuFallback,
    /// No usable adapter, or `--no-gpu`: stay quiet (the expected CPU path).
    Quiet,
}

/// Decide the init-failure action from the error + resolved policy. Callers pass
/// the ALREADY-CHECKED policy booleans (never re-derived here) so this never
/// re-enters `gpu_disabled_by_policy`/`get_gpu`/`probe_hardware`.
fn classify_gpu_init_failure(
    err: &GpuInitError,
    disabled: bool,
    required: bool,
) -> GpuInitFailureAction {
    if required {
        return GpuInitFailureAction::HardFail;
    }
    if !disabled && err.adapter_present {
        return GpuInitFailureAction::WarnCpuFallback;
    }
    GpuInitFailureAction::Quiet
}

/// Emit the correct operator notice for a GPU MoE init failure and return `None`.
/// Split out of [`get_gpu`]'s `Err` arm so the failure path is exercised by tests
/// off the GPU. MUST NOT call `probe_hardware()` or `get_gpu()`: both are mid-init
/// on this path and re-entering either OnceLock deadlocks (the bug this fixes).
fn on_gpu_init_failed(err: &GpuInitError, disabled: bool, required: bool) -> Option<GpuContext> {
    match classify_gpu_init_failure(err, disabled, required) {
        GpuInitFailureAction::HardFail => {
            crate::process_exit::require_gpu_unmet(format!(
                "--require-gpu requested but GPU MoE init failed: {}",
                err.detail
            ));
        }
        GpuInitFailureAction::WarnCpuFallback => {
            eprintln!(
                "keyhog: a GPU was detected but could not be initialized; using the \
CPU/SIMD scan path. Use --no-gpu to silence this, or --require-gpu to fail instead."
            );
        }
        GpuInitFailureAction::Quiet => {}
    }
    // LAW10: NOT the sole surface, the degrade is loud above (hard-fail under
    // --require-gpu, or the eprintln when a real GPU is present) + the
    // MOE_RUNTIME_DEGRADE_WARNED once-guard; CPU MoE is recall-preserving. This
    // debug line is supplementary detail only.
    tracing::debug!("GPU MoE init failed, using CPU fallback: {}", err.detail);
    None
}

fn init_gpu() -> Result<GpuContext, GpuInitError> {
    // Reuse the vyre WgpuBackend's device instead of creating a second one.
    // This shares the adapter probe, device request, and queue with the
    // literal-set GPU scanner - halving init time and memory.
    let vyre_backend = vyre_driver_wgpu::WgpuBackend::shared()
        .map_err(|e| GpuInitError::no_adapter(format!("vyre WgpuBackend unavailable: {e}")))?;

    let adapter_info = vyre_backend.adapter_info().clone();

    // Reject software fallback adapters. Not a real GPU, so no adapter is
    // "present" for notice purposes (keeps CI/llvmpipe hosts quiet).
    if adapter_info.device_type == wgpu::DeviceType::Cpu {
        return Err(GpuInitError::no_adapter(format!(
            "GPU adapter is a software fallback ({} on {:?}); refusing to use",
            adapter_info.name, adapter_info.backend
        )));
    }

    let device_limits = vyre_backend.device_limits().clone();
    let dq = vyre_backend.device_queue();

    // A real adapter was acquired. Prove it can actually BIND the MoE weights as
    // a storage buffer before returning a context whose first dispatch would trip
    // a `max_storage_buffer_binding_size` validation error deep in a live scan.
    // A constrained adapter (downlevel/mobile limits) is "present but unusable"
    // fail closed loudly here, not with a mid-scan wgpu panic.
    let all_weights = crate::ml_scorer::ml_weights::all_weights_slice();
    let weights_bytes = std::mem::size_of_val(all_weights) as u64;
    let max_storage_binding = u64::from(device_limits.max_storage_buffer_binding_size);
    if weights_bytes > max_storage_binding {
        return Err(GpuInitError::adapter_unusable(format!(
            "GPU adapter {} exposes max_storage_buffer_binding_size={max_storage_binding} B, \
too small for the {weights_bytes} B MoE weights buffer",
            adapter_info.name
        )));
    }

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
        source: wgpu::ShaderSource::Wgsl(moe_shader().into()),
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

    // Upload weights once (bound-checked against the adapter's storage limit above).
    let weights_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("weights"),
        contents: bytemuck::cast_slice(all_weights),
        usage: wgpu::BufferUsages::STORAGE,
    });

    Ok(GpuContext {
        device_queue: dq,
        adapter_info,
        device_limits,
        pipeline,
        weights_buf,
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
        // No silent fallbacks: if a real GPU is present but unusable the operator
        // is told loudly. CRITICAL: resolve policy from the AtomicU8 readers (no
        // OnceLock) and let `on_gpu_init_failed` decide from the error's in-band
        // `adapter_present` flag: NEVER call `probe_hardware()`/`get_gpu()` here.
        // Both are mid-init on this path; re-entering either deadlocks the scan
        // thread on GPU-init failure (the bug this fixes), and the old
        // `probe_hardware().gpu_available` check was circular anyway.
        Err(err) => on_gpu_init_failed(
            &err,
            super::gpu_disabled_by_policy(),
            super::gpu_required_by_policy(),
        ),
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
/// posture exactly so the MoE path is coherent with the literal-set GPU
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
pub(super) fn moe_runtime_degrade(reason: &str) {
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
/// non-finite probability is not a routing choice, it can only come from a GPU
/// driver bug, a shader miscompile, or a corrupt weights buffer, i.e. a GPU
/// CORRECTNESS fault. Each bad value is sanitized to a neutral `0.5` at the GPU
/// boundary (so downstream `confidence` math never sees NaN and the finding
/// still surfaces on its heuristic score), but Law 10 forbids doing that
/// silently: the operator must be told their GPU produced garbage. Gating
/// mirrors [`moe_runtime_degrade`], hard-fail under `--require-gpu` (a GPU
/// emitting NaN is exactly the malfunction that flag exists to catch), one loud
/// stderr line on an ordinary run, and quiet under `--no-gpu` where the CPU MoE
/// is the intended path anyway.
fn moe_nonfinite_degrade(nonfinite: usize, total: usize) {
    let no_gpu = super::gpu_disabled_by_policy();
    let require_gpu = super::gpu_required_by_policy();
    if require_gpu {
        crate::process_exit::require_gpu_unmet(format!(
            "--require-gpu requested but the GPU MoE returned {nonfinite}/{total} \
non-finite (NaN/Inf) confidence score(s), a GPU driver/shader/weights malfunction. \
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
/// // The feature width is `model_arch::INPUT_DIM` (43 after DET-1), never a
/// // bare literal; a wrong-width buffer is rejected by the GPU host layout.
/// let _ = batch_score_features(&[[0.0f32; 43]], std::time::Duration::from_millis(30_000));
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
    // adapter probe inside `init_gpu()`: which the team's own `gpu_probe`
    // comment notes "can block for minutes on broken driver stacks." Policy
    // disabled => return None so the caller scores this batch on CPU (identical
    // scores), and the adapter is never probed. Mirrors the gpu_probe guard so
    // the disabled-GPU path can never drift back into an unconditional probe.
    if super::gpu_disabled_by_policy() {
        return None;
    }

    // The GPU compute shader MUST reproduce the CPU MoE (`ml_scorer::score_features`
    //: the reference every confidence floor is tuned and benched against) within
    // tolerance. A shader miscompile, weights-packing mismatch, or driver bug that
    // makes the GPU score DIVERGE from CPU would silently change findings vs the
    // CPU/SIMD path (a Law-10 recall bug: a real secret the CPU scores ~1.0 gets a
    // GPU ~0.0 and is dropped) AND make autoroute calibration nondeterministic (the
    // readback-timeout degrade swaps the broken GPU score for the correct CPU one
    // between trials, flipping a floor-straddling finding). Probe ONCE per process;
    // on divergence FAIL CLOSED, return None so every batch scores on the correct,
    // deterministic CPU path, loudly, instead of trusting a broken accelerator.
    if !gpu_moe_numerically_trustworthy(readback_timeout) {
        return None;
    }

    dispatch_moe_batch(features, readback_timeout)
}

/// Global buffer pool for MoE dispatch. Eliminates per-dispatch buffer
/// allocation by reusing input/output/staging/params buffers across dispatches.
/// Buffers grow to the largest batch size seen (wgpu buffers are immutable in
/// size, so we keep the high-water mark).
///
/// Uses a global `Mutex<Vec<MoeBufferSet>>` instead of thread-local storage
/// because `wgpu::Buffer::drop` accesses wgpu's own thread-local state, which
/// panics during thread destruction. A global pool keeps buffers alive for the
/// process lifetime. Contention is minimal: the mutex is held only during
/// checkout/checkin (a Vec pop/push), not during GPU compute or readback.
struct MoeBufferPool {
    spare: Vec<MoeBufferSet>,
}

/// A checked-out set of MoE dispatch buffers. Returned to the pool on drop
/// via [`MoeBufferPool::checkin`]. The params buffer is NOT pooled, it is
/// 16 bytes and created fresh per dispatch to prevent concurrent batch_size
/// races (the params buffer is the one shared mutable GPU state that must
/// remain per-dispatch).
struct MoeBufferSet {
    input: wgpu::Buffer,
    output: wgpu::Buffer,
    staging: wgpu::Buffer,
    /// The batch_size this set was allocated for. Used to verify the set
    /// is large enough before reuse (wgpu buffers are immutable in size).
    alloc_batch_size: usize,
}

impl MoeBufferPool {
    fn new() -> Self {
        Self { spare: Vec::new() }
    }

    /// Try to pop a spare set from the pool that is large enough for
    /// `batch_size`. Returns None if the pool is empty or all spare sets
    /// are too small (in which case small sets are discarded).
    fn try_checkout(&mut self, batch_size: usize) -> Option<MoeBufferSet> {
        // Find a spare set large enough. Since all buffers grow to the
        // high-water mark, the first one is usually big enough.
        while let Some(set) = self.spare.pop() {
            if set.alloc_batch_size >= batch_size {
                return Some(set);
            }
            // Too small (discard. The larger allocation will replace it).
        }
        None
    }

    fn checkin(&mut self, set: MoeBufferSet) {
        // Keep only the largest set to bound memory. If the incoming set
        // is smaller than an existing spare, discard the incoming set
        // (it will be reallocated at the larger size next time).
        if let Some(existing) = self.spare.last() {
            if existing.alloc_batch_size >= set.alloc_batch_size {
                // Existing spare is at least as large (drop the incoming).
                return;
            }
        }
        self.spare.push(set);
    }
}

static MOE_BUFFER_POOL: std::sync::LazyLock<std::sync::Mutex<MoeBufferPool>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(MoeBufferPool::new()));

fn return_moe_buffers(bufs: MoeBufferSet) {
    match MOE_BUFFER_POOL.lock() {
        Ok(mut pool) => pool.checkin(bufs),
        Err(error) => {
            tracing::warn!(
                %error,
                "GPU MoE buffer pool is poisoned; dropping this reusable buffer set"
            );
        }
    }
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
    let output_size = (batch_size * std::mem::size_of::<f32>()) as u64;

    // Checkout pooled buffers (reused across dispatches, eliminating
    // per-dispatch buffer allocation, the dominant non-GPU overhead for
    // large MoE batches in coalesced scanning). The global mutex is held
    // only for the pop/push, not during GPU compute or readback.
    let bufs = {
        let mut pool = MOE_BUFFER_POOL.lock().unwrap();
        pool.try_checkout(batch_size)
    };
    let bufs = match bufs {
        Some(set) => set,
        None => {
            // No spare set or too small, allocate fresh. The input buffer
            // uses COPY_DST so we can write_buffer into it for reuse.
            let input_bytes = (batch_size * INPUT_DIM * std::mem::size_of::<f32>()) as u64;
            let output_bytes = (batch_size * std::mem::size_of::<f32>()) as u64;
            MoeBufferSet {
                input: device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("moe_input_pooled"),
                    size: input_bytes,
                    usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                }),
                output: device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("moe_output_pooled"),
                    size: output_bytes,
                    usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                    mapped_at_creation: false,
                }),
                staging: device.create_buffer(&wgpu::BufferDescriptor {
                    label: Some("moe_staging_pooled"),
                    size: output_bytes,
                    usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                    mapped_at_creation: false,
                }),
                alloc_batch_size: batch_size,
            }
        }
    };

    // Per-dispatch params buffer (NOT pooled). Per-chunk ML scoring runs
    // dispatch_moe_batch CONCURRENTLY across chunks (the rayon par_iter in
    // scan_coalesced). A single shared params buffer written by every
    // concurrent dispatch is a data race (Law 7): dispatch A writes
    // batch_size 136, dispatch B overwrites it with 72 before A's compute
    // reads it, so A processes only 72 of its 136 candidates and the tail
    // 64 outputs are never written, read back as 0.0 and dropped below the
    // confidence floor. Each dispatch owning its params buffer removes the
    // only shared mutable GPU state across concurrent MoE batches.
    let params = GpuParams {
        batch_size: batch_size as u32,
        _pad: [0; 3],
    };
    let params_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("moe_params"),
        contents: bytemuck::bytes_of(&params),
        usage: wgpu::BufferUsages::UNIFORM,
    });

    // Upload input features via queue.write_buffer (pooled buffer is
    // COPY_DST). `&[[f32; INPUT_DIM]]` is already a contiguous f32 block,
    // so reinterpret in place (no flatten allocation).
    queue.write_buffer(&bufs.input, 0, bytemuck::cast_slice(features));

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
                resource: bufs.input.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 2,
                resource: bufs.output.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 3,
                resource: params_buf.as_entire_binding(),
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
        let workgroups =
            (batch_size as u32).div_ceil(crate::ml_scorer::model_arch::WORKGROUP_SIZE as u32);
        pass.dispatch_workgroups(workgroups, 1, 1);
    }

    encoder.copy_buffer_to_buffer(&bufs.output, 0, &bufs.staging, 0, output_size);
    queue.submit(std::iter::once(encoder.finish()));

    // Read back results, slice only the portion we copied (the pooled
    // staging buffer may be larger than this batch if it was allocated
    // for a previous larger batch).
    let slice = bufs.staging.slice(..output_size);
    let (sender, receiver) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |result| {
        if sender.send(result).is_err() {
            tracing::warn!(
                "GPU MoE staging callback completed after its receiver closed; the caller already surfaced a readback failure"
            );
        }
    });
    let timeout = readback_timeout;
    let deadline = Instant::now() + timeout;
    let mut backoff = ReadbackWaitBackoff::new();
    let map_recv = loop {
        match receiver.try_recv() {
            Ok(result) => break result,
            Err(TryRecvError::Disconnected) => {
                tracing::warn!(
                    "GPU MoE staging-buffer callback disconnected; GPU MoE disabled and scoring uses CPU MoE for this scan"
                );
                moe_runtime_degrade("staging-buffer callback disconnected");
                // Do not pool a staging buffer whose map lifecycle did not
                // complete successfully; dropping the set prevents a later
                // dispatch from reusing unknown mapping state.
                return None;
            }
            Err(TryRecvError::Empty) => {}
        }

        if Instant::now() >= deadline {
            tracing::warn!(
                ?timeout,
                "GPU MoE staging-buffer readback timed out; GPU MoE disabled and scoring uses CPU MoE for this scan"
            );
            moe_runtime_degrade("staging-buffer readback timed out");
            // The callback may still complete after this deadline. Dropping the
            // set is safe; pooling it while map_async is pending is not.
            return None;
        }

        if let Err(error) = device.poll(wgpu::PollType::Poll) {
            tracing::warn!(
                ?error,
                "GPU MoE device.poll() failed; GPU MoE disabled and scoring uses CPU MoE for this scan"
            );
            moe_runtime_degrade("device.poll() failed");
            return None;
        }

        match receiver.try_recv() {
            Ok(result) => break result,
            Err(TryRecvError::Disconnected) => {
                tracing::warn!(
                    "GPU MoE staging-buffer callback disconnected after device polling; GPU MoE disabled and scoring uses CPU MoE for this scan"
                );
                moe_runtime_degrade("staging-buffer callback disconnected after device poll");
                return None;
            }
            Err(TryRecvError::Empty) => {}
        }

        backoff.wait(deadline.saturating_duration_since(Instant::now()));
    };
    if let Err(error) = map_recv {
        tracing::warn!(
            ?error,
            "GPU MoE staging-buffer map_async failed; GPU MoE disabled and scoring uses CPU MoE for this scan"
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
        bufs.staging.unmap();
        return_moe_buffers(bufs);
        return None;
    }
    let mut nonfinite = 0usize;
    let result: Vec<f64> = scores
        .iter()
        .map(|&s| {
            let v = s as f64;
            if v.is_finite() {
                v.clamp(0.0, 1.0)
            } else {
                nonfinite += 1;
                0.5
            }
        })
        .collect();
    drop(data);
    bufs.staging.unmap();

    // Return buffers to pool for reuse by the next dispatch.
    return_moe_buffers(bufs);

    if nonfinite > 0 {
        moe_nonfinite_degrade(nonfinite, result.len());
    }

    Some(result)
}

/// Maximum tolerated GPU-vs-CPU MoE score divergence on the parity probe. The
/// GPU shader is a re-implementation of `ml_scorer::score_features`; both compute
/// the same f32 MoE, so a faithful shader matches the CPU reference to well within
/// this bound (the only legitimate gap is `exp()`/rounding differences in the
/// softmax). A divergence above this is a shader/weights/driver fault. NOT
/// acceptable precision noise, because the GPU score then gates findings
/// differently from the CPU/SIMD path.
pub(crate) const GPU_MOE_PARITY_TOLERANCE: f64 = 0.01;

/// Probe inputs for the GPU-vs-CPU MoE parity self-test. A deterministic spread
/// that MUST include high-confidence real secrets (so a GPU that collapses every
/// score toward 0, the observed failure mode, diverges visibly from the CPU
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
        // DET-1: a probe whose context names a specific service from the vocab so
        // feature 42 (SERVICE_CONTEXT) is exercised by at least one probe vector.
        (
            "Z9x8c7v6b5n4m3q2w1e0PkR",
            "zendesk_api_token = \"Z9x8c7v6b5n4m3q2w1e0PkR\"",
        ),
    ];
    // Representative keyword activators so the probe EXERCISES the config-driven
    // feature slots that empty lists left permanently 0.0, feature 12/13 (known-
    // prefix present/length), 17 (secret keyword), 18 (test keyword), 20
    // (placeholder keyword). A GPU/CPU divergence in any of those WGSL feature
    // slots is invisible to the parity gate unless some probe vector sets them
    // non-zero. These are probe FIXTURES (coverage), NOT a detector keyword source:
    // the CPU reference and the GPU dispatch score the SAME feature vectors, so
    // enriching them cannot bias the divergence comparison, only widen its reach.
    let known_prefixes: Vec<String> = ["AKIA", "sk_live_", "ghp_", "xoxb-", "sk-"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let secret_keywords: Vec<String> = ["secret", "token", "key", "password"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let test_keywords: Vec<String> = ["test", "example"].iter().map(|s| s.to_string()).collect();
    let placeholder_keywords: Vec<String> = ["example", "changeme"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    (0..GPU_BATCH_THRESHOLD)
        .map(|i| {
            let (text, ctx) = PROBES[i % PROBES.len()];
            crate::ml_scorer::compute_features_with_config(
                text,
                ctx,
                &known_prefixes,
                &secret_keywords,
                &test_keywords,
                &placeholder_keywords,
            )
        })
        .collect()
}

/// Run the production GPU MoE dispatch on the parity probe and return the maximum
/// absolute divergence from the CPU MoE reference across all probe inputs, or an
/// error if the GPU could not be dispatched at all. Single source of truth for
/// "does the GPU MoE reproduce the CPU MoE on this device?", shared by the
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
    fn gpu_moe_dispatch_matches_cpu_on_every_repeat() {
        // GPU/CPU parity guard: the GPU MoE compute shader must reproduce the CPU
        // MoE (`ml_scorer::score_features`, the reference every confidence floor is
        // tuned and benched against) on EVERY dispatch of a >=GPU_BATCH_THRESHOLD
        // batch, with no spurious 0.0 scores. This runs dispatches ONE AT A TIME,
        // so it isolates a genuinely broken shader/weights/driver from the
        // concurrent params-race regression below (which the autoroute-calibration
        // abort actually turned out to be) and proves the dispatch is stable across
        // many repeats.
        if super::super::gpu_disabled_by_policy() || get_gpu().is_none() {
            eprintln!("no usable GPU adapter; skipping GPU MoE dispatch regression");
            return;
        }
        let probe = gpu_moe_parity_probe_features();
        assert!(probe.len() >= GPU_BATCH_THRESHOLD);
        let cpu: Vec<f64> = probe.iter().map(crate::ml_scorer::score_features).collect();
        let timeout = Duration::from_millis(30_000);
        for rep in 0..128 {
            let gpu = dispatch_moe_batch(&probe, timeout)
                .unwrap_or_else(|| panic!("GPU MoE dispatch {rep} returned no result")); // LAW10: test-only proof panic, not a fallback; a missing dispatch result is the failure under test
            assert_eq!(
                gpu.len(),
                probe.len(),
                "dispatch {rep}: score count mismatch"
            );
            let zeroed = gpu
                .iter()
                .zip(cpu.iter())
                .filter(|(g, c)| **g == 0.0 && **c > 0.01)
                .count();
            let worst = gpu
                .iter()
                .zip(cpu.iter())
                .map(|(g, c)| (g - c).abs())
                .fold(0.0f64, f64::max);
            assert_eq!(
                zeroed, 0,
                "dispatch {rep}: {zeroed} candidate(s) read back 0.0 while the CPU MoE scores them >0.01 \
                 (the GPU MoE must never emit a spurious 0.0 for a real candidate)"
            );
            assert!(
                worst <= GPU_MOE_PARITY_TOLERANCE,
                "dispatch {rep}: GPU MoE diverged from CPU MoE by {worst:.6} (tolerance {GPU_MOE_PARITY_TOLERANCE})"
            );
        }
    }

    #[test]
    fn gpu_moe_dispatch_is_race_free_under_concurrent_batches() {
        // Regression for the shared `GpuContext` params-buffer data race that aborted
        // `install.sh --calibrate` ("inconsistent calibration results"): per-chunk
        // ML scoring dispatches MoE batches concurrently (rayon par_iter in
        // scan_coalesced). A single shared uniform written by every dispatch let
        // one dispatch clobber another's batch_size, so the larger batch processed
        // too few candidates and its tail read back 0.0, dropping a
        // floor-straddling finding so the SIMD reference flipped between trials.
        // The diagnostic signature was unmistakable: on the demo a batch of 136
        // intermittently read back EXACTLY 64 zeros == 136 - 72, the other
        // concurrent batch size (NOT a coincidental workgroup multiple). Each
        // dispatch now owns its params buffer. Two distinct batch sizes are
        // dispatched from many threads in a tight loop; assert every concurrent
        // dispatch reproduces ITS OWN CPU reference with zero spurious zeros.
        if super::super::gpu_disabled_by_policy() || get_gpu().is_none() {
            eprintln!("no usable GPU adapter; skipping concurrent GPU MoE regression");
            return;
        }
        use std::sync::Arc;
        let small: Vec<[f32; INPUT_DIM]> = gpu_moe_parity_probe_features();
        let mut large = small.clone();
        large.extend(small.iter().copied()); // 2x threshold: a different batch size
        let cpu_small: Vec<f64> = small.iter().map(crate::ml_scorer::score_features).collect();
        let cpu_large: Vec<f64> = large.iter().map(crate::ml_scorer::score_features).collect();
        let small = Arc::new(small);
        let large = Arc::new(large);
        std::thread::scope(|scope| {
            for thread_idx in 0..16u32 {
                let small = Arc::clone(&small);
                let large = Arc::clone(&large);
                let cpu_small = &cpu_small;
                let cpu_large = &cpu_large;
                scope.spawn(move || {
                    let timeout = Duration::from_millis(30_000);
                    for _ in 0..8 {
                        let (feat, cpu): (&[[f32; INPUT_DIM]], &[f64]) = if thread_idx % 2 == 0 {
                            (&small, cpu_small)
                        } else {
                            (&large, cpu_large)
                        };
                        let gpu = dispatch_moe_batch(feat, timeout)
                            .expect("concurrent GPU MoE dispatch returned no result");
                        assert_eq!(gpu.len(), feat.len());
                        let zeroed = gpu
                            .iter()
                            .zip(cpu.iter())
                            .filter(|(g, c)| **g == 0.0 && **c > 0.01)
                            .count();
                        assert_eq!(
                            zeroed, 0,
                            "concurrent dispatch (batch={}) produced {zeroed} zeroed score(s): shared GPU params race",
                            feat.len()
                        );
                    }
                });
            }
        });
    }

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

    // ---- GPU-init-failure path (no real GPU required) --------------------------
    //
    // Regression for the reentrant-OnceLock deadlock: `get_gpu()`'s old `Err` arm
    // called `probe_hardware().gpu_available`, which re-entered the `HW_PROBE`
    // (and transitively `GPU`) OnceLock that was mid-init on that exact path,
    // hanging the scan thread forever on any GPU-init failure. The failure
    // decision is now a PURE function of the structured error + resolved policy,
    // so it is driven here directly, off the GPU, and CANNOT hang.

    #[test]
    fn gpu_init_error_constructors_set_adapter_present() {
        // The `adapter_present` flag is the whole reason the reentrant probe is
        // gone: it carries "is a real GPU present?" in-band instead of asking the
        // initializing OnceLock. Pin both constructors' flag exactly.
        assert!(
            !GpuInitError::no_adapter("vyre WgpuBackend unavailable").adapter_present,
            "no_adapter must report NO adapter present (quiet CPU-only path)"
        );
        assert!(
            GpuInitError::adapter_unusable("max_storage_buffer_binding_size too small")
                .adapter_present,
            "adapter_unusable must report a real adapter present (actionable notice)"
        );
    }

    #[test]
    fn classify_gpu_init_failure_covers_full_policy_matrix() {
        use GpuInitFailureAction::{HardFail, Quiet, WarnCpuFallback};
        let present = GpuInitError::adapter_unusable("real adapter, MoE unusable");
        let absent = GpuInitError::no_adapter("no adapter");

        // --require-gpu ALWAYS hard-fails, regardless of adapter presence or the
        // (mutually exclusive) --no-gpu bit: the operator forbade a CPU degrade.
        assert_eq!(
            classify_gpu_init_failure(&present, false, true),
            HardFail,
            "required + adapter present => hard-fail"
        );
        assert_eq!(
            classify_gpu_init_failure(&absent, false, true),
            HardFail,
            "required + no adapter => hard-fail (the flag exists for exactly this)"
        );

        // Ordinary run: warn ONLY when a real GPU is present but unusable.
        assert_eq!(
            classify_gpu_init_failure(&present, false, false),
            WarnCpuFallback,
            "auto + adapter present => loud CPU-fallback notice"
        );
        assert_eq!(
            classify_gpu_init_failure(&absent, false, false),
            Quiet,
            "auto + no adapter => quiet (expected CPU-only majority: laptops/CI/containers)"
        );

        // --no-gpu stays quiet EVEN when a real adapter is present: CPU is the
        // explicitly requested route, so a "GPU unusable" notice would be noise.
        assert_eq!(
            classify_gpu_init_failure(&present, true, false),
            Quiet,
            "disabled + adapter present => quiet (CPU is the requested route)"
        );
        assert_eq!(
            classify_gpu_init_failure(&absent, true, false),
            Quiet,
            "disabled + no adapter => quiet"
        );
    }

    #[test]
    fn on_gpu_init_failed_returns_none_without_reentering_onelocks() {
        // THE deadlock regression: force the `Err` branch and prove it RETURNS
        // (returns `None`, the loud degrade), rather than hanging on a reentrant
        // OnceLock. `on_gpu_init_failed` takes the resolved policy by value and,
        // by contract, calls neither `probe_hardware()` nor `get_gpu()`, so this
        // completes even when invoked from inside an initializing OnceLock. Pass
        // required=false so the hard-fail (process-exit) arm is never taken.
        //
        // adapter-present (real GPU unusable) => WarnCpuFallback notice, then None.
        let unusable = GpuInitError::adapter_unusable("forced adapter-present failure");
        assert!(
            on_gpu_init_failed(&unusable, /*disabled=*/ false, /*required=*/ false).is_none(),
            "adapter-present init failure must degrade to None (CPU MoE), not hang"
        );
        // no-adapter => quiet, then None.
        let no_adapter = GpuInitError::no_adapter("forced no-adapter failure");
        assert!(
            on_gpu_init_failed(
                &no_adapter,
                /*disabled=*/ false,
                /*required=*/ false
            )
            .is_none(),
            "no-adapter init failure must degrade to None quietly, not hang"
        );
        // --no-gpu with a real adapter present => still quiet, still None.
        assert!(
            on_gpu_init_failed(&unusable, /*disabled=*/ true, /*required=*/ false).is_none(),
            "disabled-policy init failure must degrade to None quietly, not hang"
        );
    }

    #[test]
    fn on_gpu_init_failed_does_not_deadlock_when_called_mid_onelock_init() {
        // Structural proof of non-reentrancy: run the forced failure path from
        // INSIDE another OnceLock's initializer. The old code called
        // `probe_hardware()` here; if `on_gpu_init_failed` re-entered any
        // process-wide init OnceLock this get_or_init would deadlock and the test
        // would time out. It must complete and cache `true`.
        static GUARD: OnceLock<bool> = OnceLock::new();
        let completed = *GUARD.get_or_init(|| {
            let err = GpuInitError::adapter_unusable("failure raised during OnceLock init");
            on_gpu_init_failed(&err, /*disabled=*/ true, /*required=*/ false).is_none()
        });
        assert!(
            completed,
            "GPU-init-failure handling must complete from within an initializing OnceLock"
        );
    }
}
