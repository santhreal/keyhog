//! GPU MoE dispatch, readback, validation, and CPU-parity trust gate.

use super::acquisition::get_gpu;
use super::diagnostics::{
    moe_nonfinite_degrade, moe_numeric_divergence_degrade, moe_runtime_degrade,
    report_buffer_pool_poison_once, GpuBackendError,
};
use bytemuck::{Pod, Zeroable};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::ml_scorer::GPU_BATCH_THRESHOLD;
pub(super) const INPUT_DIM: usize = crate::ml_scorer::NUM_FEATURES;
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
static MOE_NUMERIC_TRUST: OnceLock<Result<bool, GpuBackendError>> = OnceLock::new();
static MOE_NUMERIC_FAULTED: AtomicBool = AtomicBool::new(false);

/// Score a batch of feature vectors on GPU. Returns one score per input.
///
/// # Examples
///
/// ```rust,ignore
/// use keyhog_scanner::gpu::batch_score_features;
/// // The feature width is `model_arch::INPUT_DIM` (55), never a
/// // bare literal; a wrong-width buffer is rejected by the GPU host layout.
/// let _ = batch_score_features(&[[0.0f32; 55]], std::time::Duration::from_millis(30_000));
/// ```
pub(crate) fn batch_score_features(
    features: &[[f32; INPUT_DIM]],
    readback_timeout: Duration,
) -> Result<Option<Vec<f64>>, GpuBackendError> {
    if features.len() < GPU_BATCH_THRESHOLD {
        return Ok(None); // Too small for GPU, caller should use CPU
    }

    // Honor the resolved GPU runtime policy BEFORE touching `get_gpu()` /
    // `init_gpu()`, exactly as `gpu_probe()` does. Without this gate a
    // `--no-gpu` scan that reaches a large MoE batch still triggers the wgpu
    // adapter probe inside `init_gpu()`: which the team's own `gpu_probe`
    // comment notes "can block for minutes on broken driver stacks." Policy
    // disabled => return None so the caller scores this batch on CPU (identical
    // scores), and the adapter is never probed. Mirrors the gpu_probe guard so
    // the disabled-GPU path can never drift back into an unconditional probe.
    if crate::gpu::gpu_disabled_by_policy() {
        return Ok(None);
    }

    // A runtime numeric fault invalidates the device beyond the affected
    // batch. The fault site already emitted the operator-visible diagnostic.
    if MOE_NUMERIC_FAULTED.load(Ordering::Acquire) {
        return Ok(None);
    }

    // The GPU compute shader MUST reproduce the CPU MoE (`ml_scorer::score_features`
    // the reference every confidence floor is tuned and benched against) within
    // tolerance. A shader miscompile, weights-packing mismatch, or driver bug that
    // makes the GPU score DIVERGE from CPU would silently change findings vs the
    // CPU/SIMD path (a Law-10 recall bug: a real secret the CPU scores ~1.0 gets a
    // GPU ~0.0 and is dropped) AND make autoroute calibration nondeterministic (the
    // readback-timeout degrade swaps the broken GPU score for the correct CPU one
    // between trials, flipping a floor-straddling finding). Probe ONCE per process;
    // on divergence FAIL CLOSED, return None so every batch scores on the correct,
    // deterministic CPU path, loudly, instead of trusting a broken accelerator.
    if !gpu_moe_numerically_trustworthy(readback_timeout)? {
        return Ok(None);
    }

    dispatch_moe_batch(features, readback_timeout)
}

/// Global buffer pool for MoE dispatch. Eliminates per-dispatch buffer
/// allocation by reusing input/output/staging/params buffers across dispatches.
/// Buffers grow to the largest batch size seen (wgpu buffers are immutable in
/// size, so we keep the high-water mark).
///
/// Uses one global mutex-protected spare instead of thread-local storage
/// because `wgpu::Buffer::drop` accesses wgpu's own thread-local state, which
/// can panic during thread destruction. The largest idle set remains alive for
/// reuse while redundant sets are destroyed outside the critical section.
struct MoeBufferPool {
    spare: Option<MoeBufferSet>,
}

/// A checked-out set of MoE dispatch buffers. The complete set is exclusive to
/// one dispatch until check-in, so the params buffer can be reused safely
/// without sharing mutable batch state between concurrent dispatches.
struct MoeBufferSet {
    input: wgpu::Buffer,
    output: wgpu::Buffer,
    staging: wgpu::Buffer,
    params: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
    /// The batch_size this set was allocated for. Used to verify the set
    /// is large enough before reuse (wgpu buffers are immutable in size).
    alloc_batch_size: usize,
}

struct MoeDispatchLayout {
    batch_size: u32,
    input_bytes: u64,
    output_bytes: u64,
    workgroups: u32,
}

impl MoeDispatchLayout {
    fn for_device(batch_size: usize, limits: &wgpu::Limits) -> Result<Self, &'static str> {
        let batch_size_u32 = u32::try_from(batch_size)
            .map_err(|_| "candidate count exceeds the GPU batch index width")?;
        let input_bytes = batch_size
            .checked_mul(INPUT_DIM)
            .and_then(|values| values.checked_mul(std::mem::size_of::<f32>()))
            // LAW10: fail-closed; conversion failure reaches the explicit buffer-size overflow error and never selects another backend.
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or("GPU MoE input-buffer size overflow")?;
        let output_bytes = batch_size
            .checked_mul(std::mem::size_of::<f32>())
            // LAW10: fail-closed; conversion failure reaches the explicit buffer-size overflow error and never selects another backend.
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or("GPU MoE output-buffer size overflow")?;
        let storage_limit = u64::from(limits.max_storage_buffer_binding_size);
        if input_bytes > storage_limit || output_bytes > storage_limit {
            return Err("GPU MoE batch exceeds the device storage-buffer binding limit");
        }
        if input_bytes > limits.max_buffer_size || output_bytes > limits.max_buffer_size {
            return Err("GPU MoE batch exceeds the device buffer-size limit");
        }
        let workgroups =
            batch_size_u32.div_ceil(crate::ml_scorer::model_arch::WORKGROUP_SIZE as u32);
        if workgroups > limits.max_compute_workgroups_per_dimension {
            return Err("GPU MoE batch exceeds the device compute-workgroup limit");
        }
        Ok(Self {
            batch_size: batch_size_u32,
            input_bytes,
            output_bytes,
            workgroups,
        })
    }
}

impl MoeBufferPool {
    fn new() -> Self {
        Self { spare: None }
    }

    fn take_spare(&mut self) -> Option<MoeBufferSet> {
        self.spare.take()
    }

    /// Retain the largest idle set and return the other one to be dropped by
    /// the caller after it releases the mutex.
    fn checkin(&mut self, incoming: MoeBufferSet) -> Option<MoeBufferSet> {
        match self.spare.take() {
            None => {
                self.spare = Some(incoming);
                None
            }
            Some(existing) if existing.alloc_batch_size >= incoming.alloc_batch_size => {
                self.spare = Some(existing);
                Some(incoming)
            }
            Some(existing) => {
                self.spare = Some(incoming);
                Some(existing)
            }
        }
    }
}

static MOE_BUFFER_POOL: std::sync::LazyLock<std::sync::Mutex<MoeBufferPool>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(MoeBufferPool::new()));

fn lock_moe_buffer_pool() -> std::sync::MutexGuard<'static, MoeBufferPool> {
    match MOE_BUFFER_POOL.lock() {
        Ok(pool) => pool,
        Err(poisoned) => {
            report_buffer_pool_poison_once();
            poisoned.into_inner()
        }
    }
}

fn return_moe_buffers(bufs: MoeBufferSet) {
    let discarded = lock_moe_buffer_pool().checkin(bufs);
    // wgpu buffer destruction can enter driver code. Keep it outside the pool
    // critical section so a driver panic cannot poison future checkouts.
    drop(discarded);
}

/// Raw GPU MoE dispatch: upload features, run the compute shader, read back and
/// validate every per-candidate score. Split out of [`batch_score_features`] so
/// the parity self-test ([`gpu_moe_parity_max_divergence`]) can exercise the
/// exact production dispatch without re-entering the trustworthiness gate (which
/// would recurse). Callers own the size/policy/trust guards.
pub(super) fn dispatch_moe_batch(
    features: &[[f32; INPUT_DIM]],
    readback_timeout: Duration,
) -> Result<Option<Vec<f64>>, GpuBackendError> {
    let Some(gpu) = get_gpu()? else {
        return Ok(None);
    };
    let batch_size = features.len();
    let device = gpu.device();
    let queue = gpu.queue();
    let layout = match MoeDispatchLayout::for_device(batch_size, &gpu.device_limits) {
        Ok(layout) => layout,
        Err(reason) => {
            moe_runtime_degrade(reason)?;
            return Ok(None);
        }
    };

    // Checkout pooled buffers (reused across dispatches, eliminating
    // per-dispatch buffer allocation, the dominant non-GPU overhead for
    // large MoE batches in coalesced scanning). The global mutex is held
    // only while taking the spare, not during GPU compute or readback.
    let spare = lock_moe_buffer_pool().take_spare();
    let bufs = match spare {
        Some(set) if set.alloc_batch_size >= batch_size => Some(set),
        // Drop undersized buffers only after the mutex guard above is gone.
        Some(set) => {
            drop(set);
            None
        }
        None => None,
    };
    let bufs = match bufs {
        Some(set) => set,
        None => {
            // No spare set or too small, allocate one complete reusable
            // dispatch set. The bind group is immutable and points at these
            // same buffers, so it is safe to retain with the exclusive set.
            let input = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("moe_input_pooled"),
                size: layout.input_bytes,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let output = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("moe_output_pooled"),
                size: layout.output_bytes,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
                mapped_at_creation: false,
            });
            let staging = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("moe_staging_pooled"),
                size: layout.output_bytes,
                usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let params = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("moe_params_pooled"),
                size: std::mem::size_of::<GpuParams>() as u64,
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("moe_bg_pooled"),
                layout: &gpu.artifacts().bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: gpu.artifacts().weights_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: input.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: output.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 3,
                        resource: params.as_entire_binding(),
                    },
                ],
            });
            MoeBufferSet {
                input,
                output,
                staging,
                params,
                bind_group,
                alloc_batch_size: batch_size,
            }
        }
    };

    // Each checked-out set owns its params buffer until this dispatch has
    // completed and read back. This preserves per-dispatch batch_size isolation
    // under rayon concurrency without paying a device-buffer allocation on
    // every batch.
    let params = GpuParams {
        batch_size: layout.batch_size,
        _pad: [0; 3],
    };

    // Upload input features via queue.write_buffer (pooled buffer is
    // COPY_DST). `&[[f32; INPUT_DIM]]` is already a contiguous f32 block,
    // so reinterpret in place (no flatten allocation).
    queue.write_buffer(&bufs.input, 0, bytemuck::cast_slice(features));
    queue.write_buffer(&bufs.params, 0, bytemuck::bytes_of(&params));

    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some("moe_encoder"),
    });

    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("moe_pass"),
            timestamp_writes: None,
        });
        pass.set_pipeline(&gpu.artifacts().pipeline);
        pass.set_bind_group(0, &bufs.bind_group, &[]);
        pass.dispatch_workgroups(layout.workgroups, 1, 1);
    }

    encoder.copy_buffer_to_buffer(&bufs.output, 0, &bufs.staging, 0, layout.output_bytes);
    // Feature rows encode candidate length, entropy, detector identity, and
    // context signals. Clear the used input range in the same ordered GPU
    // submission so a pooled high-water buffer never retains prior candidate
    // evidence. The staging buffer contains only confidence scores.
    encoder.clear_buffer(&bufs.input, 0, Some(layout.input_bytes));
    encoder.clear_buffer(&bufs.params, 0, None);
    queue.submit(std::iter::once(encoder.finish()));

    // Read back results, slice only the portion we copied (the pooled
    // staging buffer may be larger than this batch if it was allocated
    // for a previous larger batch).
    let slice = bufs.staging.slice(..layout.output_bytes);
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
                moe_runtime_degrade("staging-buffer callback disconnected")?;
                // Do not pool a staging buffer whose map lifecycle did not
                // complete successfully; dropping the set prevents a later
                // dispatch from reusing unknown mapping state.
                return Ok(None);
            }
            Err(TryRecvError::Empty) => {}
        }

        if Instant::now() >= deadline {
            tracing::warn!(
                ?timeout,
                "GPU MoE staging-buffer readback timed out; GPU MoE disabled and scoring uses CPU MoE for this scan"
            );
            moe_runtime_degrade("staging-buffer readback timed out")?;
            // The callback may still complete after this deadline. Dropping the
            // set is safe; pooling it while map_async is pending is not.
            return Ok(None);
        }

        if let Err(error) = device.poll(wgpu::PollType::Poll) {
            tracing::warn!(
                ?error,
                "GPU MoE device.poll() failed; GPU MoE disabled and scoring uses CPU MoE for this scan"
            );
            moe_runtime_degrade("device.poll() failed")?;
            return Ok(None);
        }

        match receiver.try_recv() {
            Ok(result) => break result,
            Err(TryRecvError::Disconnected) => {
                tracing::warn!(
                    "GPU MoE staging-buffer callback disconnected after device polling; GPU MoE disabled and scoring uses CPU MoE for this scan"
                );
                moe_runtime_degrade("staging-buffer callback disconnected after device poll")?;
                return Ok(None);
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
        moe_runtime_degrade("staging-buffer map_async failed")?;
        return Ok(None);
    }
    let data = slice.get_mapped_range();
    let scores: &[f32] = bytemuck::cast_slice(&data);
    if scores.len() != batch_size {
        tracing::warn!(
            expected = batch_size,
            actual = scores.len(),
            "GPU MoE score count mismatch; routing batch to CPU MoE for this scan"
        );
        moe_runtime_degrade("score count mismatch")?;
        drop(data);
        bufs.staging.unmap();
        return_moe_buffers(bufs);
        return Ok(None);
    }
    let result = checked_moe_scores(scores);
    if result.is_err() {
        // Latch the fault before releasing the readback resources so a new
        // dispatch cannot enter during cleanup and retry the corrupt device.
        MOE_NUMERIC_FAULTED.store(true, Ordering::Release);
    }
    drop(data);
    bufs.staging.unmap();

    // Return buffers to pool for reuse by the next dispatch.
    return_moe_buffers(bufs);

    match result {
        Ok(scores) => Ok(Some(scores)),
        Err(nonfinite) => {
            moe_nonfinite_degrade(nonfinite, batch_size)?;
            Ok(None)
        }
    }
}

/// Convert a complete GPU score buffer only when every value is finite. A
/// single invalid probability makes the whole batch untrusted because adjacent
/// finite-looking values may have been produced by the same device fault.
pub(super) fn checked_moe_scores(scores: &[f32]) -> Result<Vec<f64>, usize> {
    let mut result = Vec::with_capacity(scores.len());
    let mut nonfinite = 0usize;
    for &score in scores {
        let score = f64::from(score);
        if score.is_finite() {
            result.push(score.clamp(0.0, 1.0));
        } else {
            nonfinite += 1;
        }
    }
    if nonfinite == 0 {
        Ok(result)
    } else {
        Err(nonfinite)
    }
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
pub(super) fn gpu_moe_parity_probe_features() -> Vec<[f32; INPUT_DIM]> {
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
fn gpu_moe_parity_max_divergence_typed(readback_timeout: Duration) -> Result<f64, GpuBackendError> {
    let probe = gpu_moe_parity_probe_features();
    let gpu_scores = match dispatch_moe_batch(&probe, readback_timeout)? {
        Some(scores) => scores,
        None => {
            return Err(GpuBackendError::new(
                "GPU MoE dispatch produced no result for the parity probe",
            ));
        }
    };
    if gpu_scores.len() != probe.len() {
        return Err(GpuBackendError::new(format!(
            "GPU MoE parity probe returned {} scores for {} inputs",
            gpu_scores.len(),
            probe.len()
        )));
    }
    let mut max_abs = 0.0f64;
    for (gpu, feat) in gpu_scores.iter().zip(probe.iter()) {
        let cpu = crate::ml_scorer::score_features(feat);
        max_abs = max_abs.max((gpu - cpu).abs());
    }
    Ok(max_abs)
}

pub(crate) fn gpu_moe_parity_max_divergence(readback_timeout: Duration) -> Result<f64, String> {
    gpu_moe_parity_max_divergence_typed(readback_timeout).map_err(|error| error.to_string())
}

/// One-time, process-wide GPU MoE trust gate. The GPU MoE is trusted for scoring
/// ONLY if it reproduces the CPU MoE within [`GPU_MOE_PARITY_TOLERANCE`] on the
/// parity probe. On divergence (or dispatch failure) it is permanently distrusted
/// for the process and every batch falls to the correct, deterministic CPU path,
/// with one loud line. Cached so the probe runs at most once.
fn gpu_moe_numerically_trustworthy(readback_timeout: Duration) -> Result<bool, GpuBackendError> {
    MOE_NUMERIC_TRUST
        .get_or_init(
            || match gpu_moe_parity_max_divergence_typed(readback_timeout) {
                Ok(max_abs) if max_abs <= GPU_MOE_PARITY_TOLERANCE => {
                    tracing::info!(
                        target: "keyhog::gpu",
                        max_abs_diff = max_abs,
                        tolerance = GPU_MOE_PARITY_TOLERANCE,
                        "GPU MoE parity probe matched CPU MoE"
                    );
                    Ok(true)
                }
                Ok(max_abs) => {
                    moe_numeric_divergence_degrade(&format!(
                        "max_abs_diff={max_abs:.6}, tolerance={GPU_MOE_PARITY_TOLERANCE:.6}"
                    ))?;
                    Ok(false)
                }
                Err(error) => {
                    // A non-finite readback already emitted the more precise numeric
                    // fault and permanently disabled GPU MoE scoring. Avoid a second,
                    // less-specific parity receipt for the same event, while preserving
                    // a required-GPU failure as the typed error from the fault site.
                    if MOE_NUMERIC_FAULTED.load(Ordering::Acquire) {
                        if crate::gpu::gpu_required_by_policy() {
                            return Err(error);
                        }
                        return Ok(false);
                    }
                    moe_numeric_divergence_degrade(&error.to_string())?;
                    Ok(false)
                }
            },
        )
        .clone()
}
