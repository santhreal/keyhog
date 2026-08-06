//! GPU-accelerated batch inference for the MoE classifier via wgpu compute shaders.
//!
//! Processes N feature vectors in a single GPU dispatch, achieving ~10-100x
//! throughput over CPU for large batches. Falls back to CPU when no GPU is
//! available or for batches smaller than the crossover threshold.
//!
//! Architecture mirrors ml_scorer.rs exactly:
//! - Gate: Linear(55→6) + softmax
//! - 6 experts: Linear(55→32)+ReLU → Linear(32→16)+ReLU → Linear(16→1)
//! - Output: sigmoid(weighted sum of expert logits)
//!
//! ## Feature-gating in the lean build
//!
//! Every entry point that would touch wgpu / vyre-driver-wgpu directly is
//! wrapped in `#[cfg(feature = "gpu")]`. With the `gpu` feature off (the
//! `cargo install keyhog --no-default-features --features ci` path), the
//! GPU drivers aren't linked at all, the probe functions report "no GPU
//! available" without ever calling into wgpu, and the self-test functions
//! return a "not available in this build" `Err` instead of panicking.
//! The CPU MoE path in `ml_scorer.rs` is the entire scoring story under
//! that profile.

// Both submodules lean on the wgpu device/queue + bytemuck cast helpers.
// They only exist in `gpu`-on builds; the public API in this module
// short-circuits to "no GPU" via the `cfg` arms below when off.
// Submodules live in `gpu/` (native resolution), matching the `foo.rs` + `foo/`
// layout used across the workspace. Module names (gpu_shader/backend/policy) are
// unchanged; only the files moved (and gpu_moe_backend.rs/gpu_env.rs were
// renamed to match their module names).
#[cfg(feature = "gpu")]
mod adapter_probe;
mod backend;
#[cfg(feature = "gpu")]
pub(crate) mod evidence;
#[cfg(all(test, feature = "gpu", target_os = "linux"))]
pub(crate) use backend::load_dynamic_library;
#[cfg(all(feature = "gpu", target_os = "linux"))]
pub(crate) use backend::probe_cuda_peer;
#[cfg(all(test, feature = "gpu"))]
pub(crate) use backend::with_test_resident_dispatch_failure;
pub use backend::GpuBackendAvailability;
#[cfg(feature = "gpu")]
pub(crate) use backend::{scan_gpu_literal_evidence_by_region_resident, GpuResidentLiteralSlot};
pub(crate) use backend::{GpuBackendAcquisitionFailure, GpuBackendPeers, SelectedGpuPeer};
type RecoveryReceiptCounter = std::sync::Arc<std::sync::atomic::AtomicU64>;

thread_local! {
    static RECOVERY_RECEIPT_COUNTER: std::cell::RefCell<Option<RecoveryReceiptCounter>> =
        const { std::cell::RefCell::new(None) };
}

struct RecoveryReceiptCounterGuard {
    previous: Option<RecoveryReceiptCounter>,
}

impl Drop for RecoveryReceiptCounterGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        RECOVERY_RECEIPT_COUNTER.with_borrow_mut(|counter| {
            *counter = previous;
        });
    }
}

pub(crate) fn capture_recovery_receipts() -> Option<RecoveryReceiptCounter> {
    RECOVERY_RECEIPT_COUNTER.with_borrow(|counter| counter.clone())
}

pub(crate) fn with_captured_recovery_receipts<T>(
    counter: Option<&RecoveryReceiptCounter>,
    operation: impl FnOnce() -> T,
) -> T {
    let previous = RECOVERY_RECEIPT_COUNTER
        .with_borrow_mut(|current| std::mem::replace(&mut *current, counter.cloned()));
    let _guard = RecoveryReceiptCounterGuard { previous };
    operation()
}

pub(crate) fn with_recovery_receipt_scope<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    let counter = RecoveryReceiptCounter::new(std::sync::atomic::AtomicU64::new(0));
    let result = with_captured_recovery_receipts(Some(&counter), operation);
    let receipts = counter.load(std::sync::atomic::Ordering::Relaxed);
    (result, receipts)
}

pub(crate) fn record_recovery_receipt() {
    // Every GPU recovery receipt is also typed accelerator evidence. All
    // receipt producers today are WGPU MoE/init paths, so the recovery event
    // carries the WGPU backend code; the region-presence recovery path
    // records its own backend directly.
    #[cfg(feature = "gpu")]
    evidence::record_recovery(evidence::BACKEND_WGPU);
    RECOVERY_RECEIPT_COUNTER.with_borrow(|counter| {
        if let Some(counter) = counter {
            match counter.fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |receipts| Some(receipts.saturating_add(1)),
            ) {
                Ok(_) => {}
                // LAW10: impossible unconditional update rejection is surfaced loudly to
                // stderr and tracing; no recovery receipt is silently dropped.
                Err(_) => {
                    eprintln!(
                        "keyhog: recovery receipt counter rejected an unconditional saturating update"
                    );
                    tracing::error!(
                        target: "keyhog::gpu",
                        "recovery receipt counter rejected an unconditional saturating update"
                    );
                }
            }
        }
    });
}
#[cfg(feature = "gpu")]
pub(crate) mod gpu_shader;

mod policy;
pub use policy::*;
mod self_test;
pub use self_test::*;

#[cfg(feature = "gpu")]
pub(crate) use adapter_probe::{
    gpu_adapter_device_identity, gpu_adapter_probe, is_software_adapter,
};

/// Split timers: accumulated wall time in feature extraction vs MoE scoring
/// across all batch ML inference calls. Only the SCORING fraction is
/// GPU-offloadable; feature extraction is inherent per-candidate CPU work. This
/// is the data that decides whether moving the MoE to a unified GPU batch is
/// worth the recall cost of reordering finalization. The keyhog-profile runtime
/// owns both counters (typed nanosecond sums: the split nests inside the
/// `MachineLearning` stage span, so spans would double-count the stage total).
/// Render the ML feature/score split line the unified profiler prints. Pure
/// (no I/O) so the formatting is unit-testable.
pub(crate) fn format_ml_split(feature_ns: u64, score_ns: u64) -> String {
    let f = feature_ns as f64 / 1e6;
    let s = score_ns as f64 / 1e6;
    format!(
        "=== ML split: feature_extract={f:.1}ms moe_score={s:.1}ms (score = {:.1}% of ML compute; \
only this fraction is GPU-offloadable) ===",
        100.0 * s / (f + s).max(1e-9),
    )
}

/// Build the feature/score split from one drained typed-metric batch. Missing
/// counters read as zero; the caller prints nothing when both are zero.
pub(crate) fn ml_split_from_typed(metrics: &[keyhog_profile::TypedMetricRecordV2]) -> (u64, u64) {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    (
        value(keyhog_profile::CounterId::MlFeatureNs),
        value(keyhog_profile::CounterId::MlScoreNs),
    )
}

/// The split timers only pay `Instant::now()` when a profile runtime is active.
#[cfg(feature = "ml")]
fn ml_split_prof_enabled() -> bool {
    keyhog_profile::enabled()
}

#[cfg(all(test, feature = "ml", feature = "multiline"))]
pub(crate) fn batch_ml_inference<T: crate::ml_scorer::MlScoreInput>(
    candidates: &[T],
    config: &crate::types::ScannerConfig,
) -> Vec<f64> {
    match batch_ml_inference_with_timeout(
        candidates,
        config,
        std::time::Duration::from_millis(
            crate::scanner_config::ScannerTuningConfig::GPU_MOE_TIMEOUT_MS_DEFAULT,
        ),
    ) {
        Ok(scores) => scores,
        Err(error) => panic!("test GPU ML inference failed: {error}"),
    }
}

#[cfg(feature = "ml")]
pub(crate) fn batch_ml_inference_with_timeout<T: crate::ml_scorer::MlScoreInput>(
    candidates: &[T],
    config: &crate::types::ScannerConfig,
    gpu_moe_timeout: std::time::Duration,
) -> crate::error::Result<Vec<f64>> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    #[cfg(feature = "ml")]
    {
        use rayon::prelude::*;
        #[cfg(not(feature = "gpu"))]
        let _ = gpu_moe_timeout; // LAW10: cfg-only GPU timeout marker; ML CPU scoring ignores GPU dispatch timeout by construction
        let prof = ml_split_prof_enabled();

        // Single-chunk and windowed scans commonly produce only a handful of
        // candidates. Coalesced scans aggregate pending rows across chunks
        // before entering here, but any batch below the measured GPU crossover
        // still avoids rayon split/join and GPU dispatch overhead through one
        // fused serial feature-and-score loop.
        if candidates.len() < crate::ml_scorer::GPU_BATCH_THRESHOLD {
            // Small-batch fused serial path (the ~99% case).
            let t = prof.then(std::time::Instant::now);
            let scores = crate::ml_scorer::score_input_batch_serial(candidates, config);
            if let Some(t) = t {
                // Fused loop: attribute the whole cost to feature+score combined
                // under the score counter (kept separate from the large-batch split).
                keyhog_profile::add_counter(
                    keyhog_profile::CounterId::MlScoreNs,
                    t.elapsed().as_nanos() as u64,
                );
            }
            return Ok(scores);
        }

        // Large batch: parallel feature extraction, then GPU (or parallel CPU).
        let t_feat = prof.then(std::time::Instant::now);
        let features: Vec<[f32; crate::ml_scorer::NUM_FEATURES]> = candidates
            .par_iter()
            .map(|candidate| candidate.ml_features(config))
            .collect();
        if let Some(t) = t_feat {
            keyhog_profile::add_counter(
                keyhog_profile::CounterId::MlFeatureNs,
                t.elapsed().as_nanos() as u64,
            );
        }

        let t_score = prof.then(std::time::Instant::now);
        let score_features_on_cpu =
            || crate::ml_scorer::score_precomputed_batch_on_cpu(candidates, &features);
        let scores = {
            #[cfg(feature = "gpu")]
            {
                match backend::batch_score_features(&features, gpu_moe_timeout) {
                    Ok(Some(mut scores)) if scores.len() == candidates.len() => {
                        crate::confidence::policy::apply_empty_candidate_score_policy(
                            candidates.iter().map(|candidate| candidate.ml_text()),
                            &mut scores,
                        );
                        scores
                    }
                    Ok(Some(scores)) => {
                        debug_assert_eq!(
                            scores.len(),
                            candidates.len(),
                            "backend::batch_score_features must return one score per input"
                        );
                        evidence::record_fault(
                            evidence::BACKEND_WGPU,
                            evidence::fault::SCORE_COUNT_MISMATCH,
                        );
                        evidence::record_residual_batch();
                        backend::moe_runtime_degrade(&format!(
                            "caller-side score count mismatch: backend returned {} scores for {} candidates",
                            scores.len(),
                            candidates.len()
                        ))
                        .map_err(|error| crate::error::ScanError::Gpu(error.to_string()))?;
                        score_features_on_cpu()
                    }
                    Ok(None) => score_features_on_cpu(),
                    Err(error) => {
                        return Err(crate::error::ScanError::Gpu(error.to_string()));
                    }
                }
            }
            #[cfg(not(feature = "gpu"))]
            {
                score_features_on_cpu()
            }
        };
        if let Some(t) = t_score {
            keyhog_profile::add_counter(
                keyhog_profile::CounterId::MlScoreNs,
                t.elapsed().as_nanos() as u64,
            );
        }
        Ok(scores)
    }

    #[cfg(not(feature = "ml"))]
    {
        let _ = candidates; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
        let _ = config; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
        let _ = gpu_moe_timeout; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
        Ok(Vec::new())
    }
}

/// Return `true` when GPU scoring support is available in this build/runtime.
///
/// Honors the resolved runtime policy before touching the adapter path. A
/// caller asking after `--no-gpu` must get the same cheap "not available"
/// answer as `gpu_probe()` instead of triggering a wgpu adapter probe.
///
/// # Examples
///
/// ```rust
/// use keyhog_scanner::gpu::gpu_available;
/// let _ = gpu_available();
/// ```
pub fn gpu_available() -> bool {
    gpu_probe().available
}

#[cfg(test)]
#[path = "../tests/unit/gpu_evidence_cpu_silence.rs"]
mod gpu_evidence_cpu_silence_tests;
#[cfg(all(test, feature = "gpu"))]
#[path = "../tests/unit/gpu_evidence_recovery.rs"]
mod gpu_evidence_recovery_tests;
