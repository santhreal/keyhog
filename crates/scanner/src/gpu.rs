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
mod gpu_shader;

#[cfg(feature = "gpu")]
mod backend;

mod policy;
pub use policy::*;
mod self_test;
pub use self_test::*;

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
/// `String` fields stay live for the duration of the call - the borrow is
/// safe.
/// Split timers: accumulated wall time in feature extraction vs MoE scoring
/// across all `batch_ml_inference` calls. Only the SCORING fraction is
/// GPU-offloadable; feature extraction is inherent per-candidate CPU work. This
/// is the data that decides whether moving the MoE to a unified GPU batch is
/// worth the recall cost of reordering finalization.
static MOE_FEATURE_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static MOE_SCORE_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Gated by the unified scanner profile switch and dumped as part of
/// [`crate::engine::profile_dump`].
#[cfg(feature = "ml")]
fn ml_split_prof_enabled() -> bool {
    crate::engine::profile::enabled()
}

/// Print + reset the feature-vs-score split. Folded into the unified profiler:
/// called from [`crate::engine::profile_dump`] (early-returns when no data).
pub(crate) fn ml_split_profile_dump() {
    use std::sync::atomic::Ordering::Relaxed;
    let f = MOE_FEATURE_NS.swap(0, Relaxed) as f64 / 1e6;
    let s = MOE_SCORE_NS.swap(0, Relaxed) as f64 / 1e6;
    if f == 0.0 && s == 0.0 {
        return;
    }
    eprintln!(
        "=== ML split: feature_extract={f:.1}ms moe_score={s:.1}ms (score = {:.1}% of ML compute; \
only this fraction is GPU-offloadable) ===",
        100.0 * s / (f + s).max(1e-9),
    );
}

pub(crate) fn ml_split_profile_reset() {
    use std::sync::atomic::Ordering::Relaxed;
    MOE_FEATURE_NS.store(0, Relaxed);
    MOE_SCORE_NS.store(0, Relaxed);
}

#[cfg(test)]
pub(crate) fn batch_ml_inference(
    candidates: &[(&str, &str)],
    config: &crate::types::ScannerConfig,
) -> Vec<f64> {
    batch_ml_inference_with_timeout(
        candidates,
        config,
        std::time::Duration::from_millis(
            crate::scanner_config::ScannerTuningConfig::GPU_MOE_TIMEOUT_MS_DEFAULT,
        ),
    )
}

#[cfg(any(feature = "ml", test))]
pub(crate) fn batch_ml_inference_with_timeout(
    candidates: &[(&str, &str)],
    config: &crate::types::ScannerConfig,
    gpu_moe_timeout: std::time::Duration,
) -> Vec<f64> {
    if candidates.is_empty() {
        return Vec::new();
    }

    #[cfg(feature = "ml")]
    {
        use rayon::prelude::*;
        #[cfg(not(feature = "gpu"))]
        let _ = gpu_moe_timeout; // LAW10: cfg-only GPU timeout marker; ML CPU scoring ignores GPU dispatch timeout by construction
        let prof = ml_split_prof_enabled();

        // Measurement (`keyhog scan --profile`, regime B): batch sizes average
        // 0.5 candidates/call and 90% of calls are empty; only 0.2% reach the
        // GPU's 64-candidate threshold. `batch_ml_inference` runs INSIDE the
        // already-parallel coalesced/per-chunk scan (rayon outer loop), so a
        // `par_iter` over a 1-7 element inner batch pays rayon split/join
        // overhead for no parallelism — pure loss on the overwhelmingly common
        // path. Below the GPU crossover the GPU never engages anyway, so the
        // small-batch path is a single fused serial loop (compute feature ->
        // score, no intermediate Vec, no rayon). Byte-identical results to the
        // parallel path; the only change is the iteration strategy.
        let feat_of = |text: &str, ctx: &str| -> [f32; crate::ml_scorer::NUM_FEATURES] {
            if text.is_empty() {
                [0.0; crate::ml_scorer::NUM_FEATURES]
            } else {
                crate::ml_scorer::compute_features_with_config(
                    text,
                    ctx,
                    &config.known_prefixes,
                    &config.secret_keywords,
                    &config.test_keywords,
                    &config.placeholder_keywords,
                )
            }
        };

        if candidates.len() < crate::ml_scorer::GPU_BATCH_THRESHOLD {
            // Small-batch fused serial path (the ~99% case).
            let t = prof.then(std::time::Instant::now);
            let scores: Vec<f64> = candidates
                .iter()
                .map(|(text, ctx)| {
                    crate::confidence::policy::ml_score_for_candidate_text(text, || {
                        crate::ml_scorer::score_features(&feat_of(text, ctx))
                    })
                })
                .collect();
            if let Some(t) = t {
                // Fused loop: attribute the whole cost to feature+score combined
                // under MOE_SCORE_NS (kept separate from the large-batch split).
                MOE_SCORE_NS.fetch_add(
                    t.elapsed().as_nanos() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            return scores;
        }

        // Large batch: parallel feature extraction, then GPU (or parallel CPU).
        let t_feat = prof.then(std::time::Instant::now);
        let features: Vec<[f32; crate::ml_scorer::NUM_FEATURES]> = candidates
            .par_iter()
            .map(|(text, ctx)| feat_of(text, ctx))
            .collect();
        if let Some(t) = t_feat {
            MOE_FEATURE_NS.fetch_add(
                t.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }

        let t_score = prof.then(std::time::Instant::now);
        let score_features_on_cpu = || -> Vec<f64> {
            candidates
                .par_iter()
                .zip(features.par_iter())
                .map(|((text, _ctx), features)| {
                    crate::confidence::policy::ml_score_for_candidate_text(text, || {
                        crate::ml_scorer::score_features(features)
                    })
                })
                .collect()
        };
        let scores = {
            #[cfg(feature = "gpu")]
            {
                match backend::batch_score_features(&features, gpu_moe_timeout) {
                    Some(mut scores) if scores.len() == candidates.len() => {
                        crate::confidence::policy::apply_empty_candidate_score_policy(
                            candidates.iter().map(|(text, _ctx)| *text),
                            &mut scores,
                        );
                        scores
                    }
                    Some(scores) => {
                        tracing::warn!(
                            candidates = candidates.len(),
                            scores = scores.len(),
                            "GPU MoE score count mismatch; recomputing CPU MoE scores for this batch"
                        );
                        score_features_on_cpu()
                    }
                    None => score_features_on_cpu(),
                }
            }
            #[cfg(not(feature = "gpu"))]
            {
                score_features_on_cpu()
            }
        };
        if let Some(t) = t_score {
            MOE_SCORE_NS.fetch_add(
                t.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        scores
    }

    #[cfg(not(feature = "ml"))]
    {
        let _ = candidates; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
        let _ = config; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
        let _ = gpu_moe_timeout; // LAW10: unused-binding marker (signature/borrowck/cfg/compile-time assert); no runtime effect, not a fallback
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
    #[cfg(feature = "gpu")]
    {
        backend::get_gpu().is_some()
    }
    #[cfg(not(feature = "gpu"))]
    {
        false
    }
}

pub(crate) fn gpu_runtime_identity() -> Option<String> {
    #[cfg(feature = "gpu")]
    {
        backend::gpu_runtime_identity()
    }
    #[cfg(not(feature = "gpu"))]
    {
        None
    }
}
