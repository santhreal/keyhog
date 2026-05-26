//! Bayesian Beta(α, β) calibration per detector.
//!
//! Tier-B moat innovation #4 from audits/legendary-2026-04-26: surface
//! per-detector reliability based on observed true-positive vs false-
//! positive history rather than a fixed threshold. Detectors with a long
//! history of clean hits get a higher confidence multiplier; detectors
//! that fire-then-suppress repeatedly get downweighted.
//!
//! Mathematical model:
//!     each detector has a Beta(α, β) prior over P(true positive | match).
//!     α counts confirmed TPs, β counts confirmed FPs (both incremented from
//!     a starting prior of α=1, β=1 — uniform Beta(1, 1)).
//!     posterior mean = α / (α + β)  ∈ [0, 1].
//!
//! Storage: JSON at `$XDG_CACHE_HOME/keyhog/calibration.json` with a schema
//! version field. Load returns an empty store on miss / corrupted JSON /
//! schema mismatch — never poison the cache from a damaged artifact.
//!
//! This module ships the DATA layer only. Live integration into the
//! scanner's confidence-scoring path is a separate change that needs
//! per-detector lookup at `apply_post_ml_penalties` time.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// A detector's running Beta posterior counters. Always ≥1 each (Beta(1,1)
/// uniform prior baseline) to avoid posterior_mean undefined when a detector
/// has had no observations yet.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BetaCounters {
    pub alpha: u32,
    pub beta: u32,
}

impl Default for BetaCounters {
    fn default() -> Self {
        Self { alpha: 1, beta: 1 }
    }
}

impl BetaCounters {
    /// Posterior mean: α / (α + β). Falls in [0, 1]; the higher, the more
    /// reliable the detector is historically.
    pub fn posterior_mean(&self) -> f64 {
        let total = self.alpha as f64 + self.beta as f64;
        if total == 0.0 {
            0.5
        } else {
            self.alpha as f64 / total
        }
    }

    /// Number of observations (excluding the prior) the posterior is built
    /// on. Useful for "trust the recent history" UI gates.
    ///
    /// kimi-confidence audit: the previous form was
    /// `alpha.saturating_sub(1) + beta.saturating_sub(1)` — the `+`
    /// was a plain add and would panic in debug / wrap to 0 in release
    /// once both counters reached ~`u32::MAX / 2`. Use `saturating_add`
    /// so the result clamps at `u32::MAX` instead of wrapping. That's
    /// still a frozen counter at saturation, but the posterior mean
    /// stays correct and no detector silently gets disabled.
    pub fn observations(&self) -> u32 {
        // Subtract the Beta(1, 1) prior baseline.
        self.alpha
            .saturating_sub(1)
            .saturating_add(self.beta.saturating_sub(1))
    }
}

/// On-disk format. The version field gates breaking schema changes.
#[derive(Debug, Serialize, Deserialize)]
struct OnDisk {
    version: u32,
    detectors: HashMap<String, BetaCounters>,
}

const SCHEMA_VERSION: u32 = 1;

/// Process-wide calibration store. Concurrent updates are serialized via
/// a single `RwLock` because update events are rare (one per `keyhog
/// calibrate` invocation or per verifier outcome) and the locked region is
/// constant-time. We deliberately don't shard via DashMap — the persisted
/// artifact is small enough that contention is a non-issue.
#[derive(Debug, Default)]
pub struct Calibration {
    inner: RwLock<HashMap<String, BetaCounters>>,
}

impl Calibration {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Self {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => return Self::empty(),
        };
        let on_disk: OnDisk = match serde_json::from_slice(&bytes) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    cache = %path.display(),
                    error = %e,
                    "calibration parse failed; treating as cold start"
                );
                return Self::empty();
            }
        };
        if on_disk.version != SCHEMA_VERSION {
            tracing::warn!(
                cache = %path.display(),
                version = on_disk.version,
                expected = SCHEMA_VERSION,
                "calibration schema mismatch; treating as cold start"
            );
            return Self::empty();
        }
        Self {
            inner: RwLock::new(on_disk.detectors),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let detectors = self.inner.read().clone();
        let on_disk = OnDisk {
            version: SCHEMA_VERSION,
            detectors,
        };
        let serialized = serde_json::to_vec_pretty(&on_disk)
            .map_err(|e| std::io::Error::other(format!("calibration encode: {e}")))?;
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(parent)?;
        // Same atomic-write-via-NamedTempFile pattern used by
        // `merkle_index::save` — see that file's note for rationale.
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut tmp, &serialized)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Record a true positive for `detector_id` (α += 1).
    ///
    /// kimi-confidence audit: bare `alpha += 1` would panic in debug
    /// and wrap to 0 in release once a single detector accumulates
    /// 2^32 observations. Wrapping to 0 silently mutes a previously
    /// reliable detector (posterior mean drops to 0.0/1.0 = 0). Use
    /// `saturating_add` so the worst case is a frozen counter at
    /// `u32::MAX`, which keeps the posterior mean correct.
    pub fn record_true_positive(&self, detector_id: &str) {
        let mut guard = self.inner.write();
        let entry = guard.entry(detector_id.to_string()).or_default();
        entry.alpha = entry.alpha.saturating_add(1);
    }

    /// Record a false positive for `detector_id` (β += 1). Same
    /// `saturating_add` rationale as [`record_true_positive`].
    pub fn record_false_positive(&self, detector_id: &str) {
        let mut guard = self.inner.write();
        let entry = guard.entry(detector_id.to_string()).or_default();
        entry.beta = entry.beta.saturating_add(1);
    }

    /// Return the posterior mean for `detector_id`, falling back to 0.5
    /// when no observations exist (uniform prior over a never-calibrated
    /// detector). Callers MAY use this value as a confidence multiplier
    /// inside the scanner's confidence-scoring path; the live integration
    /// is staged separately.
    pub fn confidence_multiplier(&self, detector_id: &str) -> f64 {
        self.inner
            .read()
            .get(detector_id)
            .copied()
            .unwrap_or_default()
            .posterior_mean()
    }

    /// Return the full counters for `detector_id` (defaults to Beta(1, 1)).
    pub fn counters(&self, detector_id: &str) -> BetaCounters {
        self.inner
            .read()
            .get(detector_id)
            .copied()
            .unwrap_or_default()
    }

    /// Iterate every recorded `(detector_id, counters)`. Useful for
    /// `keyhog calibrate --show`.
    pub fn entries(&self) -> Vec<(String, BetaCounters)> {
        let mut out: Vec<_> = self
            .inner
            .read()
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Test-only hook for saturation oracle tests in `tests/unit/`.
    #[doc(hidden)]
    pub fn test_seed_counters(&self, id: &str, alpha: u32, beta: u32) {
        let mut guard = self.inner.write();
        let entry = guard.entry(id.to_string()).or_default();
        entry.alpha = alpha;
        entry.beta = beta;
    }
}

/// Default cache location: `$XDG_CACHE_HOME/keyhog/calibration.json` (or
/// the macOS/Windows equivalents via the `dirs` crate).
pub fn default_cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("keyhog").join("calibration.json"))
}
