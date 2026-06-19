//! Bayesian Beta(α, β) calibration per detector.
//!
//! Tier-B moat innovation #4 from docs/EXECUTION_PLAN.md: surface
//! per-detector reliability based on observed true-positive vs false-
//! positive history rather than a fixed threshold. Detectors with a long
//! history of clean hits get a higher confidence multiplier; detectors
//! that fire-then-suppress repeatedly get downweighted.
//!
//! Mathematical model:
//!     each detector has a Beta(α, β) prior over P(true positive | match).
//!     α counts confirmed TPs, β counts confirmed FPs (both incremented from
//!     a starting prior of α=1, β=1 - uniform Beta(1, 1)).
//!     posterior mean = α / (α + β)  ∈ [0, 1].
//!
//! Storage: JSON at `$XDG_CACHE_HOME/keyhog/calibration.json` with a schema
//! version field. [`Calibration::try_load`] distinguishes a missing cache from
//! a damaged artifact so operator commands can fail closed instead of
//! overwriting corrupt state as if it were a clean first run. The legacy
//! [`Calibration::load`] API remains tolerant for compatibility; production
//! operator paths must use the strict loader when the cache is explicit.
//!
//! Coherence contract (audit organization/coherence finding): this module is
//! the DATA layer, but it is now LIVE - the scanner's confidence-scoring path
//! (`scanner::confidence::apply_calibration_multiplier`) reads these counters.
//! Because a calibration artifact silently present on one machine but absent on
//! another would make `tuned != benched != shipped`, the integration MUST be
//! opt-in and deterministic: the scoring path only consults a calibration store
//! when one is explicitly supplied, and the default / benchmark / CI scan runs
//! with an [`empty`](Calibration::empty) store so two machines produce identical
//! findings for the same input. A stray `$XDG_CACHE_HOME` artifact on a dev box
//! must never silently alter results - that gating lives in the scanner crate.

#![allow(missing_docs)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
    pub(crate) fn posterior_mean(&self) -> f64 {
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
    /// `alpha.saturating_sub(1) + beta.saturating_sub(1)` - the `+`
    /// was a plain add and would panic in debug / wrap to 0 in release
    /// once both counters reached ~`u32::MAX / 2`. Use `saturating_add`
    /// so the result clamps at `u32::MAX` instead of wrapping. That's
    /// still a frozen counter at saturation, but the posterior mean
    /// stays correct and no detector silently gets disabled.
    pub(crate) fn observations(&self) -> u32 {
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

/// Error returned when an existing calibration cache cannot be trusted.
#[derive(Debug, Error)]
pub enum CalibrationLoadError {
    /// The cache file exists but could not be read.
    #[error("calibration cache '{}' could not be read: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The cache file exists but is not valid JSON for the calibration schema.
    #[error("calibration cache '{}' is not valid JSON: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// The cache JSON has a version this binary does not understand.
    #[error(
        "calibration cache '{}' has schema version {found}; expected {expected}",
        path.display()
    )]
    SchemaVersion {
        path: PathBuf,
        found: u32,
        expected: u32,
    },
}

/// Process-wide calibration store. Concurrent updates are serialized via
/// a single `RwLock` because update events are rare (one per `keyhog
/// calibrate` invocation or per verifier outcome) and the locked region is
/// constant-time. We deliberately don't shard via DashMap - the persisted
/// artifact is small enough that contention is a non-issue.
#[derive(Debug, Default)]
pub struct Calibration {
    inner: RwLock<HashMap<String, BetaCounters>>,
}

impl Calibration {
    fn empty() -> Self {
        Self::default()
    }

    pub fn try_load(path: &Path) -> Result<Option<Self>, CalibrationLoadError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CalibrationLoadError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let on_disk: OnDisk =
            serde_json::from_slice(&bytes).map_err(|source| CalibrationLoadError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        if on_disk.version != SCHEMA_VERSION {
            return Err(CalibrationLoadError::SchemaVersion {
                path: path.to_path_buf(),
                found: on_disk.version,
                expected: SCHEMA_VERSION,
            });
        }
        Ok(Some(Self {
            inner: RwLock::new(on_disk.detectors),
        }))
    }

    pub(crate) fn load(path: &Path) -> Self {
        match Self::try_load(path) {
            Ok(Some(calibration)) => calibration,
            Ok(None) => Self::empty(),
            Err(error) => {
                tracing::warn!(
                    cache = %path.display(),
                    error = %error,
                    "calibration cache could not be loaded; treating as cold start"
                );
                Self::empty()
            }
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
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
        std::fs::create_dir_all(parent)?;
        // Same atomic-write-via-NamedTempFile pattern used by
        // `merkle_index::save` - see that file's note for rationale.
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut tmp, &serialized)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Record an operator-confirmed outcome for `detector_id`.
    pub fn record_outcome(&self, detector_id: &str, true_positive: bool) {
        if true_positive {
            self.record_true_positive(detector_id);
        } else {
            self.record_false_positive(detector_id);
        }
    }

    /// Record a true positive for `detector_id` (α += 1).
    ///
    /// kimi-confidence audit: bare `alpha += 1` would panic in debug
    /// and wrap to 0 in release once a single detector accumulates
    /// 2^32 observations. Wrapping to 0 silently mutes a previously
    /// reliable detector (posterior mean drops to 0.0/1.0 = 0). Use
    /// `saturating_add` so the worst case is a frozen counter at
    /// `u32::MAX`, which keeps the posterior mean correct.
    pub(crate) fn record_true_positive(&self, detector_id: &str) {
        let mut guard = self.inner.write();
        let entry = guard.entry(detector_id.to_string()).or_default();
        entry.alpha = entry.alpha.saturating_add(1);
    }

    /// Record a false positive for `detector_id` (β += 1). Same
    /// `saturating_add` rationale as [`record_true_positive`].
    pub(crate) fn record_false_positive(&self, detector_id: &str) {
        let mut guard = self.inner.write();
        let entry = guard.entry(detector_id.to_string()).or_default();
        entry.beta = entry.beta.saturating_add(1);
    }

    /// Return the posterior mean for `detector_id`, falling back to 0.5
    /// when no observations exist (uniform prior over a never-calibrated
    /// detector). The scanner's confidence-scoring path consumes this value,
    /// but only when calibration is explicitly opted in (see the module-level
    /// coherence contract) so default / benchmark scans stay deterministic.
    pub(crate) fn confidence_multiplier(&self, detector_id: &str) -> f64 {
        self.inner
            .read()
            .get(detector_id)
            .copied()
            .unwrap_or_default() // LAW10: missing/non-string field => empty/placeholder; recall-safe
            .posterior_mean()
    }

    /// Return the full counters for `detector_id` (defaults to Beta(1, 1)).
    pub fn counters(&self, detector_id: &str) -> BetaCounters {
        self.inner
            .read()
            .get(detector_id)
            .copied()
            .unwrap_or_default() // LAW10: missing/non-string field => empty/placeholder; recall-safe
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
    pub(crate) fn test_seed_counters(&self, id: &str, alpha: u32, beta: u32) {
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
