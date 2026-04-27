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
    pub fn observations(&self) -> u32 {
        // Subtract the Beta(1, 1) prior baseline.
        self.alpha.saturating_sub(1) + self.beta.saturating_sub(1)
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
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        std::fs::write(&tmp, &serialized)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Record a true positive for `detector_id` (α += 1).
    pub fn record_true_positive(&self, detector_id: &str) {
        self.inner
            .write()
            .entry(detector_id.to_string())
            .or_default()
            .alpha += 1;
    }

    /// Record a false positive for `detector_id` (β += 1).
    pub fn record_false_positive(&self, detector_id: &str) {
        self.inner
            .write()
            .entry(detector_id.to_string())
            .or_default()
            .beta += 1;
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
}

/// Default cache location: `$XDG_CACHE_HOME/keyhog/calibration.json` (or
/// the macOS/Windows equivalents via the `dirs` crate).
pub fn default_cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("keyhog").join("calibration.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_detector_returns_uniform_prior() {
        let c = Calibration::empty();
        assert_eq!(c.confidence_multiplier("never-seen"), 0.5);
    }

    #[test]
    fn true_positives_drive_posterior_up() {
        let c = Calibration::empty();
        for _ in 0..9 {
            c.record_true_positive("aws-access-key");
        }
        // α = 10, β = 1 → mean = 10/11 ≈ 0.909
        let m = c.confidence_multiplier("aws-access-key");
        assert!(m > 0.85, "expected >0.85, got {m}");
    }

    #[test]
    fn false_positives_drive_posterior_down() {
        let c = Calibration::empty();
        for _ in 0..9 {
            c.record_false_positive("noisy-detector");
        }
        // α = 1, β = 10 → mean = 1/11 ≈ 0.091
        let m = c.confidence_multiplier("noisy-detector");
        assert!(m < 0.15, "expected <0.15, got {m}");
    }

    #[test]
    fn observations_excludes_prior() {
        let c = Calibration::empty();
        assert_eq!(c.counters("x").observations(), 0);
        c.record_true_positive("x");
        c.record_false_positive("x");
        assert_eq!(c.counters("x").observations(), 2);
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calibration.json");

        let c = Calibration::empty();
        c.record_true_positive("aws-access-key");
        c.record_false_positive("aws-access-key");
        c.record_true_positive("github-pat");
        c.save(&path).unwrap();

        let loaded = Calibration::load(&path);
        let aws = loaded.counters("aws-access-key");
        assert_eq!(aws.alpha, 2);
        assert_eq!(aws.beta, 2);
        let gh = loaded.counters("github-pat");
        assert_eq!(gh.alpha, 2);
        assert_eq!(gh.beta, 1);
    }

    #[test]
    fn corrupted_cache_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calibration.json");
        std::fs::write(&path, b"this is not json").unwrap();
        let loaded = Calibration::load(&path);
        assert_eq!(loaded.entries().len(), 0);
    }

    #[test]
    fn schema_mismatch_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calibration.json");
        let bad = serde_json::json!({
            "version": 99,
            "detectors": { "x": { "alpha": 5, "beta": 5 } }
        });
        std::fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
        let loaded = Calibration::load(&path);
        assert_eq!(loaded.entries().len(), 0);
    }

    #[test]
    fn entries_returns_sorted() {
        let c = Calibration::empty();
        c.record_true_positive("zzz");
        c.record_true_positive("aaa");
        c.record_true_positive("mmm");
        let e = c.entries();
        assert_eq!(e.len(), 3);
        assert_eq!(e[0].0, "aaa");
        assert_eq!(e[1].0, "mmm");
        assert_eq!(e[2].0, "zzz");
    }
}
