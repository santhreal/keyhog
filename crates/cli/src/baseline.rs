//! Baseline scanning support for the KeyHog CLI.
//!
//! Baselines allow teams to suppress known/acknowledged secrets so that
//! scanning an existing repository does not produce overwhelming noise.
//! A finding is suppressed if its `(detector_id, credential_hash)` pair
//! exists in the baseline. File path and line number are stored for
//! reference only — secrets may move between lines.

use anyhow::{Context, Result};
use keyhog_core::VerifiedFinding;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

const BASELINE_VERSION: u32 = 1;

/// A baseline file containing acknowledged secrets.
///
/// `entries` is the canonical persisted form. `cached_index` is built lazily
/// on first lookup and reused across subsequent `filter_new` / `contains`
/// calls so we don't re-hash every entry on every call. Constructors that
/// know the entry list will not change can call `build_index()` to amortize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub version: u32,
    pub created: String,
    pub entries: Vec<BaselineEntry>,
    #[serde(skip)]
    cached_index: std::sync::OnceLock<HashSet<(String, String)>>,
}

/// A single entry in a baseline file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BaselineEntry {
    pub detector_id: String,
    pub credential_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default = "default_status")]
    pub status: String,
}

fn default_status() -> String {
    "acknowledged".to_string()
}

impl Baseline {
    /// Create an empty baseline with the current timestamp.
    pub fn empty() -> Self {
        Self {
            version: BASELINE_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            entries: Vec::new(),
            cached_index: std::sync::OnceLock::new(),
        }
    }

    /// Load a baseline from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline file {}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&content)
            .with_context(|| format!("parsing baseline file {}", path.display()))?;
        if baseline.version != BASELINE_VERSION {
            anyhow::bail!(
                "unsupported baseline version {} (expected {})",
                baseline.version,
                BASELINE_VERSION
            );
        }
        Ok(baseline)
    }

    /// Save the baseline to a JSON file (pretty-printed).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(path)
            .with_context(|| format!("creating baseline file {}", path.display()))?;
        let writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)
            .with_context(|| format!("writing baseline file {}", path.display()))?;
        Ok(())
    }

    /// Build a new baseline from a slice of findings.
    /// Entries are deduplicated by `(detector_id, credential_hash)`.
    pub fn from_findings(findings: &[VerifiedFinding]) -> Self {
        let mut entries: Vec<BaselineEntry> = findings
            .iter()
            .map(|f| BaselineEntry {
                detector_id: f.detector_id.to_string(),
                credential_hash: format!("sha256:{}", f.credential_hash),
                file_path: f.location.file_path.as_ref().map(|p| p.to_string()),
                line: f.location.line,
                status: "acknowledged".to_string(),
            })
            .collect();

        entries.sort_by(|a, b| {
            a.detector_id
                .cmp(&b.detector_id)
                .then(a.credential_hash.cmp(&b.credential_hash))
        });
        entries.dedup_by(|a, b| {
            a.detector_id == b.detector_id && a.credential_hash == b.credential_hash
        });

        Self {
            version: BASELINE_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            entries,
            cached_index: std::sync::OnceLock::new(),
        }
    }

    /// Merge new findings into an existing baseline.
    /// New entries are added; existing entries are preserved.
    pub fn merge(&mut self, findings: &[VerifiedFinding]) {
        let existing: HashSet<(String, String)> = self
            .entries
            .iter()
            .map(|e| (e.detector_id.clone(), e.credential_hash.clone()))
            .collect();

        for finding in findings {
            let key = (
                finding.detector_id.to_string(),
                format!("sha256:{}", finding.credential_hash),
            );
            if !existing.contains(&key) {
                self.entries.push(BaselineEntry {
                    detector_id: finding.detector_id.to_string(),
                    credential_hash: key.1,
                    file_path: finding.location.file_path.as_ref().map(|p| p.to_string()),
                    line: finding.location.line,
                    status: "acknowledged".to_string(),
                });
            }
        }

        self.entries.sort_by(|a, b| {
            a.detector_id
                .cmp(&b.detector_id)
                .then(a.credential_hash.cmp(&b.credential_hash))
        });
        self.entries.dedup_by(|a, b| {
            a.detector_id == b.detector_id && a.credential_hash == b.credential_hash
        });
    }

    /// Returns `true` if the given finding matches an entry in the baseline.
    /// Matching is based solely on `(detector_id, credential_hash)`.
    ///
    /// O(N) — for hot paths (e.g. filtering a large finding set against a
    /// baseline) prefer `contains_set` + `index_set` to amortize lookups.
    pub fn contains(&self, finding: &VerifiedFinding) -> bool {
        let hash = format!("sha256:{}", finding.credential_hash);
        self.entries
            .iter()
            .any(|e| e.detector_id == finding.detector_id.as_ref() && e.credential_hash == hash)
    }

    /// Cached O(1) lookup set keyed by `(detector_id, credential_hash)`.
    /// Built once on first access via `OnceLock` and reused; subsequent
    /// `filter_new` / `contains` calls are O(N) total instead of O(N·M).
    pub fn index_set(&self) -> &HashSet<(String, String)> {
        self.cached_index.get_or_init(|| {
            self.entries
                .iter()
                .map(|e| (e.detector_id.clone(), e.credential_hash.clone()))
                .collect()
        })
    }

    /// Filter a slice of findings, returning only those **not** present in
    /// the baseline. Uses an O(1) HashSet lookup so total cost is O(N) in
    /// the number of findings instead of O(N·M).
    pub fn filter_new(&self, findings: &[VerifiedFinding]) -> Vec<VerifiedFinding> {
        let index = self.index_set();
        findings
            .iter()
            .filter(|f| {
                let key = (
                    f.detector_id.to_string(),
                    format!("sha256:{}", f.credential_hash),
                );
                !index.contains(&key)
            })
            .cloned()
            .collect()
    }
}
