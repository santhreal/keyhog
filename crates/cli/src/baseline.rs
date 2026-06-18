//! Baseline scanning support for the KeyHog CLI.
//!
//! Baselines allow teams to suppress known/acknowledged secrets so that
//! scanning an existing repository does not produce overwhelming noise.
//! A finding is suppressed if its `(detector_id, credential_hash)` pair
//! exists in the baseline. File path and line number are stored for
//! reference only - secrets may move between lines.

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
pub(crate) struct Baseline {
    pub version: u32,
    #[serde(default = "default_created")]
    pub created: String,
    pub entries: Vec<BaselineEntry>,
    #[serde(skip)]
    cached_index: std::sync::OnceLock<HashSet<(String, String)>>,
}

/// A single entry in a baseline file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct BaselineEntry {
    pub detector_id: String,
    pub credential_hash: String,
    #[serde(default, alias = "path", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default = "default_status")]
    pub status: String,
}

fn default_status() -> String {
    "acknowledged".to_string()
}

fn default_created() -> String {
    "unknown".to_string()
}

/// Heuristic used only to turn an opaque serde error into an actionable hint:
/// does this JSON look like a `scan` findings report rather than a baseline?
/// A baseline is a JSON object carrying `version` + `entries`; a findings
/// report is an array, or an object without that shape.
fn looks_like_findings_report(content: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(serde_json::Value::Array(_)) => true,
        Ok(serde_json::Value::Object(map)) => {
            !(map.contains_key("version") && map.contains_key("entries"))
        }
        _ => false,
    }
}

impl Baseline {
    /// Create an empty baseline with the current timestamp.
    pub(crate) fn empty() -> Self {
        Self {
            version: BASELINE_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            entries: Vec::new(),
            cached_index: std::sync::OnceLock::new(),
        }
    }

    /// Load a baseline from a JSON file.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline file {}", path.display()))?;
        let baseline: Baseline = serde_json::from_str(&content).map_err(|e| {
            // The #1 mistake here is feeding a `scan --format json` FINDINGS
            // report to `diff`, which wants a BASELINE file. The raw serde
            // error ("invalid type: map, expected u32") sends people chasing a
            // corruption bug that isn't there - detect the shape and point at
            // the command that actually produces a baseline.
            if looks_like_findings_report(&content) {
                anyhow::anyhow!(
                    "{p} is not a keyhog baseline file - it looks like a `scan` \
                     findings report (e.g. `--format json` output).\n       \
                     Create a baseline with:  keyhog scan <path> --create-baseline {p}",
                    p = path.display(),
                )
            } else {
                anyhow::Error::new(e).context(format!("parsing baseline file {}", path.display()))
            }
        })?;
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
    ///
    /// Atomic write: serialise to a `NamedTempFile` in the target
    /// directory, fsync, then atomic-rename onto the final path. If
    /// keyhog crashes (panic, SIGTERM, OOM-kill) before the rename
    /// completes, the user's existing baseline is intact and the
    /// tmp file is reaped by `NamedTempFile`'s Drop. Without this
    /// pattern a mid-write `--update-baseline` could leave a half-
    /// written JSON that the next run can't parse.
    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating baseline parent dir {}", parent.display()))?;
        let serialized = serde_json::to_vec_pretty(self)
            .with_context(|| format!("serializing baseline for {}", path.display()))?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("creating baseline tmp in {}", parent.display()))?;
        std::io::Write::write_all(&mut tmp, &serialized)
            .with_context(|| format!("writing baseline tmp for {}", path.display()))?;
        tmp.as_file()
            .sync_all()
            .with_context(|| format!("fsyncing baseline tmp for {}", path.display()))?;
        tmp.persist(path)
            .map_err(|e| e.error)
            .with_context(|| format!("renaming baseline tmp onto {}", path.display()))?;
        Ok(())
    }

    /// Build a new baseline from a slice of findings.
    /// Entries are deduplicated by `(detector_id, credential_hash)`.
    pub(crate) fn from_findings(findings: &[VerifiedFinding]) -> Self {
        let mut entries: Vec<BaselineEntry> = findings
            .iter()
            .map(|f| BaselineEntry {
                detector_id: f.detector_id.to_string(),
                // `credential_hash` is the raw 32 bytes; the baseline stores the
                // hex form prefixed with the algorithm (hex at the serde boundary).
                credential_hash: format!("sha256:{}", keyhog_core::hex_encode(&f.credential_hash)),
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
    pub(crate) fn merge(&mut self, findings: &[VerifiedFinding]) {
        let existing: HashSet<(String, String)> = self
            .entries
            .iter()
            .map(|e| (e.detector_id.clone(), e.credential_hash.clone()))
            .collect();

        for finding in findings {
            let key = (
                finding.detector_id.to_string(),
                format!(
                    "sha256:{}",
                    keyhog_core::hex_encode(&finding.credential_hash)
                ),
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
    /// O(N) - for hot paths (e.g. filtering a large finding set against a
    /// baseline) prefer `contains_set` + `index_set` to amortize lookups.
    pub(crate) fn contains(&self, finding: &VerifiedFinding) -> bool {
        let hash = format!(
            "sha256:{}",
            keyhog_core::hex_encode(&finding.credential_hash)
        );
        self.entries
            .iter()
            .any(|e| e.detector_id == finding.detector_id.as_ref() && e.credential_hash == hash)
    }

    /// Cached O(1) lookup set keyed by `(detector_id, credential_hash)`.
    /// Built once on first access via `OnceLock` and reused; subsequent
    /// `filter_new` / `contains` calls are O(N) total instead of O(N·M).
    pub(crate) fn index_set(&self) -> &HashSet<(String, String)> {
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
    pub(crate) fn filter_new(&self, findings: &[VerifiedFinding]) -> Vec<VerifiedFinding> {
        let index = self.index_set();
        findings
            .iter()
            .filter(|f| {
                let key = (
                    f.detector_id.to_string(),
                    format!("sha256:{}", keyhog_core::hex_encode(&f.credential_hash)),
                );
                !index.contains(&key)
            })
            .cloned()
            .collect()
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    use anyhow::Result;
    use keyhog_core::VerifiedFinding;
    use std::path::Path;

    pub(crate) fn baseline_version() -> u32 {
        super::BASELINE_VERSION
    }

    pub(crate) fn looks_like_findings_report(content: &str) -> bool {
        super::looks_like_findings_report(content)
    }

    pub(crate) fn empty() -> super::Baseline {
        super::Baseline::empty()
    }

    pub(crate) fn load(path: &Path) -> Result<super::Baseline> {
        super::Baseline::load(path)
    }

    pub(crate) fn save(baseline: &super::Baseline, path: &Path) -> Result<()> {
        baseline.save(path)
    }

    pub(crate) fn from_findings(findings: &[VerifiedFinding]) -> super::Baseline {
        super::Baseline::from_findings(findings)
    }

    pub(crate) fn merge(baseline: &mut super::Baseline, findings: &[VerifiedFinding]) {
        baseline.merge(findings);
    }

    pub(crate) fn contains(baseline: &super::Baseline, finding: &VerifiedFinding) -> bool {
        baseline.contains(finding)
    }

    pub(crate) fn filter_new(
        baseline: &super::Baseline,
        findings: &[VerifiedFinding],
    ) -> Vec<VerifiedFinding> {
        baseline.filter_new(findings)
    }
}
