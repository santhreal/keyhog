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
    pub fn save(&self, path: &Path) -> Result<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
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
    /// O(N) - for hot paths (e.g. filtering a large finding set against a
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn findings_report_array_is_recognized() {
        // `scan --format json` emits a top-level ARRAY of findings.
        assert!(looks_like_findings_report(
            r#"[{"detector_id":"hot-github_pat","line":1}]"#
        ));
    }

    #[test]
    fn findings_report_object_without_baseline_keys_is_recognized() {
        // An object lacking version+entries is not a baseline.
        assert!(looks_like_findings_report(r#"{"results":[],"summary":{}}"#));
    }

    #[test]
    fn real_baseline_is_not_flagged_as_findings_report() {
        assert!(!looks_like_findings_report(
            r#"{"version":1,"created":"now","entries":[]}"#
        ));
    }

    #[test]
    fn load_of_scan_report_gives_actionable_error_not_serde_noise() {
        // Regression: feeding a `scan --format json` report to `diff` used to
        // surface "invalid type: map, expected u32", which reads like file
        // corruption. It must instead name the right command.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, r#"[{{"detector_id":"hot-github_pat","line":1}}]"#).unwrap();
        let err = Baseline::load(tmp.path()).expect_err("a findings array is not a baseline");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("--create-baseline"),
            "error must point at `--create-baseline`, got: {msg}"
        );
        assert!(
            !msg.contains("expected u32"),
            "raw serde noise must be suppressed, got: {msg}"
        );
    }

    #[test]
    fn load_of_valid_baseline_roundtrips() {
        let b = Baseline::empty();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", serde_json::to_string(&b).unwrap()).unwrap();
        let loaded = Baseline::load(tmp.path()).expect("valid baseline loads");
        assert_eq!(loaded.version, BASELINE_VERSION);
    }
}
