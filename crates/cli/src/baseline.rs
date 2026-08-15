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

const BASELINE_VERSION: u32 = 2;

/// Canonical baseline serialization of a credential hash: the `sha256:`-prefixed
/// lowercase-hex form stored in, and matched against, baseline entries. One
/// definition so `from_findings` / `merge` / `contains` / `filter_new` can never
/// drift to different spellings of the same key. (Note: this `sha256:`-prefixed
/// form is baseline-specific; the SARIF `partialFingerprints` and `.keyhogignore`
/// `hash:` surfaces use the bare hex without the prefix.)
fn baseline_hash_key(hash: &keyhog_core::CredentialHash) -> String {
    format!("sha256:{}", keyhog_core::hex_encode(hash))
}

/// A baseline file containing acknowledged secrets.
///
/// `entries` is the canonical persisted form. `cached_index` is built lazily
/// on first lookup and reused across subsequent `filter_new` / `contains`
/// calls so we don't re-hash every entry on every call. Constructors that
/// know the entry list will not change can call `build_index()` to amortize.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(crate) struct BaselineEntry {
    pub detector_id: String,
    pub credential_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Evidence verdict recorded when this finding was acknowledged.
    pub evidence: keyhog_core::EvidenceVerdict,
}

fn default_created() -> String {
    "unknown".to_string()
}

/// Heuristic used only to turn an opaque serde error into an actionable hint:
/// does this JSON look like a `scan` findings report rather than a baseline?
/// A baseline is a JSON object carrying `version` + `entries`; a findings
/// report is a legacy array or a versioned object carrying `findings`.
fn looks_like_findings_report(content: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(serde_json::Value::Array(_)) => true,
        Ok(serde_json::Value::Object(map)) => {
            map.contains_key("findings")
                || !(map.contains_key("version") && map.contains_key("entries"))
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
        // Baseline load/parse is Preprocess-stage work.
        let _span = keyhog_profile::span(keyhog_profile::Stage::Preprocess);
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline file {}", path.display()))?;
        if looks_like_findings_report(&content) {
            anyhow::bail!(
                "{p} is not a keyhog baseline file - it looks like a `scan` \
                 findings report (for example `--format json` output).\n       \
                 Create a baseline with:  keyhog scan <path> --create-baseline {p}",
                p = path.display(),
            );
        }
        #[derive(Deserialize)]
        struct BaselineVersion {
            version: u32,
        }
        let version: BaselineVersion = serde_json::from_str(&content)
            .with_context(|| format!("parsing baseline file {}", path.display()))?;
        if version.version != BASELINE_VERSION {
            anyhow::bail!(
                "unsupported baseline version {} (expected {})",
                version.version,
                BASELINE_VERSION
            );
        }
        serde_json::from_str(&content)
            .with_context(|| format!("parsing baseline file {}", path.display()))
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
        // Baseline persistence is Reporting-stage work.
        let _span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
        let serialized = serde_json::to_vec_pretty(self)
            .with_context(|| format!("serializing baseline for {}", path.display()))?;
        crate::atomic_file::write_bytes(path, &serialized)
            .with_context(|| format!("atomically writing baseline {}", path.display()))?;
        Ok(())
    }

    /// Build a new baseline from a slice of findings.
    /// Entries are deduplicated by `(detector_id, credential_hash)`.
    pub(crate) fn from_findings(findings: &[VerifiedFinding]) -> Self {
        // Entry insertion with sort/dedup is ResultMerge-stage work.
        let _span = keyhog_profile::span(keyhog_profile::Stage::ResultMerge);
        let mut entries: Vec<BaselineEntry> = findings
            .iter()
            .map(|f| BaselineEntry {
                detector_id: f.detector_id.to_string(),
                // `credential_hash` is the raw 32 bytes; the baseline stores the
                // hex form prefixed with the algorithm (hex at the serde boundary).
                credential_hash: baseline_hash_key(&f.credential_hash),
                file_path: f.location.file_path.as_ref().map(|p| p.to_string()),
                line: f.location.line,
                evidence: f.evidence,
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
        // Merge/update entry insertion is ResultMerge-stage work.
        let _span = keyhog_profile::span(keyhog_profile::Stage::ResultMerge);
        let existing: HashSet<(String, String)> = self
            .entries
            .iter()
            .map(|e| (e.detector_id.clone(), e.credential_hash.clone()))
            .collect();

        for finding in findings {
            let key = (
                finding.detector_id.to_string(),
                baseline_hash_key(&finding.credential_hash),
            );
            if !existing.contains(&key) {
                self.entries.push(BaselineEntry {
                    detector_id: finding.detector_id.to_string(),
                    credential_hash: key.1,
                    file_path: finding.location.file_path.as_ref().map(|p| p.to_string()),
                    line: finding.location.line,
                    evidence: finding.evidence,
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
        // Baseline matching is Suppression-stage work.
        let _span = keyhog_profile::span(keyhog_profile::Stage::Suppression);
        let hash = baseline_hash_key(&finding.credential_hash);
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

    /// Compute the in-order keep mask without cloning finding graphs. Baseline
    /// update uses this before merging, then applies it after the complete
    /// finding set has been persisted.
    pub(crate) fn new_finding_mask(&self, findings: &[VerifiedFinding]) -> Vec<bool> {
        let index = self.index_set();
        findings
            .iter()
            .map(|finding| {
                let key = (
                    finding.detector_id.to_string(),
                    baseline_hash_key(&finding.credential_hash),
                );
                !index.contains(&key)
            })
            .collect()
    }

    /// Filter findings in their existing allocation so suppression does not
    /// retain old and replacement `VerifiedFinding` graphs at the same time.
    pub(crate) fn retain_new(&self, findings: &mut Vec<VerifiedFinding>) {
        let keep = self.new_finding_mask(findings);
        Self::retain_mask(findings, &keep);
    }
    /// Apply a previously computed mask without reallocating the finding
    /// vector. The mask and findings originate from the same ordered slice.
    pub(crate) fn retain_mask(findings: &mut Vec<VerifiedFinding>, mask: &[bool]) {
        debug_assert_eq!(findings.len(), mask.len());
        let mut remaining = mask;
        findings.retain(|_| {
            let Some((&keep, tail)) = remaining.split_first() else {
                return false;
            };
            remaining = tail;
            keep
        });
        debug_assert!(remaining.is_empty());
    }

    /// Filter a slice of findings, returning only those **not** present in
    /// the baseline. Uses an O(1) HashSet lookup so total cost is O(N) in
    /// the number of findings instead of O(N·M).
    pub(crate) fn filter_new(&self, findings: &[VerifiedFinding]) -> Vec<VerifiedFinding> {
        // Baseline filtering is Suppression-stage work.
        let _span = keyhog_profile::span(keyhog_profile::Stage::Suppression);
        let mut filtered = findings.to_vec();
        self.retain_new(&mut filtered);
        filtered
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) fn baseline_version() -> u32 {
        super::BASELINE_VERSION
    }

    pub(crate) fn looks_like_findings_report(content: &str) -> bool {
        super::looks_like_findings_report(content)
    }
}
