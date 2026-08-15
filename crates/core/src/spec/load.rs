//! Detector loading pipeline: read TOML files and run the quality gate.

#![allow(clippy::result_large_err)] // SpecError carries a 128-byte toml::de::Error; boxing it would be a breaking API change.

use std::path::{Path, PathBuf};

use rayon::prelude::*;
use thiserror::Error;

use super::{
    migrate_legacy_success_policies, validate_detector, DetectorCorpusManifest, DetectorFile,
    DetectorSpec, QualityIssue, DETECTOR_CORPUS_MANIFEST_FILE,
    DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION, DETECTOR_CORPUS_MIN_SCHEMA_VERSION,
    DETECTOR_CORPUS_SCHEMA_VERSION,
};
pub use crate::detector_file_io::{read_detector_toml_file, DETECTOR_TOML_FILE_BYTES};

/// Errors returned while loading or validating detector specifications.
#[derive(Debug, Error)]
#[allow(clippy::result_large_err)] // SpecError variants include 128-byte toml::de::Error; boxing would be a breaking API change.
pub enum SpecError {
    #[error(
        "failed to read detector path {path}: {source}. Fix: check the detector path exists and that the file is readable TOML"
    )]
    /// A detector path could not be read.
    ReadFile {
        /// Detector path that failed to read.
        path: String,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    #[error(
        "invalid TOML in detector {path}: {source}. Fix: repair the TOML syntax in the detector file"
    )]
    /// A detector file is not valid TOML.
    InvalidToml {
        /// Detector file that failed to parse.
        path: PathBuf,
        /// Underlying TOML error.
        source: toml::de::Error,
    },
    #[error(
        "invalid detector corpus manifest {path}: {source}. Fix: set `schema_version` \
         to an integer supported by this keyhog binary and remove misspelled manifest fields"
    )]
    /// A directory `corpus.toml` manifest is not valid TOML.
    InvalidCorpusManifest {
        /// Manifest file that failed to parse.
        path: PathBuf,
        /// Underlying TOML error.
        source: toml::de::Error,
    },
    #[error(
        "unsupported detector corpus schema {found} declared by {path}; this binary \
         supports schema {current} and bounded forward compatibility through schema \
         {max_forward}. Fix: use a compatible detector corpus or update keyhog"
    )]
    /// A corpus declares a schema outside this binary's compatibility window.
    UnsupportedCorpusSchema {
        /// Manifest that declared the schema.
        path: PathBuf,
        /// Schema version the corpus declared.
        found: u32,
        /// Schema version this binary owns.
        current: u32,
        /// Highest schema this binary may inspect additively.
        max_forward: u32,
    },
    #[error(
        "detector corpus {dir} declares supported forward schema {declared_schema}, \
         while this binary owns schema {supported_schema}; {skipped_count} of {total} \
         detector file(s) use fields this binary cannot interpret. Keyhog refuses to \
         scan under newer parsing semantics or with a partial corpus because either \
         would invalidate corpus identity and could silently drop recall. \
         Compatibility detail:\n{detail}\nFix: update keyhog to load the complete \
         detector corpus"
    )]
    /// A newer corpus uses fields this binary cannot interpret, so loading it would silently drop recall.
    ForwardIncompatibleCorpus {
        /// Detector directory that was rejected.
        dir: String,
        /// Forward schema the corpus declared.
        declared_schema: u32,
        /// Schema version this binary owns.
        supported_schema: u32,
        /// Number of detector files this binary could not interpret.
        skipped_count: usize,
        /// Total detector files in the directory.
        total: usize,
        /// Per-file compatibility detail.
        detail: String,
    },
    #[error(
        "{failed_count} of {total} embedded detector(s) failed to parse, the binary \
         baked in a CORRUPT detector set, so its recall is silently degraded. This is \
         a build/source bug, not a runtime condition: the embedded corpus is compiled \
         in and cannot have been edited at runtime. Offending detector(s):\n{detail}\n\
         Fix: repair the named TOML(s) under `detectors/` (the toml error names the \
         line/column) and rebuild keyhog so build.rs re-embeds a valid set."
    )]
    /// The compiled-in detector corpus failed to parse, which is a build bug.
    EmbeddedCorpusCorrupt {
        /// Number of embedded detectors that failed to parse.
        failed_count: usize,
        /// Total embedded detectors.
        total: usize,
        /// Per-detector parse detail.
        detail: String,
    },
    #[error(
        "{failed_count} of {total} detector file(s) from {dir} failed to load, \
         pass the quality gate, or exist at all, that is a partial detector \
         corpus, so keyhog is refusing to scan without a complete detector \
         corpus (a partial corpus silently drops recall). \
         Offending detector(s):\n{detail}\nFix: repair the named TOML file(s) \
         or add at least one valid `*.toml` detector spec, then rerun the scan."
    )]
    /// A detector directory produced a partial corpus, which would silently drop recall.
    DetectorCorpusRejected {
        /// Detector directory that was rejected.
        dir: String,
        /// Number of detector files that failed to load or gate.
        failed_count: usize,
        /// Total detector files considered.
        total: usize,
        /// Per-file failure detail.
        detail: String,
    },
}

/// A validated detector corpus paired with the schema identity that selected
/// its normalization rules.
///
/// `schema_version` is the normalized directory identity: a missing manifest
/// is schema 1, while an explicit manifest contributes its declared version.
/// Keeping it beside `specs` prevents a caller from hashing normalized legacy
/// specs as though they had been authored under the current schema.
#[derive(Debug)]
pub struct LoadedDetectorCorpus {
    /// Fully parsed and validated detector specifications.
    pub specs: Vec<DetectorSpec>,
    /// Effective detector corpus schema version.
    pub schema_version: u32,
}

impl LoadedDetectorCorpus {
    /// Compute the schema-bound identity of these exact normalized specs.
    pub fn compute_digest(&self) -> Result<[u8; 32], serde_json::Error> {
        crate::compute_detector_corpus_digest_for_schema(&self.specs, self.schema_version)
    }
}

/// Load all detector specs from a directory of TOML files.
/// Runs the quality gate on each detector and fails closed if any detector
/// cannot be read, parsed, or accepted by the gate.
///
/// # Examples
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use keyhog_core::load_detectors;
/// use std::path::Path;
///
/// let detectors = load_detectors(Path::new("detectors"))?;
/// assert!(!detectors.is_empty());
/// # Ok(()) }
/// ```
pub fn load_detectors(dir: &Path) -> Result<Vec<DetectorSpec>, SpecError> {
    Ok(load_detector_corpus(dir)?.specs)
}

/// Load all detector specs together with their normalized corpus schema
/// identity.
pub fn load_detector_corpus(dir: &Path) -> Result<LoadedDetectorCorpus, SpecError> {
    load_detector_corpus_with_gate(dir, true)
}

/// Load detectors with optional quality gate enforcement.
/// When `enforce_gate` is `true`, detector read/parse/quality errors reject
/// the entire corpus instead of returning a partial detector set.
///
/// # Examples
///
/// ```ignore
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Crate-internal hook for tests and CLI detector-cache owner code.
/// use keyhog_core::spec::load::load_detectors_with_gate;
/// use std::path::Path;
///
/// let _detectors = load_detectors_with_gate(Path::new("detectors"), true)?;
/// # Ok(()) }
/// ```
#[derive(Clone, Copy)]
struct CorpusCompatibility {
    schema_version: u32,
    permits_forward_unknown_fields: bool,
}

pub(crate) fn load_detectors_with_gate(
    dir: &Path,
    enforce_gate: bool,
) -> Result<Vec<DetectorSpec>, SpecError> {
    Ok(load_detector_corpus_with_gate(dir, enforce_gate)?.specs)
}

fn load_detector_corpus_with_gate(
    dir: &Path,
    enforce_gate: bool,
) -> Result<LoadedDetectorCorpus, SpecError> {
    let compatibility = read_corpus_compatibility(dir)?;
    let toml_paths = discover_detector_tomls(dir, enforce_gate)?;
    let parsed = parse_detector_files(&toml_paths, compatibility);
    let specs = assemble_detector_load(dir, enforce_gate, compatibility, toml_paths.len(), parsed)?;
    Ok(LoadedDetectorCorpus {
        specs,
        schema_version: compatibility.schema_version,
    })
}

fn read_corpus_compatibility(dir: &Path) -> Result<CorpusCompatibility, SpecError> {
    let path = dir.join(DETECTOR_CORPUS_MANIFEST_FILE);
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CorpusCompatibility {
                schema_version: DETECTOR_CORPUS_MIN_SCHEMA_VERSION,
                permits_forward_unknown_fields: false,
            });
        }
        Err(source) => {
            return Err(SpecError::ReadFile {
                path: path.display().to_string(),
                source,
            });
        }
    };
    let manifest: DetectorCorpusManifest =
        toml::from_str(&contents).map_err(|source| SpecError::InvalidCorpusManifest {
            path: path.clone(),
            source,
        })?;
    if !(DETECTOR_CORPUS_MIN_SCHEMA_VERSION..=DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION)
        .contains(&manifest.schema_version)
    {
        return Err(SpecError::UnsupportedCorpusSchema {
            path,
            found: manifest.schema_version,
            current: DETECTOR_CORPUS_SCHEMA_VERSION,
            max_forward: DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION,
        });
    }
    Ok(CorpusCompatibility {
        schema_version: manifest.schema_version,
        permits_forward_unknown_fields: manifest.schema_version > DETECTOR_CORPUS_SCHEMA_VERSION,
    })
}

fn discover_detector_tomls(dir: &Path, enforce_gate: bool) -> Result<Vec<PathBuf>, SpecError> {
    let entries = std::fs::read_dir(dir).map_err(|e| SpecError::ReadFile {
        path: dir.display().to_string(),
        source: e,
    })?;
    let mut toml_paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| SpecError::ReadFile {
            path: format!("directory entry under {}", dir.display()),
            source: e,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml")
            && path
                .file_name()
                .is_none_or(|name| name != DETECTOR_CORPUS_MANIFEST_FILE)
        {
            toml_paths.push(path);
        }
    }

    if enforce_gate && toml_paths.is_empty() {
        return Err(SpecError::DetectorCorpusRejected {
            dir: dir.display().to_string(),
            failed_count: 0,
            total: 0,
            detail:
                "  - no detector TOML files found; add at least one valid `*.toml` detector spec"
                    .to_string(),
        });
    }
    Ok(toml_paths)
}

fn parse_detector_files(
    toml_paths: &[PathBuf],
    compatibility: CorpusCompatibility,
) -> Vec<ReadDetectorOutcome> {
    toml_paths
        .par_iter()
        .map(|path| read_detector_file(path, compatibility))
        .collect()
}

fn assemble_detector_load(
    dir: &Path,
    enforce_gate: bool,
    compatibility: CorpusCompatibility,
    total: usize,
    parsed: Vec<ReadDetectorOutcome>,
) -> Result<Vec<DetectorSpec>, SpecError> {
    let mut load_state = DetectorLoadState::default();
    let mut detectors = Vec::with_capacity(parsed.len());

    for outcome in parsed {
        match outcome {
            ReadDetectorOutcome::Loaded {
                path,
                spec,
                legacy_migrations,
            } => {
                load_state.legacy_migrations += legacy_migrations;
                if should_reject_detector(
                    &spec,
                    &path,
                    enforce_gate,
                    &mut load_state.gate_rejected,
                    &mut load_state.gate_errors,
                    &mut load_state.total_warnings,
                ) {
                    continue;
                }
                detectors.push(*spec);
            }
            ReadDetectorOutcome::ForwardSkipped { message } => {
                load_state.forward_skipped += 1;
                load_state.forward_errors.push(message);
            }
            ReadDetectorOutcome::Skipped { message } => {
                load_state.skipped += 1;
                load_state.load_errors.push(message);
            }
        }
    }

    // Sort before the duplicate-id scan so identical ids are adjacent and one
    // linear pass finds them. A detector id is a unique key, it selects the
    // checksum validator, suppression rules, and finding attribution, so two
    // detectors sharing an id silently shadow each other (the loser's
    // patterns/companions never fire). Law 10: surface it, don't let it pass.
    // Folded into the SAME gate as other corpus-integrity failures (fail closed
    // under the gate, logged otherwise) rather than a bespoke rejection path.
    detectors.sort_by(|a, b| a.id.cmp(&b.id));
    let mut duplicate_ids: Vec<&str> = detectors
        .windows(2)
        .filter(|w| w[0].id == w[1].id)
        .map(|w| w[0].id.as_str())
        .collect();
    duplicate_ids.dedup();
    if !duplicate_ids.is_empty() {
        load_state.gate_rejected += duplicate_ids.len();
        for id in duplicate_ids {
            load_state.gate_errors.push(format!(
                "duplicate detector id `{id}` (a later spec would shadow the earlier)"
            ));
        }
    }

    log_load_summary(&load_state);
    if enforce_gate && compatibility.permits_forward_unknown_fields {
        return Err(load_state.into_forward_error(dir, total, compatibility.schema_version));
    }
    if enforce_gate && load_state.has_failures() {
        return Err(load_state.into_rejected_error(dir, total));
    }
    Ok(detectors)
}

#[derive(Default)]
struct DetectorLoadState {
    skipped: usize,
    load_errors: Vec<String>,
    forward_skipped: usize,
    forward_errors: Vec<String>,
    legacy_migrations: usize,
    gate_rejected: usize,
    gate_errors: Vec<String>,
    total_warnings: usize,
}

impl DetectorLoadState {
    fn has_failures(&self) -> bool {
        self.skipped > 0 || self.forward_skipped > 0 || self.gate_rejected > 0
    }

    fn into_rejected_error(self, dir: &Path, total: usize) -> SpecError {
        let mut details = self.load_errors;
        details.extend(self.gate_errors);
        let detail = details
            .into_iter()
            .map(|line| format!("  - {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        SpecError::DetectorCorpusRejected {
            dir: dir.display().to_string(),
            failed_count: self.skipped + self.gate_rejected,
            total,
            detail,
        }
    }
    fn into_forward_error(self, dir: &Path, total: usize, declared_schema: u32) -> SpecError {
        let detail = if self.forward_errors.is_empty() {
            format!(
                "  - {} declares schema {}; schema metadata is part of effective \
                 corpus identity and cannot be interpreted as schema {}",
                dir.join(DETECTOR_CORPUS_MANIFEST_FILE).display(),
                declared_schema,
                DETECTOR_CORPUS_SCHEMA_VERSION
            )
        } else {
            self.forward_errors
                .into_iter()
                .map(|line| format!("  - {line}"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        SpecError::ForwardIncompatibleCorpus {
            dir: dir.display().to_string(),
            declared_schema,
            supported_schema: DETECTOR_CORPUS_SCHEMA_VERSION,
            skipped_count: self.forward_skipped,
            total,
            detail,
        }
    }
}

fn log_load_summary(state: &DetectorLoadState) {
    if state.skipped > 0 {
        // Aggregate into ONE actionable line instead of one warn! per file.
        // Unknown fields reaching this strict path are same-version typos or
        // undeclared version skew; a declared bounded-forward corpus is handled
        // separately below.
        let version_skew = state
            .load_errors
            .iter()
            .filter(|error| error.contains("unknown field"))
            .count();
        let examples = state
            .load_errors
            .iter()
            .take(3)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" | ");
        if version_skew > 0 {
            tracing::warn!(
                "skipped {} detector file(s); {} contain unknown fields while the corpus \
                 is using the current/legacy strict schema. Fix field typos, or add a \
                 supported newer `{}` declaration when the fields are intentional. \
                 Examples: {examples}",
                state.skipped,
                version_skew,
                DETECTOR_CORPUS_MANIFEST_FILE
            );
        } else {
            tracing::warn!(
                "skipped {} malformed/unreadable detector file(s) - run \
                 `keyhog detectors --detectors <DIR>` or -vv for the full list. \
                 Examples: {examples}",
                state.skipped
            );
        }
    }
    if state.forward_skipped > 0 {
        let examples = state
            .forward_errors
            .iter()
            .take(3)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(" | ");
        tracing::warn!(
            "detector corpus declared a supported forward schema; skipped {} detector \
             file(s) that use newer fields rather than silently dropping those fields. \
             Update keyhog for full recall. Examples: {examples}",
            state.forward_skipped
        );
    }
    if state.legacy_migrations > 0 {
        tracing::warn!(
            "migrated {} legacy schema-{} verifier success contract(s) to \
             status_with_error_backstop; add an explicit success policy and a \
             schema-{} corpus manifest",
            state.legacy_migrations,
            DETECTOR_CORPUS_MIN_SCHEMA_VERSION,
            DETECTOR_CORPUS_SCHEMA_VERSION
        );
    }
    if state.gate_rejected > 0 {
        // Law 10: quality-gate rejections are not silent. The per-detector
        // causes are logged at warn! below; the aggregate is surfaced at
        // the default level so operators see why the detector set would have
        // been smaller than expected.
        tracing::warn!(
            "quality gate rejected {} detectors (see per-detector warnings above)",
            state.gate_rejected
        );
    }
    if state.total_warnings > 0 {
        // Advisory (non-rejecting) quality warnings describe detector-AUTHORING
        // nits on the already-validated, shipped detector set (e.g. "companion
        // regex is a pure character class; ALLOWED because within_lines <= 5").
        // They are build-time/authoring feedback, not an operator signal: the
        // bundled detectors passed the gate, so re-announcing their advisories
        // on every user command that loads detectors (`explain`, `detectors`,
        // a custom `--detectors` dir) is noise that drowns out the real
        // rejections above. Keep them at debug! (visible with `-vv` /
        // RUST_LOG=keyhog=debug for authors); errors and gate REJECTIONS stay
        // loud above (Law 10).
        tracing::debug!("quality gate: {} advisory warnings", state.total_warnings);
    }
}

enum ReadDetectorOutcome {
    Loaded {
        path: PathBuf,
        spec: Box<DetectorSpec>,
        legacy_migrations: usize,
    },
    ForwardSkipped {
        message: String,
    },
    Skipped {
        message: String,
    },
}

const SEMANTIC_POLICY_SCHEMA_VERSION: u32 = 4;

fn declares_semantic_policy(contents: &str) -> Result<bool, toml::de::Error> {
    let document = toml::from_str::<toml::Value>(contents)?;
    let Some(detector) = document.get("detector").and_then(toml::Value::as_table) else {
        return Ok(false);
    };
    Ok([
        "capture_role",
        "anchor_role",
        "allowed_source_roles",
        "required_evidence",
    ]
    .iter()
    .any(|field| detector.contains_key(*field)))
}

fn read_detector_file(path: &Path, compatibility: CorpusCompatibility) -> ReadDetectorOutcome {
    let contents = match read_detector_toml_file(path) {
        Ok(contents) => contents,
        Err(error) => {
            // LAW10: reporting-only; per-file detail stays at debug! (visible
            // with -vv), while `log_load_summary` warns and gated loads reject.
            // One warn! per skipped file floods stderr on a version-skewed or
            // partly-broken corpus (dozens of near-identical lines before any
            // finding), which is the opposite of actionable.
            let message = format!("failed to read {}: {}", path.display(), error);
            tracing::debug!(
                detector_path = %path.display(),
                error = %error,
                "skipping detector - unreadable file" // LAW10: aggregate warning surfaces the skipped file count and examples; gated loads reject
            );
            return ReadDetectorOutcome::Skipped { message };
        }
    };
    if compatibility.schema_version < SEMANTIC_POLICY_SCHEMA_VERSION {
        match declares_semantic_policy(&contents) {
            Ok(true) => {
                return ReadDetectorOutcome::Skipped {
                    message: format!(
                        "{} declares semantic policy fields that require corpus schema {SEMANTIC_POLICY_SCHEMA_VERSION}; corpus.toml declares schema {}",
                        path.display(),
                        compatibility.schema_version
                    ),
                };
            }
            Ok(false) => {}
            Err(error) => {
                return ReadDetectorOutcome::Skipped {
                    message: format!(
                        "failed to inspect detector schema fields in {}: {error}",
                        path.display()
                    ),
                };
            }
        }
    }

    match toml::from_str::<DetectorFile>(&contents) {
        Ok(mut file) => {
            let legacy_migrations =
                if compatibility.schema_version == DETECTOR_CORPUS_MIN_SCHEMA_VERSION {
                    migrate_legacy_success_policies(&mut file.detector)
                } else {
                    0
                };
            ReadDetectorOutcome::Loaded {
                path: path.to_path_buf(),
                spec: Box::new(file.detector),
                legacy_migrations,
            }
        }
        Err(error) => {
            let unknown_field = error.to_string().contains("unknown field");
            if compatibility.permits_forward_unknown_fields && unknown_field {
                let message = format!(
                    "skipped {} under declared detector corpus schema {} because it uses \
                     a field unknown to schema {}: {}. Fix: update keyhog to load this detector",
                    path.display(),
                    compatibility.schema_version,
                    DETECTOR_CORPUS_SCHEMA_VERSION,
                    error
                );
                tracing::warn!(
                    detector_path = %path.display(),
                    declared_schema = compatibility.schema_version,
                    supported_schema = DETECTOR_CORPUS_SCHEMA_VERSION,
                    error = %error,
                    "skipping forward-schema detector without dropping unknown fields"
                );
                return ReadDetectorOutcome::ForwardSkipped { message };
            }
            let message = format!(
                "failed to parse {} under detector corpus schema {}: {}. Fix: correct \
                 misspelled or invalid detector fields; only a corpus manifest declaring \
                 a supported newer schema permits an unknown future field",
                path.display(),
                compatibility.schema_version,
                error
            );
            // LAW10: the default-level aggregate warning surfaces every skip,
            // and gated loads return DetectorCorpusRejected with this detail.
            tracing::debug!(
                detector_path = %path.display(),
                schema_version = compatibility.schema_version,
                error = %error,
                "skipping detector - TOML parse failed"
            );
            ReadDetectorOutcome::Skipped { message }
        }
    }
}

fn should_reject_detector(
    spec: &DetectorSpec,
    path: &Path,
    enforce_gate: bool,
    gate_rejected: &mut usize,
    gate_errors: &mut Vec<String>,
    total_warnings: &mut usize,
) -> bool {
    let mut has_errors = false;
    let mut detector_errors = Vec::new();
    for issue in validate_detector(spec) {
        match issue {
            QualityIssue::Warning(warning) => {
                // Advisory only - the detector still loads and scans. This is
                // authoring feedback (see the aggregate at debug! in
                // `log_load_summary`), so keep it at debug! to stay out of
                // user-facing command output; errors below stay loud (Law 10).
                tracing::debug!(detector_path = %path.display(), "quality: {} - {}", spec.id, warning);
                *total_warnings += 1;
            }
            QualityIssue::Error(error) => {
                // Law 10: a detector that fails the quality gate must not be
                // silently loaded. The warning names the detector and the
                // issue so the author can fix it; when enforce_gate is true
                // the detector is rejected below.
                tracing::warn!(
                    detector_path = %path.display(),
                    "detector quality error: {}: {}",
                    spec.id,
                    error
                );
                detector_errors.push(format!("{}: {}: {}", path.display(), spec.id, error));
                has_errors = true;
            }
        }
    }

    if has_errors && enforce_gate {
        *gate_rejected += 1;
        gate_errors.extend(detector_errors);
        return true;
    }

    false
}

/// Load a set of detectors from a TOML string.
///
/// This is primarily used for dynamic detector injection and tests that need
/// an in-memory detector corpus.
pub(crate) fn load_detectors_from_str(toml_str: &str) -> Result<Vec<DetectorSpec>, SpecError> {
    let file: DetectorFile = toml::from_str(toml_str).map_err(|e| SpecError::InvalidToml {
        path: PathBuf::from("<string>"),
        source: e,
    })?;
    Ok(vec![file.detector])
}
