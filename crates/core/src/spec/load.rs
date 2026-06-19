//! Detector loading pipeline: read TOML files, run the quality gate, and inject
//! small compatibility shims for legacy token formats when needed.

#![allow(clippy::result_large_err)] // SpecError carries a 128-byte toml::de::Error; boxing it would be a breaking API change.

use std::path::{Path, PathBuf};

use rayon::prelude::*;

use super::{validate_detector, DetectorFile, DetectorSpec, QualityIssue, SpecError};

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
    load_detectors_with_gate(dir, true)
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
pub(crate) fn load_detectors_with_gate(
    dir: &Path,
    enforce_gate: bool,
) -> Result<Vec<DetectorSpec>, SpecError> {
    // Phase 1: collect all TOML file paths (fast, sequential)
    let entries = std::fs::read_dir(dir).map_err(|e| SpecError::ReadFile {
        path: dir.display().to_string(),
        source: e,
    })?;
    let mut toml_paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| SpecError::ReadFile {
            path: dir.display().to_string(),
            source: e,
        })?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            toml_paths.push(path);
        }
    }

    // Phase 2: read + parse all TOMLs in parallel
    let parsed: Vec<ReadDetectorOutcome> = toml_paths
        .par_iter()
        .map(|path| read_detector_file(path))
        .collect();

    // Phase 3: validate + filter (sequential for logging)
    let mut load_state = DetectorLoadState::default();
    let mut detectors = Vec::with_capacity(parsed.len());

    for outcome in parsed {
        match outcome {
            ReadDetectorOutcome::Loaded(spec) => {
                if should_reject_detector(
                    &spec,
                    enforce_gate,
                    &mut load_state.gate_rejected,
                    &mut load_state.gate_errors,
                    &mut load_state.total_warnings,
                ) {
                    continue;
                }
                detectors.push(*spec);
            }
            ReadDetectorOutcome::Skipped { message } => {
                load_state.skipped += 1;
                load_state.load_errors.push(message);
            }
        }
    }

    log_load_summary(&load_state);
    if enforce_gate && load_state.has_failures() {
        return Err(load_state.into_rejected_error(dir, toml_paths.len()));
    }

    detectors.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(detectors)
}

#[derive(Default)]
struct DetectorLoadState {
    skipped: usize,
    load_errors: Vec<String>,
    gate_rejected: usize,
    gate_errors: Vec<String>,
    total_warnings: usize,
}

impl DetectorLoadState {
    fn has_failures(&self) -> bool {
        self.skipped > 0 || self.gate_rejected > 0
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
}

fn log_load_summary(state: &DetectorLoadState) {
    if state.skipped > 0 {
        tracing::warn!("skipped {} malformed detector files", state.skipped);
    }
    for error in &state.load_errors {
        tracing::warn!("detector load issue: {error}");
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
        tracing::warn!("quality gate: {} warnings", state.total_warnings);
    }
}

enum ReadDetectorOutcome {
    Loaded(Box<DetectorSpec>),
    Skipped { message: String },
}

fn read_detector_file(path: &Path) -> ReadDetectorOutcome {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            // Bumped from `debug!` to `warn!`. A user with a broken
            // permission/typoed-path detector deserves to see the
            // reason at default log level - not "all detectors
            // appeared to load" silently. The path is included so
            // operators can grep for it.
            let message = format!("failed to read {}: {}", path.display(), error);
            tracing::warn!(
                detector_path = %path.display(),
                error = %error,
                "skipping detector - fix the file's permissions or path \
                 (run `keyhog detectors --detectors <DIR>` for the full skip list)"
            );
            return ReadDetectorOutcome::Skipped { message };
        }
    };

    match toml::from_str::<DetectorFile>(&contents) {
        Ok(file) => ReadDetectorOutcome::Loaded(Box::new(file.detector)),
        Err(error) => {
            // Same rationale: a TOML parse error (line + column
            // included by the toml crate's Display impl) needs to
            // surface to the user. Default `debug!` hid these
            // entirely under the keyhog=warn filter, so a single
            // mistyped field would silently drop one detector
            // from the corpus and never tell the user.
            let message = format!("failed to parse {}: {}", path.display(), error);
            tracing::warn!(
                detector_path = %path.display(),
                error = %error,
                "skipping detector - TOML parse failed, fix the syntax \
                 in the file at the indicated line/column"
            );
            ReadDetectorOutcome::Skipped { message }
        }
    }
}

fn should_reject_detector(
    spec: &DetectorSpec,
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
                tracing::warn!("quality: {} - {}", spec.id, warning);
                *total_warnings += 1;
            }
            QualityIssue::Error(error) => {
                // Law 10: a detector that fails the quality gate must not be
                // silently loaded. The warning names the detector and the
                // issue so the author can fix it; when enforce_gate is true
                // the detector is rejected below.
                tracing::warn!("detector quality error: {}: {}", spec.id, error);
                detector_errors.push(format!("{}: {}", spec.id, error));
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
