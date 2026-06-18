//! Detector loading pipeline: read TOML files, run the quality gate, and inject
//! small compatibility shims for legacy token formats when needed.

#![allow(clippy::result_large_err)] // SpecError carries a 128-byte toml::de::Error; boxing it would be a breaking API change.

use std::io;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use super::{validate_detector, DetectorFile, DetectorSpec, QualityIssue, SpecError};

const DETECTOR_CACHE_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
struct DetectorCacheFile {
    version: u32,
    detectors: Vec<DetectorSpec>,
}

/// Save detectors to a JSON cache file for fast subsequent loads.
///
/// # Examples
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use keyhog_core::{DetectorSpec, save_detector_cache};
/// use std::path::Path;
///
/// let detectors: Vec<DetectorSpec> = Vec::new();
/// save_detector_cache(&detectors, Path::new(".keyhog-cache.json"))?;
/// # Ok(()) }
/// ```
pub fn save_detector_cache(
    detectors: &[DetectorSpec],
    cache_path: &Path,
) -> Result<(), std::io::Error> {
    for detector in detectors {
        let issues = validate_detector(detector);
        if issues
            .iter()
            .any(|issue| matches!(issue, QualityIssue::Error(_)))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "refusing to cache invalid detector '{}'. Fix: repair the detector before writing the cache",
                    detector.id
                ),
            ));
        }
    }

    let json = serde_json::to_vec(&DetectorCacheFile {
        version: DETECTOR_CACHE_VERSION,
        detectors: detectors.to_vec(),
    })?;
    // Atomic rename via NamedTempFile - same pattern as merkle index
    // and baseline. A mid-write crash used to leave a corrupt
    // `.keyhog-cache.json` that the next run would `tracing::warn!`
    // on and silently fall back to TOML-load (unbounded slowdown).
    // tempfile::Drop reaps the tmp on panic; persist atomic-renames
    // on success.
    let parent = cache_path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    std::io::Write::write_all(&mut tmp, &json)?;
    tmp.as_file().sync_all()?;
    tmp.persist(cache_path).map_err(|e| e.error)?;
    Ok(())
}

/// Load detectors from a JSON cache file. Returns None if cache is stale or missing.
///
/// # Examples
///
/// ```rust,no_run
/// use keyhog_core::load_detector_cache;
/// use std::path::Path;
///
/// let _cached = load_detector_cache(
///     Path::new(".keyhog-cache.json"),
///     Path::new("detectors"),
/// );
/// ```
///
/// # Security
///
/// Cached detectors are re-validated through the quality gate to prevent cache
/// poisoning attacks where a malicious `.keyhog-cache.json` injects evil regex
/// patterns that bypass the TOML quality gate.
pub fn load_detector_cache(cache_path: &Path, source_dir: &Path) -> Option<Vec<DetectorSpec>> {
    let cache_meta = std::fs::metadata(cache_path).ok()?;
    let cache_mtime = cache_meta.modified().ok()?;

    // Check if any TOML in source_dir is newer than the cache
    let entries = std::fs::read_dir(source_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "toml") {
            let is_stale = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .is_ok_and(|mtime| mtime > cache_mtime);

            if is_stale {
                return None; // Cache is stale
            }
        }
    }

    let data = match std::fs::read(cache_path) {
        Ok(data) => data,
        Err(error) => {
            tracing::warn!(
                "failed to read detector cache {}: {}",
                cache_path.display(),
                error
            );
            return None;
        }
    };
    let cache: DetectorCacheFile = match serde_json::from_slice(&data) {
        Ok(cache) => cache,
        Err(error) => {
            tracing::warn!(
                "failed to parse detector cache {}: {}",
                cache_path.display(),
                error
            );
            return None;
        }
    };
    if cache.version != DETECTOR_CACHE_VERSION {
        return None;
    }

    let mut validated = Vec::with_capacity(cache.detectors.len());
    for spec in cache.detectors {
        let issues = validate_detector(&spec);
        if issues
            .iter()
            .any(|issue| matches!(issue, QualityIssue::Error(_)))
        {
            tracing::warn!(
                "cached detector '{}' failed quality gate; discarding the entire cache",
                spec.id
            );
            return None;
        }
        validated.push(spec);
    }

    if validated.is_empty() {
        tracing::warn!("detector cache is empty after validation, falling back to TOML load");
        return None;
    }

    Some(validated)
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
    load_detectors_with_gate(dir, true)
}

/// Load detectors with optional quality gate enforcement.
/// When `enforce_gate` is `true`, detector read/parse/quality errors reject
/// the entire corpus instead of returning a partial detector set.
///
/// # Examples
///
/// ```rust,no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use keyhog_core::load_detectors_with_gate;
/// use std::path::Path;
///
/// let _detectors = load_detectors_with_gate(Path::new("detectors"), true)?;
/// # Ok(()) }
/// ```
pub fn load_detectors_with_gate(
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
/// This is primarily used for testing and dynamic detector injection.
pub fn load_detectors_from_str(toml_str: &str) -> Result<Vec<DetectorSpec>, SpecError> {
    let file: DetectorFile = toml::from_str(toml_str).map_err(|e| SpecError::InvalidToml {
        path: PathBuf::from("<string>"),
        source: e,
    })?;
    Ok(vec![file.detector])
}
