//! Specialized error types for the scanner engine.

use thiserror::Error;

#[derive(Debug, Error)]
/// Errors returned while compiling detector patterns into a scanner.
pub enum ScanError {
    #[error(
        "failed to compile regex for detector {detector_id} pattern {index}: {source}. Fix: correct the detector regex or capture group configuration"
    )]
    RegexCompile {
        detector_id: String,
        index: usize,
        source: regex::Error,
    },
    #[error(
        "detector {detector_id} pattern {index} declares capture group {group}, but its compiled regex has only {captures_len} group(s) (valid indices 0..{captures_len}). \
         An out-of-range group makes the engine fall back to the whole match, capturing the keyword and separator instead of the secret. \
         Fix: set `group` to a capture-group index that exists in the regex (group 0 is the whole match), or add the missing capture group"
    )]
    CaptureGroupOutOfRange {
        detector_id: String,
        index: usize,
        group: usize,
        captures_len: usize,
    },
    #[error(
        "failed to compile scanner regex set: {0}. Fix: simplify the detector regex set or remove the invalid pattern"
    )]
    RegexSetCompile(#[from] regex::Error),
    #[error(
        "failed to build Aho-Corasick literal matcher: {0}. Fix: check for empty or invalid detector keywords"
    )]
    AhoCorasick(#[from] aho_corasick::BuildError),
    #[error(
        "GPU scanner failure: {0}. Fix: rerun with `--backend cpu` to scan on the CPU path, or run `keyhog doctor` to diagnose the GPU stack"
    )]
    Gpu(String),
    #[error(
        "SIMD scanner failure: {0}. Fix: rerun with `--backend cpu` for the portable scalar path, or run `keyhog doctor` to check CPU feature detection"
    )]
    Simd(String),
    #[error(
        "compiled scanner invariant violation: {table}[{pattern_index}] references detector_index {detector_index} but only {detectors_len} detector(s) are loaded. Fix: rebuild detector compilation so every compiled pattern keeps its source detector index before scanner construction completes"
    )]
    CompiledPatternDetectorIndex {
        table: &'static str,
        pattern_index: usize,
        detector_index: usize,
        detectors_len: usize,
    },
    #[error("scanner configuration failure: {0}. Fix: correct the bundled scanner rules")]
    Config(String),
}

/// Specialized Result type for scanning operations.
pub type Result<T> = std::result::Result<T, ScanError>;
