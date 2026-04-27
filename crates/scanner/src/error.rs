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
        "failed to compile scanner regex set: {0}. Fix: simplify the detector regex set or remove the invalid pattern"
    )]
    RegexSetCompile(#[from] regex::Error),
    #[error(
        "failed to build Aho-Corasick literal matcher: {0}. Fix: check for empty or invalid detector keywords"
    )]
    AhoCorasick(#[from] aho_corasick::BuildError),
    #[error("GPU scanner failure: {0}")]
    Gpu(String),
    #[error("SIMD scanner failure: {0}")]
    Simd(String),
}

/// Specialized Result type for scanning operations.
pub type Result<T> = std::result::Result<T, ScanError>;
