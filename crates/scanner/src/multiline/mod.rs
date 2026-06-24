//! Multi-line string concatenation preprocessor.
//!
//! Detects and joins string concatenation patterns across lines for multiple languages.
//! This allows the scanner to detect secrets that are split across lines using various
//! concatenation syntaxes.

mod config;
#[cfg(feature = "multiline")]
mod preprocessor;
mod string_extract;
#[cfg(feature = "multiline")]
mod structural;

#[cfg(feature = "multiline")]
pub(crate) use config::has_concatenation_indicators;
pub use config::MultilineConfig;
#[cfg(feature = "multiline")]
pub(crate) use config::{LineMapping, PreprocessedText};
#[cfg(feature = "multiline")]
pub(crate) use preprocessor::preprocess_multiline;
pub(crate) use string_extract::{extract_prefix, fragment_assignment_name_is_credential_like};

#[cfg(feature = "multiline")]
pub(crate) fn collect_structural_fragments_for_test(
    lines: &[&str],
    source_line_offsets: &[usize],
    initial_offset: usize,
    fragment_cache: &crate::fragment_cache::FragmentCache,
) -> (Vec<String>, Vec<LineMapping>) {
    structural::collect_structural_fragments(
        lines,
        source_line_offsets,
        initial_offset,
        fragment_cache,
    )
}

#[cfg(feature = "multiline")]
pub(crate) fn warm_runtime_regexes() {
    config::warm_runtime_regexes();
    structural::warm_runtime_regexes();
}

#[cfg(not(feature = "multiline"))]
pub(crate) fn warm_runtime_regexes() {}
