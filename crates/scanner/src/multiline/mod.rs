//! Multi-line string concatenation preprocessor.
//!
//! Detects and joins string concatenation patterns across lines for multiple languages.
//! This allows the scanner to detect secrets that are split across lines using various
//! concatenation syntaxes.

mod config;
pub mod fragment_cache;
mod preprocessor;
mod structural;

#[allow(unused_imports)]
pub(crate) use config::has_concatenation_indicators;
pub use config::{LineMapping, MultilineConfig, PreprocessedText};
pub(crate) use preprocessor::extract_prefix;
pub use preprocessor::preprocess_multiline;
