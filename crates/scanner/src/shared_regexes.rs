//! Compiled regexes shared across multiple scan passes.
//!
//! Each entry is a `LazyLock<Option<Regex>>` so an upstream `regex` crate
//! version that tightens validation degrades to "feature disabled" rather
//! than poisoning the LazyLock and crashing every worker.

use regex::Regex;
use std::sync::LazyLock;

/// `key = "value"` / `key: "value"` assignment pattern, matched per-line.
///
/// Used by both `engine::mod::CompiledScanner::scan_fragment_assignments`
/// (for cross-line fragment reassembly inside one chunk) and
/// `multiline::structural::collect_structural_fragments` (for the
/// preprocessor pass over multi-line code blocks). Pre-consolidation
/// the same regex source was defined in both files; any future
/// adjustment had to land in two places or the two scan paths would
/// diverge silently. Single source now (kimi-dedup audit row #9).
pub(crate) static ASSIGN_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)([a-z0-9_-]{2,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_-]{4,})["'`](?:;|,)?$"#).ok()
});

pub(crate) fn warm_runtime_regexes() {
    let _ = ASSIGN_RE.as_ref();
}
