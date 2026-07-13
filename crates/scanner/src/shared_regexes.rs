//! Compiled regexes shared across multiple scan passes.
//!
//! Each entry is a `LazyLock<Regex>` over a hardcoded compile-time-constant
//! pattern. Its consumers SKIP their scan pass when the regex is absent, so a
//! silent "disabled" degrade would be an invisible recall loss; the init instead
//! fails closed (panics), a regex-crate defect being a build bug, not a runtime
//! condition an operator can act on (Law 10).

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
pub(crate) static ASSIGN_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Law 10: hardcoded compile-time-constant pattern. Both consumers
    // (`scan_fragment_assignments`, `collect_structural_fragments`) SKIP their
    // scan pass when this regex is absent, so a silent `None` on compile failure
    // is an INVISIBLE recall loss, not a recall-preserving degrade. Fail closed:
    // a compile failure here is a regex-crate version defect, surfaced loudly at
    // build/startup, never a silent runtime downgrade.
    let pattern = r#"(?i)([a-z0-9_-]{2,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_-]{4,})["'`](?:;|,)?$"#;
    match Regex::new(pattern) {
        Ok(re) => re,
        Err(error) => panic!(
            "BUG: hardcoded ASSIGN_RE must compile; a failure is a regex-crate \
             version defect: {error}"
        ),
    }
});

pub(crate) fn warm_runtime_regexes() {
    LazyLock::force(&ASSIGN_RE); // warm-up: eager-init the shared regex
}
