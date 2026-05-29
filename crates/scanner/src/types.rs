//! Internal types and constants for the scanning engine.

use regex::Regex;
use std::sync::Arc;

// Fallback regex-only scanning switches to per-line mode once a chunk grows
// beyond 10 KB. Prefixless regexes over larger blobs are expensive and secrets
// are short enough that line-local scanning preserves recall.
pub const LARGE_FALLBACK_SCAN_THRESHOLD: usize = 10_000;

/// Hard cap on the dedup set to prevent unbounded memory growth when scanning
/// repositories with millions of duplicate credential-like strings.
pub const MAX_WINDOW_DEDUP_ENTRIES: usize = 100_000;

/// Maximum bytes scanned in a single chunk. Files larger than this are split
/// into overlapping windows. 1 MiB keeps peak RSS predictable under parallel
/// scanning with `rayon` (N threads × 1 MiB per chunk = bounded memory).
pub const MAX_SCAN_CHUNK_BYTES: usize = 1024 * 1024;

/// Overlap between adjacent scan windows when a file exceeds
/// `MAX_SCAN_CHUNK_BYTES`. Must be larger than the longest secret the scanner
/// can detect to avoid missing secrets that straddle a chunk boundary.
/// 128 KiB covers PEM-encoded RSA-8192 keys, large JWTs, and multi-line
/// concatenated secrets with generous margin.
pub const WINDOW_OVERLAP_BYTES: usize = 128 * 1024;

/// Minimum line length considered for fallback pattern scanning. Lines shorter
/// than 8 bytes cannot contain a credential prefix plus a meaningful secret.
pub const MIN_FALLBACK_LINE_LENGTH: usize = 8;

/// Minimum AC literal prefix length. Shorter prefixes (e.g., "1", "x", "_")
/// match too many positions and degrade Aho-Corasick throughput.
pub const FULL_MATCH_INDEX: usize = 0;
pub const FIRST_CAPTURE_GROUP_INDEX: usize = 1;
pub const FIRST_LINE_NUMBER: usize = 1;
pub const PREVIOUS_LINE_DISTANCE: usize = 1;
pub const MIN_LITERAL_PREFIX_CHARS: usize = 3;

/// Default per-regex AST + lazy-DFA-cache size limit. 1 MiB is large enough for
/// complex detectors while preventing pathological patterns from consuming
/// unbounded memory during regex compilation.
///
/// `dfa_size_limit` is a PER-THREAD, PER-REGEX CEILING on the lazy-DFA cache:
/// the regex builds DFA states on demand up to this cap, then evicts/falls back
/// rather than growing unbounded. It bounds the WORST case (pathological or
/// state-heavy patterns); for the typical detector corpus the per-thread caches
/// stay well below 1 MiB, so lowering this does NOT measurably reduce peak RSS
/// (measured: 1 MiB vs 64 KiB on a 32-core release scan = no change). It shows
/// up prominently in `perf -e page-faults` (alloc/grow CHURN, a CPU cost) but
/// that churn is reused, not retained - so this is a safety/throughput ceiling,
/// not the lever for the large per-scan resident footprint. Tunable at runtime
/// via [`set_regex_dfa_limit`] (`keyhog scan --regex-dfa-limit`, or
/// `regex_dfa_limit` in `.keyhog.toml`).
pub const REGEX_SIZE_LIMIT_BYTES: usize = 1 << 20; // 1 MiB default

/// Process-wide effective regex DFA limit, overridable from config/CLI. `0`
/// means "unset - use [`REGEX_SIZE_LIMIT_BYTES`]". Set ONCE at scan startup
/// (before any [`LazyRegex`] compiles) via [`set_regex_dfa_limit`]; read by the
/// regex builders in `compiler_compile`. Mirrors the `megascan_input_len`
/// process-global pattern so the per-detector lazy-compile path needs no
/// per-call plumbing.
static REGEX_DFA_LIMIT_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Override the per-regex DFA size limit for this process. Call before scanning.
/// `0` resets to the compiled default. Tier-A config knob (default → TOML → CLI).
pub fn set_regex_dfa_limit(bytes: usize) {
    REGEX_DFA_LIMIT_OVERRIDE.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

/// The effective per-regex DFA size limit: the override if set, else the
/// compiled default [`REGEX_SIZE_LIMIT_BYTES`].
#[must_use]
pub fn regex_dfa_limit() -> usize {
    match REGEX_DFA_LIMIT_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => REGEX_SIZE_LIMIT_BYTES,
        n => n,
    }
}

/// How many characters around a hex match to inspect for structural context
/// (assignment operators, quotes, keywords).
pub const HEX_CONTEXT_RADIUS_CHARS: usize = 20;

/// Minimum length for a standalone hex string to qualify as a potential secret.
/// Shorter hex runs (e.g., CSS colors like `#ff00ff`) are too common.
pub const MIN_HEX_MATCH_LEN: usize = 16;
pub const MIN_HEX_DIGITS_IN_MATCH: usize = 16;

/// Minimum hex digits required in the context window around a match to trigger
/// hex-aware false-positive suppression.
pub const MIN_HEX_CONTEXT_DIGITS: usize = 8;

/// Maximum non-hex separators (colons, dashes) tolerated within a hex context
/// window before the match is treated as a non-hex string.
pub const MAX_HEX_CONTEXT_SEPARATORS: usize = 4;

#[cfg(feature = "ml")]
pub const MAX_ML_CACHE_ENTRIES: usize = 1024;
#[cfg(feature = "ml")]
pub const MAX_ML_CACHE_BYTES: usize = 256 * 1024;
#[cfg(feature = "ml")]
pub const ML_CONTEXT_RADIUS_LINES: usize = 5;
#[cfg(feature = "ml")]
pub const ML_WEIGHT: f64 = 0.6;
#[cfg(feature = "ml")]
pub const HEURISTIC_WEIGHT: f64 = 0.4;

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
pub struct LineMapping {
    pub start_offset: usize,
    pub end_offset: usize,
    pub line_number: usize,
}

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
pub struct PreprocessedText {
    pub text: String,
    pub mappings: Vec<LineMapping>,
}

#[cfg(not(feature = "multiline"))]
impl PreprocessedText {
    /// Map a preprocessed-text offset back to an original line number.
    /// Binary search; same monotonic-mappings invariant as the
    /// multiline variant - see that doc for the analysis.
    pub fn line_for_offset(&self, offset: usize) -> Option<usize> {
        let idx = self.mappings.partition_point(|m| m.start_offset <= offset);
        if idx == 0 {
            return None;
        }
        let m = &self.mappings[idx - 1];
        if offset < m.end_offset {
            Some(m.line_number)
        } else {
            None
        }
    }

    pub fn passthrough(line: &str) -> Self {
        Self {
            text: line.to_string(),
            mappings: vec![LineMapping {
                line_number: 1,
                start_offset: 0,
                end_offset: line.len(),
            }],
        }
    }
}

#[cfg(feature = "multiline")]
pub type ScannerPreprocessedText = crate::multiline::PreprocessedText;

#[cfg(not(feature = "multiline"))]
pub type ScannerPreprocessedText = PreprocessedText;

/// A detector pattern whose `Regex` is compiled on first use, not at load.
///
/// Building the full ~1000-pattern corpus up front cost ~450ms (Hyperscan
/// path) to ~2.3s (portable regex path) on EVERY invocation - even to scan a
/// one-line file where a single detector fires. The Aho-Corasick literal
/// prefilter already decides which patterns a given input could match;
/// deferring each pattern's `Regex::build` until that prefilter (or a
/// keyword-gated fallback sweep) actually needs it means a typical scan
/// compiles a handful of patterns instead of all of them. Startup drops to
/// the cost of the AC automaton plus the few regexes that fire.
///
/// `as_str()` returns the source with no compilation, so the Hyperscan /
/// GPU literal-set builders that only read pattern text stay zero-cost.
///
/// The compiled `Arc<Regex>` is shared across clones of the same pattern
/// (the `cell` is `Arc`-shared) and, for the detector flavor, across all
/// detectors with an identical pattern string via the process-wide regex
/// cache (`compiler_compile::shared_regex`) - so the ~6-15% duplicate
/// regexes in the corpus (`AIza...`, `xoxb-...`, JWT shapes) still compile
/// at most once each.
#[derive(Debug, Clone)]
pub struct LazyRegex {
    src: Arc<str>,
    /// Detector patterns are case-insensitive + CRLF-aware + size-bounded
    /// (the `shared_regex_compile` build); homoglyph-expanded fallback
    /// variants use plain defaults (the old `Regex::new`). Tracked so the
    /// deferred build reproduces the exact regex the eager path produced.
    case_insensitive: bool,
    cell: Arc<std::sync::OnceLock<Arc<Regex>>>,
}

impl LazyRegex {
    /// A detector pattern: case-insensitive, CRLF-aware, DFA-size-bounded -
    /// identical to the eager `shared_regex_compile` build, and routed
    /// through the same process-wide dedup cache on first use.
    pub fn detector(src: impl Into<Arc<str>>) -> Self {
        Self {
            src: src.into(),
            case_insensitive: true,
            cell: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// A plain pattern with default flags - matches the old `Regex::new`
    /// used for homoglyph-expanded fallback variants.
    pub fn plain(src: impl Into<Arc<str>>) -> Self {
        Self {
            src: src.into(),
            case_insensitive: false,
            cell: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// The regex source, without triggering compilation.
    pub fn as_str(&self) -> &str {
        &self.src
    }

    /// Compile-on-first-use. A pattern that fails to compile (impossible for
    /// the curated corpus - the contracts suite compiles every embedded
    /// detector on each CI run, and the `--detectors` quality gate
    /// AST-parses + size-bounds user patterns) degrades to a never-matching
    /// regex with a loud `error!` log rather than panicking: a scanner that
    /// can't build one rule must still not crash the whole scan.
    pub fn get(&self) -> &Regex {
        self.cell
            .get_or_init(|| {
                let built = if self.case_insensitive {
                    crate::compiler::compiler_compile::shared_regex(&self.src)
                } else {
                    Regex::new(&self.src).map(Arc::new)
                };
                match built {
                    Ok(rx) => rx,
                    Err(error) => {
                        tracing::error!(
                            pattern = %self.src,
                            %error,
                            "detector regex failed to compile on first use; \
                             this pattern is disabled for this run"
                        );
                        never_match_regex()
                    }
                }
            })
            .as_ref()
    }
}

/// A shared, process-wide regex that matches nothing. Returned by
/// `LazyRegex::get` when a pattern fails to compile, so callers always get a
/// usable `&Regex` (one that simply never fires) instead of a panic.
/// `[^\s\S]` is the canonical empty-language pattern: no char is both
/// non-whitespace and non-non-whitespace.
fn never_match_regex() -> Arc<Regex> {
    static NEVER: std::sync::OnceLock<Arc<Regex>> = std::sync::OnceLock::new();
    NEVER
        .get_or_init(|| Arc::new(Regex::new(r"[^\s\S]").expect("empty-language regex is valid")))
        .clone()
}

/// A compiled entry: one pattern from one detector. The regex is compiled
/// lazily on first use - see [`LazyRegex`].
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub detector_index: usize,
    pub regex: LazyRegex,
    pub group: Option<usize>,
    /// Mirrors `PatternSpec::client_safe` for the compiled side. A
    /// match against a pattern with this set collapses the finding's
    /// severity to `Severity::ClientSafe` so `--hide-client-safe`
    /// can drop it without affecting any other detector's tier.
    pub client_safe: bool,
}

/// An optional compiled companion pattern for a detector.
pub struct CompiledCompanion {
    pub name: String,
    pub regex: Regex,
    pub capture_group: Option<usize>,
    pub within_lines: usize,
    pub required: bool,
}

pub use crate::scanner_config::{ScanState, ScannerConfig};
// `MlPendingMatch` only exists with the `ml` feature (it is the batch-deferral
// record); re-export it under the same gate so the lean / `--no-default-features`
// build resolves the import set instead of failing with E0432.
#[cfg(feature = "ml")]
pub use crate::scanner_config::MlPendingMatch;
