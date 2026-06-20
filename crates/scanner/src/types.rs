//! Internal types and constants for the scanning engine.

use regex::Regex;
use std::sync::Arc;

// Fallback regex-only scanning switches to per-line mode once a chunk grows
// beyond 10 KB. Prefixless regexes over larger blobs are expensive and secrets
// are short enough that line-local scanning preserves recall.
pub(crate) const LARGE_FALLBACK_SCAN_THRESHOLD: usize = 10_000;

/// Hard cap on the dedup set to prevent unbounded memory growth when scanning
/// repositories with millions of duplicate credential-like strings.
pub(crate) const MAX_WINDOW_DEDUP_ENTRIES: usize = 100_000;

/// Maximum bytes scanned in a single chunk. Files larger than this are split
/// into overlapping windows. 1 MiB keeps peak RSS predictable under parallel
/// scanning with `rayon` (N threads × 1 MiB per chunk = bounded memory).
pub(crate) const MAX_SCAN_CHUNK_BYTES: usize = 1024 * 1024;

/// Overlap between adjacent scan windows when a file exceeds
/// `MAX_SCAN_CHUNK_BYTES`. Must be larger than the longest secret the scanner
/// can detect to avoid missing secrets that straddle a chunk boundary.
/// 128 KiB covers PEM-encoded RSA-8192 keys, large JWTs, and multi-line
/// concatenated secrets with generous margin.
pub(crate) const WINDOW_OVERLAP_BYTES: usize = 128 * 1024;

/// Minimum AC literal prefix length. Shorter prefixes (e.g., "1", "x", "_")
/// match too many positions and degrade Aho-Corasick throughput.
pub(crate) const FIRST_CAPTURE_GROUP_INDEX: usize = 1;
pub(crate) const FIRST_LINE_NUMBER: usize = 1;
pub(crate) const PREVIOUS_LINE_DISTANCE: usize = 1;
pub(crate) const MIN_LITERAL_PREFIX_CHARS: usize = 3;

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
pub(crate) const REGEX_SIZE_LIMIT_BYTES: usize = 1 << 20; // 1 MiB default

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
pub(crate) fn regex_dfa_limit() -> usize {
    match REGEX_DFA_LIMIT_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed) {
        0 => REGEX_SIZE_LIMIT_BYTES,
        n => n,
    }
}

/// How many characters around a hex match to inspect for structural context
/// (assignment operators, quotes, keywords).
pub(crate) const HEX_CONTEXT_RADIUS_CHARS: usize = 20;

/// Minimum length for a standalone hex string to qualify as a potential secret.
/// Shorter hex runs (e.g., CSS colors like `#ff00ff`) are too common.
pub(crate) const MIN_HEX_MATCH_LEN: usize = 16;
pub(crate) const MIN_HEX_DIGITS_IN_MATCH: usize = 16;

/// Minimum hex digits required in the context window around a match to trigger
/// hex-aware false-positive suppression.
pub(crate) const MIN_HEX_CONTEXT_DIGITS: usize = 8;

/// Maximum non-hex separators (colons, dashes) tolerated within a hex context
/// window before the match is treated as a non-hex string.
pub(crate) const MAX_HEX_CONTEXT_SEPARATORS: usize = 4;

#[cfg(feature = "ml")]
pub(crate) const ML_CONTEXT_RADIUS_LINES: usize = 5;
// The ML/heuristic blend weight is NOT a compile-time constant: it is the
// runtime-configurable `ScannerConfig::ml_weight` knob (default seeded from
// `keyhog_core::ScanConfig`, overridable via `.keyhog.toml` and the
// `--ml-weight` CLI flag, clamped to [0,1] in `ScannerConfig::sanitise`).
// The blend at `apply_ml_batch_scores` reads `self.config.ml_weight` and
// `(1.0 - self.config.ml_weight)`. The former `ML_WEIGHT`/`HEURISTIC_WEIGHT`
// consts were a dead parallel source of truth (tuned!=shipped) and have been
// removed so there is exactly one place the weight lives.

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
pub(crate) struct LineMapping {
    pub(crate) start_offset: usize,
    pub(crate) end_offset: usize,
    pub(crate) line_number: usize,
}

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
pub(crate) struct PreprocessedText<'a> {
    /// `Cow` so the passthrough/identity path borrows the chunk bytes with zero
    /// allocation; only the structured-config build owns a synthesized `String`.
    /// See the multiline variant's doc for the full rationale.
    pub(crate) text: std::borrow::Cow<'a, str>,
    pub(crate) mappings: Vec<LineMapping>,
}

#[cfg(not(feature = "multiline"))]
impl<'a> PreprocessedText<'a> {
    /// Map a preprocessed-text offset back to an original line number.
    /// Binary search; same monotonic-mappings invariant as the
    /// multiline variant - see that doc for the analysis.
    pub(crate) fn line_for_offset(&self, offset: usize) -> Option<usize> {
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

    pub(crate) fn passthrough(line: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        let line: std::borrow::Cow<'a, str> = line.into();
        let end_offset = line.len();
        Self {
            // Carried as-is: `Cow::Borrowed` for a byte-identical passthrough
            // (no body copy), `Cow::Owned` only when normalization rewrote it.
            text: line,
            mappings: vec![LineMapping {
                line_number: 1,
                start_offset: 0,
                end_offset,
            }],
        }
    }
}

#[cfg(feature = "multiline")]
pub(crate) type ScannerPreprocessedText<'a> = crate::multiline::PreprocessedText<'a>;

#[cfg(not(feature = "multiline"))]
pub(crate) type ScannerPreprocessedText<'a> = PreprocessedText<'a>;

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
pub(crate) struct LazyRegex {
    src: Arc<str>,
    /// Detector patterns are case-insensitive + CRLF-aware + size-bounded
    /// (the `shared_regex_compile` build); homoglyph-expanded fallback
    /// variants use plain defaults (the old `Regex::new`). Tracked so the
    /// lazy build reproduces the exact regex the eager path produced.
    case_insensitive: bool,
    cell: Arc<std::sync::OnceLock<Arc<Regex>>>,
    /// Memoized `extract_literal_prefix(src).is_some()` — a per-PATTERN
    /// constant (it depends only on the regex SOURCE, never on the input
    /// being scanned). The scoring hot path (`match_confidence`) needs it
    /// as a `ConfidenceSignals.has_literal_prefix` input on EVERY surviving
    /// candidate; computing it inline re-ran the full char-by-char prefix
    /// parser — which allocates a `String` (and, on a `(` alternation, an
    /// extra `chars.clone().collect::<String>()` of the whole tail) — once
    /// per match. On a dense corpus where a handful of hot patterns each
    /// fire thousands of times, that is thousands of redundant parses +
    /// allocations of a value that never changes. Cached in this
    /// `Arc<OnceLock<bool>>` so it is computed AT MOST ONCE per unique
    /// regex source (shared across `Clone`s, populated on first scoring
    /// touch), exactly like the compiled-`Regex` cache above.
    has_literal_prefix: Arc<std::sync::OnceLock<bool>>,
}

impl LazyRegex {
    /// A detector pattern: case-insensitive, CRLF-aware, DFA-size-bounded -
    /// identical to the eager `shared_regex_compile` build, and routed
    /// through the same process-wide dedup cache on first use.
    pub(crate) fn detector(src: impl Into<Arc<str>>) -> Self {
        Self {
            src: src.into(),
            case_insensitive: true,
            cell: Arc::new(std::sync::OnceLock::new()),
            has_literal_prefix: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// A plain pattern with default flags - matches the old `Regex::new`
    /// used for homoglyph-expanded fallback variants.
    pub(crate) fn plain(src: impl Into<Arc<str>>) -> Self {
        Self {
            src: src.into(),
            case_insensitive: false,
            cell: Arc::new(std::sync::OnceLock::new()),
            has_literal_prefix: Arc::new(std::sync::OnceLock::new()),
        }
    }

    /// The regex source, without triggering compilation.
    pub(crate) fn as_str(&self) -> &str {
        &self.src
    }

    /// Whether this pattern has an extractable literal prefix
    /// (`extract_literal_prefix(self.as_str()).is_some()`), memoized.
    ///
    /// This is the `ConfidenceSignals.has_literal_prefix` input the per-match
    /// scoring path consumes. It is a pure function of the regex SOURCE, so
    /// the result is cached the first time scoring touches this pattern and
    /// reused for every subsequent match — the prior inline call re-parsed
    /// (and re-allocated) the prefix on each surviving candidate. The value
    /// is byte-for-byte identical to the inline computation it replaces
    /// (same `extract_literal_prefix`, same `.is_some()`), so findings are
    /// unchanged; only the redundant work is removed.
    #[must_use]
    pub(crate) fn has_literal_prefix(&self) -> bool {
        *self.has_literal_prefix.get_or_init(|| {
            crate::compiler::compiler_prefix::extract_literal_prefix(&self.src).is_some()
        })
    }

    /// Whether this pattern compiles with the case-insensitive + CRLF-aware
    /// `shared_regex` flags (a `detector` pattern) versus plain `Regex::new`
    /// defaults (a homoglyph-expanded `plain` variant). Callers that build an
    /// equivalent combined matcher (e.g. the always-active phase-2 RegexSet
    /// prefilter) must replicate these flags exactly to stay match-equivalent.
    pub(crate) fn is_case_insensitive(&self) -> bool {
        self.case_insensitive
    }

    /// Compile-on-first-use. A pattern that fails to compile (impossible for
    /// the curated corpus - the contracts suite compiles every embedded
    /// detector on each CI run, and the `--detectors` quality gate
    /// AST-parses + size-bounds user patterns) degrades to a never-matching
    /// regex with a loud `error!` log rather than panicking: a scanner that
    /// can't build one rule must still not crash the whole scan.
    pub(crate) fn get(&self) -> &Regex {
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
        .get_or_init(|| {
            // `[^\s\S]` is the canonical empty-language pattern (no char is both
            // whitespace and non-whitespace) and a compile-time constant, so
            // `Regex::new` here cannot fail. We avoid `.expect()` to honor the
            // no-panic source contract enforced by `unit::gates::
            // types_no_unwrap_expect`; the `unreachable!` arm documents the
            // invariant and is dead code (it is not a stub - the value is fully
            // implemented on the `Ok` path).
            match Regex::new(r"[^\s\S]") {
                Ok(re) => Arc::new(re),
                Err(_error) => {
                    // Law 10: Err arm is unreachable! on a compile-time-const valid pattern; fail-closed, not a swallow
                    unreachable!("empty-language regex `[^\\s\\S]` is a valid constant pattern")
                }
            }
        })
        .clone()
}

/// A compiled entry: one pattern from one detector. The regex is compiled
/// lazily on first use - see [`LazyRegex`].
#[derive(Debug, Clone)]
pub(crate) struct CompiledPattern {
    pub detector_index: usize,
    pub regex: LazyRegex,
    pub group: Option<usize>,
    /// Mirrors `PatternSpec::client_safe` for the compiled side. A
    /// match against a pattern with this set collapses the finding's
    /// severity to `Severity::ClientSafe` so `--hide-client-safe`
    /// can drop it without affecting any other detector's tier.
    pub client_safe: bool,
    /// True when every possible match for this regex starts with one of the
    /// detector keywords. In that case `keyword_nearby` is proven by the match
    /// bytes and does not need an additional whole-chunk substring scan.
    pub match_proves_keyword_nearby: bool,
    /// True iff this is a compiler-generated HOMOGLYPH fallback variant: the
    /// detector's literal prefix expanded to its unicode look-alikes
    /// (`compiler_build.rs`). Such a variant ALWAYS has its base ASCII prefix in
    /// the AC/confirmed path (the same loop pushes both), so on a pure-ASCII
    /// chunk — which by definition contains no homoglyph — it can be skipped
    /// without recall loss (the base AC covers it). This flag, NOT case
    /// sensitivity, is what `homoglyph_ascii_skip` keys on: generic anchorless
    /// fallbacks (generic-password, client_secret) are ALSO case-sensitive but
    /// have NO base AC pattern and must never be skipped.
    pub homoglyph_variant: bool,
}

/// An optional compiled companion pattern for a detector.
pub(crate) struct CompiledCompanion {
    pub(crate) name: String,
    pub(crate) regex: Regex,
    pub(crate) capture_group: Option<usize>,
    pub(crate) within_lines: usize,
    pub(crate) required: bool,
}

pub(crate) use crate::scanner_config::ScanState;
pub use crate::scanner_config::{ScannerConfig, ScannerTuningConfig};
// `MlPendingMatch` only exists with the `ml` feature (it is the batch-queue
// record); re-export it under the same gate so the lean / `--no-default-features`
// build resolves the import set instead of failing with E0432.
#[cfg(feature = "ml")]
pub(crate) use crate::scanner_config::MlPendingMatch;
