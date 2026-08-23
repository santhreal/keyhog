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
pub const MAX_SCAN_CHUNK_BYTES: usize = keyhog_core::DEFAULT_WINDOW_SIZE_BYTES;

/// Overlap between adjacent scan windows when a file exceeds
/// `MAX_SCAN_CHUNK_BYTES`. Must be larger than the longest secret the scanner
/// can detect to avoid missing secrets that straddle a chunk boundary.
/// 128 KiB covers PEM-encoded RSA-8192 keys, large JWTs, and multi-line
/// concatenated secrets with generous margin.
pub const WINDOW_OVERLAP_BYTES: usize = keyhog_core::DEFAULT_WINDOW_OVERLAP_BYTES;

pub(crate) const FIRST_CAPTURE_GROUP_INDEX: usize = 1;
pub(crate) const FIRST_LINE_NUMBER: usize = 1;
pub(crate) const PREVIOUS_LINE_DISTANCE: usize = 1;
/// Minimum AC literal prefix length. Shorter prefixes (e.g., "1", "x", "_")
/// match too many positions and degrade Aho-Corasick throughput.
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
/// regex builders in `compiler_compile`. Mirrors the `gpu_batch_input_limit`
/// process-global pattern so the per-detector lazy-compile path needs no
/// per-call plumbing.
static REGEX_DFA_LIMIT_OVERRIDE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Process-wide count of dynamic regex first-use compilations - incremented
/// EXACTLY once per lazily compiled regex the moment its `OnceLock` builds the
/// `Regex` (the cold-cache miss inside [`LazyRegex::get`] or dynamic verifier
/// compilation in [`crate::anchored_regex::AnchoredRegex::compile`]). Scanner
/// construction VALIDATES every detector pattern by building it once and
/// dropping it again (see `compiler_compile::compile_pattern`), so the first
/// chunk that actually reaches a pattern or anchored verifier pays one compile
/// for it and every later chunk is a cache hit: this counter is the observable
/// that proves "compile once per reached pattern, scan many" - no per-scan regex rebuild.
/// A regression that reintroduced per-scan `Regex::new` (the bug #13 fixed)
/// would make this climb across scans. Pure observability (Law 10): it only
/// ticks on a real compile, never gates or alters behaviour.
static LAZY_REGEX_COMPILE_EVENTS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[inline]
pub(crate) fn record_lazy_regex_compile() {
    LAZY_REGEX_COMPILE_EVENTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Snapshot of [`LAZY_REGEX_COMPILE_EVENTS`]: how many dynamic regex first-use
/// compilations (including [`LazyRegex`] and [`crate::anchored_regex::AnchoredRegex`])
/// have happened process-wide so far. The zero-recompile regression gate snapshots
/// this around repeated scans to prove steady-state scanning rebuilds no regex.
pub(crate) fn lazy_regex_compile_events() -> u64 {
    LAZY_REGEX_COMPILE_EVENTS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Override the per-regex DFA size limit for this process. Call before scanning.
/// `0` resets to the compiled default. Tier-A config knob (default → TOML → CLI).
pub fn set_regex_dfa_limit(bytes: usize) {
    REGEX_DFA_LIMIT_OVERRIDE.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

/// The compiled-default per-regex DFA size limit ([`REGEX_SIZE_LIMIT_BYTES`]):
/// the cap that takes effect when no `--regex-dfa-limit` / `regex_dfa_limit`
/// override is set. Exposed so `keyhog config --effective` can report the real
/// active default instead of a misleading "off" - an unset limit is never truly
/// off, it falls back to this compiled cap.
#[must_use]
pub fn regex_dfa_limit_default() -> usize {
    REGEX_SIZE_LIMIT_BYTES
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

/// The ONE always-compiled `LineMapping` owner. Previously duplicated field-for-field
/// under `#[cfg(feature = "multiline")]` in `multiline/config.rs`; both the multiline
/// and non-multiline `PreprocessedText` variants now share this single definition
/// (re-exported as `crate::multiline::LineMapping` under the `multiline` feature).
#[derive(Debug, Clone)]
pub(crate) struct LineMapping {
    pub(crate) start_offset: usize,
    pub(crate) end_offset: usize,
    pub(crate) line_number: usize,
    pub(crate) original_start_offset: usize,
    /// The mapped line was synthesized from a transport-decoded structured
    /// value (for example Kubernetes Secret `data:` base64), not plaintext.
    pub(crate) transport_decoded: bool,
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

    pub(crate) fn transport_decoded_for_offset(&self, offset: usize) -> bool {
        transport_decoded_for_offset(&self.mappings, offset)
    }

    pub(crate) fn source_offset_for_match(
        &self,
        source: &str,
        offset: usize,
        credential: &str,
    ) -> usize {
        let idx = self.mappings.partition_point(|m| m.start_offset <= offset);
        if idx == 0 {
            return offset.min(source.len().saturating_sub(1));
        }
        let m = &self.mappings[idx - 1];
        if offset >= m.end_offset {
            return offset.min(source.len().saturating_sub(1));
        }
        source_offset_from_mapping(source, m, offset, credential)
    }

    pub(crate) fn passthrough(text: impl Into<std::borrow::Cow<'a, str>>) -> Self {
        // Carried as-is: `Cow::Borrowed` for a byte-identical passthrough (no
        // body copy), `Cow::Owned` only when normalization rewrote it.
        let text: std::borrow::Cow<'a, str> = text.into();
        // One LineMapping PER physical line so `line_for_offset` resolves the
        // correct 1-based line for every offset. The prior form built a single
        // whole-text mapping with `line_number: 1`, which labeled EVERY offset
        // in a multi-line chunk as line 1: `match_line_number` then reported
        // line 1 for credentials on later lines, and
        // `infer_context_with_documentation` read the line ABOVE the credential.
        // A secret directly under a `# url` / `// note` comment was therefore
        // mis-classified as Comment context and silently hard-suppressed (a
        // recall bug on the ubiquitous "comment line, then key=value" shape).
        // `start_offset == original_start_offset` on every mapping keeps
        // `source_offset_from_mapping` on its identity fast-path (no remapping
        // for the non-`multiline` passthrough). Mirrors the `multiline`
        // PreprocessedText::passthrough so both feature builds attribute lines
        // identically.
        let mut mappings = Vec::new();
        let mut offset = 0;
        for (line_idx, line) in text.split('\n').enumerate() {
            let end = offset + line.len();
            mappings.push(LineMapping {
                line_number: line_idx + 1,
                start_offset: offset,
                end_offset: end + 1,
                original_start_offset: offset,
                transport_decoded: false,
            });
            offset = end + 1;
        }
        if let Some(last) = mappings.last_mut() {
            last.end_offset = text.len();
        }
        Self { text, mappings }
    }
}

pub(crate) fn transport_decoded_for_offset(mappings: &[LineMapping], offset: usize) -> bool {
    let idx = mappings.partition_point(|mapping| mapping.start_offset <= offset);
    idx.checked_sub(1)
        .and_then(|index| mappings.get(index))
        .is_some_and(|mapping| offset < mapping.end_offset && mapping.transport_decoded)
}

/// The ONE always-compiled owner (was duplicated identically in `multiline/config.rs`
/// under `#[cfg(feature = "multiline")]`). Called by both `PreprocessedText` variants.
pub(crate) fn source_offset_from_mapping(
    source: &str,
    mapping: &LineMapping,
    offset: usize,
    credential: &str,
) -> usize {
    if mapping.start_offset == mapping.original_start_offset && offset < source.len() {
        return offset;
    }
    if let Some(line) = source_line_at(source, mapping.original_start_offset) {
        if let Some(column) = line.find(credential) {
            return mapping.original_start_offset + column;
        }
    }
    let candidate = mapping
        .original_start_offset
        .saturating_add(offset.saturating_sub(mapping.start_offset));
    if candidate < source.len() {
        candidate
    } else if mapping.original_start_offset < source.len() {
        mapping.original_start_offset
    } else {
        source.len().saturating_sub(1)
    }
}

/// The ONE always-compiled owner (was duplicated in `multiline/config.rs`; the code
/// body was identical (only the comment wording differed)).
pub(crate) fn source_line_at(source: &str, start: usize) -> Option<&str> {
    if start >= source.len() {
        return None;
    }
    // `start` is a byte offset that can land inside a multi-byte UTF-8 scalar on
    // binary / lossy-UTF-8 input (a `&source[start..]` there panics with "byte
    // index N is not a char boundary" and aborts the worker). Snap DOWN to the
    // enclosing char boundary; the line containing that byte is unchanged. LAW10:
    // snapping to a char boundary is recall-preserving -- the same line text is
    // scanned and findings are unchanged; it only prevents a panic on a
    // mid-scalar byte index. (Mirrors the identical guard in the
    // `multiline`-enabled twin in multiline/config.rs.)
    let start = crate::engine::floor_char_boundary(source, start);
    let rest = &source[start..];
    let end = rest.find('\n').unwrap_or(rest.len()); // LAW10: no newline means the line runs to source end; reporting-only coordinate slice
    let line = &rest[..end];
    Some(line.strip_suffix('\r').unwrap_or(line)) // LAW10: no CR suffix means the source line is already normalized; reporting-only coordinate slice
}

#[cfg(feature = "multiline")]
pub(crate) type ScannerPreprocessedText<'a> = crate::multiline::PreprocessedText<'a>;

#[cfg(not(feature = "multiline"))]
pub(crate) type ScannerPreprocessedText<'a> = PreprocessedText<'a>;

/// Flag indicating that regex matching is case-insensitive.
const LAZY_REGEX_FLAG_CASE_INSENSITIVE: u8 = 1 << 0;
/// Flag indicating that regex matching is CRLF-aware.
const LAZY_REGEX_FLAG_CRLF: u8 = 1 << 1;
/// Mask isolating the memoized literal prefix extraction state.
const LAZY_REGEX_PREFIX_STATE_MASK: u8 = 0b11 << 2;
/// Memoized state indicating literal prefix extraction yielded false.
const LAZY_REGEX_PREFIX_STATE_FALSE: u8 = 1 << 2;
/// Memoized state indicating literal prefix extraction yielded true.
const LAZY_REGEX_PREFIX_STATE_TRUE: u8 = 2 << 2;
/// Mask isolating the memoized required literal run state.
const LAZY_REGEX_INFIX_STATE_MASK: u8 = 0b11 << 4;
/// Memoized state indicating required literal run detection yielded false.
const LAZY_REGEX_INFIX_STATE_FALSE: u8 = 1 << 4;
/// Memoized state indicating required literal run detection yielded true.
const LAZY_REGEX_INFIX_STATE_TRUE: u8 = 2 << 4;

/// Internal shared state for [`LazyRegex`].
///
/// Clones share one allocation containing the compiled matcher, regex source,
/// and bit-packed atomic flags / memoized source facts.
#[derive(Debug)]
struct LazyRegexState {
    src: Arc<str>,
    cell: std::sync::OnceLock<Arc<Regex>>,
    flags: std::sync::atomic::AtomicU8,
}

/// A regex wrapper that holds a detector regex source and compiles it at most
/// once, on the first chunk that actually reaches the pattern.
///
/// Scanner construction still VALIDATES every detector pattern (and every
/// generated homoglyph/plain variant) by building it through the bounded
/// shared builder, so a malformed or oversized pattern is rejected loudly
/// before a scan can start. It does not RETAIN those builds: a compiled
/// `regex::Regex` for a corpus pattern costs on the order of 200 KB of NFA /
/// one-pass DFA / Teddy-prefilter state, and the embedded corpus declares
/// 1,709 patterns and 178 companions (923 detectors, measured) plus a
/// generated homoglyph variant per eligible literal prefix, so seeding every
/// one of them cost ~450 MB of resident memory to scan an eleven-byte file.
/// Only the patterns a scan really touches are worth that state, and phase-1
/// literal gating means that is a small fraction of the corpus for real
/// inputs.
///
/// `as_str()` returns the source with no compilation, so the Hyperscan /
/// GPU literal-set builders that only read pattern text stay zero-cost.
///
/// Clones share one allocation containing the compiled matcher and memoized
/// source facts. Keeping each `OnceLock` in a separate `Arc` multiplied
/// allocation metadata and widened every retained `CompiledPattern`.
#[derive(Debug, Clone)]
pub(crate) struct LazyRegex {
    state: Arc<LazyRegexState>,
}

impl LazyRegex {
    /// A detector pattern: case-insensitive, CRLF-aware, size-bounded. The
    /// source has already been validated by `compile_pattern`; the compiled
    /// form is built on first use and shared from there on.
    pub(crate) fn detector(src: impl Into<Arc<str>>) -> Self {
        Self::new(src, true, true, std::sync::OnceLock::new())
    }

    /// Test-only: a detector pattern with its compiled regex already seeded,
    /// so a test can assert `get()` hands back that exact instance.
    pub(crate) fn detector_compiled(src: impl Into<Arc<str>>, compiled: Arc<Regex>) -> Self {
        Self::new(src, true, true, std::sync::OnceLock::from(compiled))
    }

    /// A generated plain pattern (a homoglyph-expanded variant) built with
    /// default regex flags. Validated by the compiler, compiled on first use.
    pub(crate) fn plain(src: impl Into<Arc<str>>) -> Self {
        Self::new(src, false, false, std::sync::OnceLock::new())
    }

    /// A case-sensitive companion pattern with the scanner's bounded CRLF
    /// configuration. Its source was validated during pack compilation and is
    /// materialized only when a primary match actually consults the relation.
    pub(crate) fn companion(src: impl Into<Arc<str>>) -> Self {
        Self::new(src, false, true, std::sync::OnceLock::new())
    }

    fn new(
        src: impl Into<Arc<str>>,
        case_insensitive: bool,
        crlf: bool,
        cell: std::sync::OnceLock<Arc<Regex>>,
    ) -> Self {
        let mut initial_flags = 0u8;
        if case_insensitive {
            initial_flags |= LAZY_REGEX_FLAG_CASE_INSENSITIVE;
        }
        if crlf {
            initial_flags |= LAZY_REGEX_FLAG_CRLF;
        }
        Self {
            state: Arc::new(LazyRegexState {
                src: src.into(),
                cell,
                flags: std::sync::atomic::AtomicU8::new(initial_flags),
            }),
        }
    }

    /// The regex source, without triggering compilation.
    pub(crate) fn as_str(&self) -> &str {
        &self.state.src
    }

    pub(crate) fn cloned_source(&self) -> Arc<str> {
        Arc::clone(&self.state.src)
    }

    /// Whether this pattern is anchored by a distinctive literal prefix,
    /// memoized.
    ///
    /// This is the `ConfidenceSignals.has_literal_prefix` input the per-match
    /// scoring path consumes. It delegates to the SAME extractor the routing
    /// prefilter uses (`extract_literal_prefixes`, the plural), so confidence
    /// and routing agree on what counts as a literal anchor: it strips a leading
    /// inline-flag group (`(?-i)cs_…`), strips a boundary guard
    /// (`(?:^|[^…])(sk-…)`), and, crucially, recognizes a leading literal
    /// ALTERNATION where the branches diverge (`(?:test_|live_)…` lob,
    /// `(?:hanko_|corbado1_)…` hanko). The earlier `extract_literal_prefix`
    /// (singular) returned only the single COMMON prefix, which is empty when
    /// the branches share no head, so every multi-prefix detector was silently
    /// denied its literal-prefix confidence weight and scored below the floor.
    ///
    /// Pure function of the regex SOURCE, cached on first touch.
    #[must_use]
    pub(crate) fn has_literal_prefix(&self) -> bool {
        let current = self.state.flags.load(std::sync::atomic::Ordering::Acquire);
        let prefix_state = current & LAZY_REGEX_PREFIX_STATE_MASK;
        if prefix_state == LAZY_REGEX_PREFIX_STATE_TRUE {
            return true;
        }
        if prefix_state == LAZY_REGEX_PREFIX_STATE_FALSE {
            return false;
        }
        let has_prefix =
            !crate::compiler::compiler_prefix::extract_literal_prefixes(&self.state.src).is_empty();
        let to_set = if has_prefix {
            LAZY_REGEX_PREFIX_STATE_TRUE
        } else {
            LAZY_REGEX_PREFIX_STATE_FALSE
        };
        self.state
            .flags
            .fetch_or(to_set, std::sync::atomic::Ordering::Release);
        has_prefix
    }

    /// Whether every match of this pattern necessarily contains a distinctive
    /// required literal run (the terraform `\.atlasv1\.` infix), memoized. This
    /// is an anchor signal of the same strength as a leading literal prefix for
    /// a named detector whose regex opens with a class and captures the whole
    /// match, so it carries neither `has_literal_prefix` nor a keyword
    /// `has_context_anchor`. Pure function of the regex SOURCE, cached on first
    /// touch.
    #[must_use]
    pub(crate) fn has_distinctive_inner_literal(&self) -> bool {
        let current = self.state.flags.load(std::sync::atomic::Ordering::Acquire);
        let infix_state = current & LAZY_REGEX_INFIX_STATE_MASK;
        if infix_state == LAZY_REGEX_INFIX_STATE_TRUE {
            return true;
        }
        if infix_state == LAZY_REGEX_INFIX_STATE_FALSE {
            return false;
        }
        let has_infix = crate::compiler::compiler_prefix::regex_has_required_literal_run(
            &self.state.src,
            crate::compiler::compiler_prefix::MIN_DISTINCTIVE_INFIX_CHARS,
        );
        let to_set = if has_infix {
            LAZY_REGEX_INFIX_STATE_TRUE
        } else {
            LAZY_REGEX_INFIX_STATE_FALSE
        };
        self.state
            .flags
            .fetch_or(to_set, std::sync::atomic::Ordering::Release);
        has_infix
    }

    /// Whether this pattern compiles with the case-insensitive + CRLF-aware
    /// `shared_regex` flags (a `detector` pattern) versus plain `Regex::new`
    /// defaults (a homoglyph-expanded `plain` variant). Callers that build an
    /// equivalent combined matcher (e.g. the always-active phase-2 RegexSet
    /// prefilter) must replicate these flags exactly to stay match-equivalent.
    pub(crate) fn is_case_insensitive(&self) -> bool {
        (self.state.flags.load(std::sync::atomic::Ordering::Relaxed)
            & LAZY_REGEX_FLAG_CASE_INSENSITIVE)
            != 0
    }

    /// Return the compiled regex seeded during scanner construction. Test-only
    /// constructors may still compile here; a compile error is a build-invariant
    /// breach (construction validation should have rejected the source), so it is
    /// surfaced LOUDLY and fails closed to a never-matching sentinel for this one
    /// pattern instead of panicking and aborting the whole scan.
    pub(crate) fn get(&self) -> &Regex {
        self.state
            .cell
            .get_or_init(|| {
                // Cold-cache miss: this `LazyRegex` is compiling for the first
                // time. Record it so the zero-recompile gate can prove that the
                // scan hot path triggers none of these after warm-up.
                record_lazy_regex_compile();
                let flags = self.state.flags.load(std::sync::atomic::Ordering::Relaxed);
                let built = if (flags & LAZY_REGEX_FLAG_CASE_INSENSITIVE) != 0 {
                    crate::compiler::compiler_compile::shared_regex(&self.state.src)
                } else if (flags & LAZY_REGEX_FLAG_CRLF) != 0 {
                    crate::compiler::compiler_compile::companion_regex(&self.state.src)
                } else {
                    Regex::new(&self.state.src).map(Arc::new)
                };
                match built {
                    Ok(rx) => rx,
                    Err(error) => {
                        crate::prefilter_degrade::warn_prefilter_disabled(
                            &format!("detector regex first-use compile ({})", self.state.src),
                            &error,
                        );
                        never_match_sentinel()
                    }
                }
            })
            .as_ref()
    }
    pub(crate) fn is_compiled(&self) -> bool {
        self.state.cell.get().is_some()
    }
}

/// A process-wide never-matching regex used as the fail-closed sentinel when a
/// `LazyRegex` source that passed construction validation nonetheless fails to
/// compile on first use. `\b\B` requires a position to be simultaneously a word
/// boundary and not one, which no position satisfies (so it matches nothing).
/// The failing detector contributes zero matches (fail closed) while the rest of
/// the scan proceeds; the failure is surfaced loudly via `warn_prefilter_disabled`.
fn never_match_sentinel() -> Arc<Regex> {
    static SENTINEL: std::sync::OnceLock<Arc<Regex>> = std::sync::OnceLock::new();
    SENTINEL
        .get_or_init(|| match Regex::new(r"\b\B") {
            Ok(re) => Arc::new(re),
            Err(error) => panic!("`\\b\\B` is a constant valid regex but failed to build: {error}"),
        })
        .clone()
}

/// A compiled entry: one pattern from one detector. Detector and generated
/// plain regexes are scanner-compile seeded - see [`LazyRegex`].
#[derive(Debug, Clone)]
pub(crate) struct CompiledPattern {
    pub detector_index: usize,
    /// Zero-based ordinal in the owning detector's canonical `patterns` list.
    /// Generated routing variants retain the originating ordinal, so backend
    /// choice and homoglyph expansion cannot change candidate provenance.
    pub pattern_index: u32,
    pub regex: LazyRegex,
    pub group: Option<usize>,
    /// Mirrors `PatternSpec::client_safe` for the compiled side. A
    /// match against a pattern with this set collapses the finding's
    /// severity to `Severity::ClientSafe` so `--hide-client-safe`
    /// can drop it without affecting any other detector's tier.
    pub client_safe: bool,
    /// Exact `PatternSpec::weak_anchor` decision compiled beside the regex.
    pub weak_anchor: bool,
    /// Exact `PatternSpec::structural_password_slot` decision compiled beside
    /// the regex.
    pub structural_password_slot: bool,
    /// True when every possible match for this regex starts with one of the
    /// detector keywords. In that case `keyword_nearby` is proven by the match
    /// bytes and does not need an additional whole-chunk substring scan.
    pub match_proves_keyword_nearby: bool,
    /// Install-compiled proof that the detector regex admits repeated
    /// `_`/`-`/`.` separators inside a compound keyword.
    pub allows_repeated_keyword_separator: bool,
    /// True iff this is a compiler-generated HOMOGLYPH fallback variant: the
    /// detector's literal prefix expanded to its unicode look-alikes
    /// (`compiler_build.rs`). Such a variant ALWAYS has its base ASCII prefix in
    /// the AC/confirmed path (the same loop pushes both), so on a pure-ASCII
    /// chunk, which by definition contains no homoglyph, it can be skipped
    /// without recall loss (the base AC covers it). This flag, NOT case
    /// sensitivity, is what `homoglyph_ascii_skip` keys on: generic anchorless
    /// fallbacks (generic-password, client_secret) are ALSO case-sensitive but
    /// have NO base AC pattern and must never be skipped.
    pub homoglyph_variant: bool,
}

impl CompiledPattern {
    pub(crate) fn captures_exact_slot(&self, line: &str, start: usize, end: usize) -> bool {
        self.regex.get().captures_iter(line).any(|captures| {
            self.group
                .and_then(|group| captures.get(group))
                .is_some_and(|slot| slot.start() == start && slot.end() == end)
        })
    }
}

/// An optional compiled companion pattern for a detector.
#[derive(Debug)]
pub(crate) struct CompiledCompanion {
    /// Immutable detector metadata shared by every emitted companion match.
    pub(crate) name: Arc<str>,
    pub(crate) regex: LazyRegex,
    pub(crate) capture_group: Option<usize>,
    pub(crate) within_lines: usize,
    pub(crate) within_bytes: Option<usize>,
    pub(crate) direction: keyhog_core::EvidenceDirection,
    pub(crate) scope: keyhog_core::EvidenceScope,
    pub(crate) requirement: keyhog_core::EvidenceRequirement,
    pub(crate) value_relation: keyhog_core::EvidenceValueRelation,
}

#[cfg(feature = "entropy")]
pub(crate) use crate::scan_state::RawMatchPriority;
pub(crate) use crate::scan_state::ScanState;
pub use crate::scanner_config::{ScanExecutionRoute, ScannerConfig, ScannerTuningConfig};
// `MlPendingMatch` only exists with the `ml` feature (it is the batch-queue
// record); re-export it under the same gate so the lean / `--no-default-features`
// build resolves the import set instead of failing with E0432.
#[cfg(feature = "ml")]
pub(crate) use crate::scan_state::ml_features_for_candidate;
#[cfg(feature = "ml")]
pub(crate) use crate::scan_state::MlPendingMatch;
