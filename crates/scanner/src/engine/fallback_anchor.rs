//! Shared-anchor localization for the keyword-gated fallback scan.
//!
//! ## The problem
//!
//! `scan_fallback_patterns` runs each fired fallback pattern's capture regex
//! over the WHOLE chunk. The per-pattern profile (`fallback_pattern_profile`)
//! shows ~82 patterns active on a 16 KiB chunk, each effectively doing its own
//! `memchr`/prefilter pass over the chunk for its literal — 82 redundant chunk
//! scans, the dominant 77-85% of phase-2 time.
//!
//! ## The optimization
//!
//! Every one of those patterns has, by `regex_syntax` proof, a finite set of
//! REQUIRED prefix literals: every match of the pattern must begin with one of
//! them (this is exactly the property the `regex` crate uses to build its own
//! prefilters). We union all those literals into ONE Aho-Corasick automaton and
//! scan the chunk a SINGLE time. Each AC hit is a candidate start position for
//! the pattern(s) that own that literal; we verify the candidate by running a
//! `\A`-anchored copy of the pattern's regex at exactly that position — O(match
//! length), with no forward scan. The 82 chunk passes collapse to one shared AC
//! pass plus a handful of anchored verifications.
//!
//! ## Soundness (recall is identical, proven by differential test)
//!
//! For an eligible pattern P with required-prefix literal set L(P): every match
//! M of P starts with some l ∈ L(P), so M's start byte is a position where the
//! AC reports l. Verifying P anchored at every AC-reported position therefore
//! finds every match the whole-chunk walk would (`fallback_anchor_parity`
//! asserts byte-identical `RawMatch` sets over the corpora + generated inputs).
//! A pattern whose required-literal set cannot be proven finite/short (pure
//! char-class bodies, homoglyph unicode cross-products) is NOT eligible and
//! keeps the whole-chunk path — never a silent recall trade.

use super::scan_filters::looks_like_variable_name;
use super::CompiledScanner;
use std::sync::OnceLock as StdOnceLock;

/// Whether the localized homoglyph extraction path is enabled. DEFAULT OFF
/// (`KEYHOG_LOCALIZER=1` opts in): the localizer's per-chunk AC overhead is a
/// net end-to-end LOSS (+17.7% on the decode-recursion-heavy mirror corpus —
/// many small sub-chunks each pay the AC scan), even though it makes the phase-2
/// fallback pass faster in isolation. The default plain-pattern path is the
/// lighter single-RegexSet ASCII-fold, which is an end-to-end WIN (-2.6%). The
/// localizer remains opt-in for workloads of large single chunks without decode
/// recursion, where the AC amortizes.
fn localizer_enabled() -> bool {
    static EN: StdOnceLock<bool> = StdOnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_LOCALIZER").as_deref() == Ok("1"))
}
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use keyhog_core::Chunk;
use regex::{Regex, RegexBuilder};
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use std::cell::OnceCell;
use std::sync::{Arc, OnceLock};

/// Required-prefix literals shorter than this occur too densely to prune the
/// scan and bloat the shared automaton; below the keyword-AC's >=4 floor is
/// intentional — an anchor is a *required* substring, so even a 3-byte one
/// (`sk-`, `eyJ`, `1/`) hard-prunes a 16 KiB chunk.
const MIN_ANCHOR_LEN: usize = 3;

/// Cap on distinct (ASCII-lowercased) required-prefix literals per pattern. The
/// ASCII-base detectors that dominate the profile collapse to 1-4 literals
/// after case folding; only homoglyph cross-products and giant alternations
/// exceed this, and those are exactly the patterns better left whole-chunk
/// (their rare literals never appear in real text, so their own prefilter is
/// already ~free).
const MAX_LITERALS_PER_PATTERN: usize = 8;

/// A lazily-compiled `\A`-anchored copy of a fallback pattern's regex. Searched
/// on `&text[pos..]`, `\A` pins the match to start exactly at `pos`, so a hit is
/// confirmed in O(match length) with no forward scan. Flags mirror the
/// pattern's own `LazyRegex` build so the anchored regex is match-equivalent.
pub(crate) struct AnchoredRegex {
    src: Arc<str>,
    case_insensitive: bool,
    cell: OnceLock<Option<Arc<Regex>>>,
}

impl AnchoredRegex {
    fn new(src: &str, case_insensitive: bool) -> Self {
        Self {
            src: Arc::from(src),
            case_insensitive,
            cell: OnceLock::new(),
        }
    }

    /// The anchored regex, or `None` if it failed to compile. A `None` here is
    /// surfaced LOUDLY by the caller (one `error!`) and the pattern is run on
    /// the whole-chunk path instead — never a silent skip. For the curated
    /// corpus this never returns `None` (anchoring only shrinks the automaton
    /// the unanchored regex already builds).
    fn get(&self) -> Option<&Regex> {
        self.cell
            .get_or_init(|| {
                // Wrap in a non-capturing group so the inner capture-group
                // numbering (`entry.group`) is preserved, then pin with `\A`.
                let anchored = format!(r"\A(?:{})", self.src);
                let built = RegexBuilder::new(&anchored)
                    .case_insensitive(self.case_insensitive)
                    .size_limit(crate::types::REGEX_SIZE_LIMIT_BYTES)
                    .dfa_size_limit(crate::types::regex_dfa_limit())
                    .crlf(self.case_insensitive)
                    .build();
                match built {
                    Ok(rx) => Some(Arc::new(rx)),
                    Err(error) => {
                        tracing::error!(
                            pattern = %self.src,
                            %error,
                            "fallback anchored-regex failed to compile; this \
                             pattern uses the whole-chunk path for the rest of \
                             the run (recall preserved, localization skipped)"
                        );
                        None
                    }
                }
            })
            .as_ref()
            .map(Arc::as_ref)
    }
}

/// Per-scanner index that drives shared-anchor fallback localization AND
/// replaces the always-active RegexSet prefilter for eligible patterns.
pub(crate) struct FallbackAnchorIndex {
    /// One automaton over every eligible pattern's required-prefix literals,
    /// ASCII-case-insensitive (so a lowercase literal anchors all case variants
    /// the case-insensitive detector regex would match). Scanned once per chunk
    /// with `find_overlapping_iter` so overlapping literals (`sk-` vs `sk-ant-`)
    /// all report.
    anchor_ac: Option<AhoCorasick>,
    /// `anchor_ac` pattern id -> fallback indices that declared this literal.
    literal_patterns: Vec<Vec<u32>>,
    /// Per fallback index: eligible for the anchored fast path.
    eligible: Vec<bool>,
    /// Per fallback index: eligible AND always-active (no >=4-char keyword).
    /// These are gated+located purely by the shared AC, so they are REMOVED
    /// from the expensive always-active RegexSet prefilter — the main win.
    always_active_eligible: Vec<bool>,
    /// Per fallback index: the anchored regex (Some iff eligible OR plain
    /// -anchorable — the localized homoglyph path also runs `\A(?:regex)`).
    anchored: Vec<Option<AnchoredRegex>>,
    /// Count of eligible patterns (diagnostics).
    eligible_count: usize,

    // --- Localized homoglyph path (ASCII chunks only) ---
    /// Case-SENSITIVE Aho-Corasick over the plain (homoglyph) patterns' FOLDED
    /// leading literals (`[sѕｓ][kкκｋ]_…` → fold `[s][k]_[lOo]…` → `{sk_live_,
    /// sk_Oive_, sk_oive_}`). On a pure-ASCII chunk every homoglyph match begins
    /// with one of these, so the AC gives candidate START positions; each is
    /// verified by `extract_anchored` (O(match), so dense over-marking from a
    /// short literal is cheap quick-fails, NOT whole-chunk scans). Replaces the
    /// plain RegexSet batches on ASCII chunks.
    plain_anchor_ac: Option<AhoCorasick>,
    /// `plain_anchor_ac` literal id -> plain fallback indices.
    plain_literal_patterns: Vec<Vec<u32>>,
    /// Plain patterns with NO usable folded literal: run whole-chunk on ASCII
    /// chunks (they are few — homoglyph variants almost always have a prefix).
    plain_always_mark: Vec<u32>,
}

impl FallbackAnchorIndex {
    pub(crate) fn eligible_count(&self) -> usize {
        self.eligible_count
    }

    #[inline]
    pub(crate) fn is_eligible(&self, fallback_idx: usize) -> bool {
        self.eligible.get(fallback_idx).copied().unwrap_or(false)
    }

    #[inline]
    pub(crate) fn is_always_active_eligible(&self, fallback_idx: usize) -> bool {
        self.always_active_eligible
            .get(fallback_idx)
            .copied()
            .unwrap_or(false)
    }

    /// Build the index from the compiled fallback set. `always_active_indices`
    /// are the fallback patterns with no >=4-char keyword (gated today by the
    /// RegexSet prefilter); the eligible subset of those is recorded so the
    /// caller can shrink the prefilter to only the non-eligible remainder.
    /// Always succeeds: a pattern whose required-prefix literals can't be proven
    /// finite/short simply isn't eligible (whole-chunk). Returns `None` only when
    /// NO pattern is eligible (the anchored path is then a no-op and skipped).
    pub(crate) fn build(
        fallback: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
    ) -> Option<Self> {
        let mut eligible = vec![false; fallback.len()];
        let mut anchored: Vec<Option<AnchoredRegex>> = (0..fallback.len()).map(|_| None).collect();
        // Dedup literal string -> ac pattern id (ci eligible path).
        let mut literal_ids: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut literals: Vec<String> = Vec::new();
        let mut literal_patterns: Vec<Vec<u32>> = Vec::new();
        // Plain (homoglyph) localized path: separate case-sensitive AC.
        let mut plain_literal_ids: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut plain_literals: Vec<String> = Vec::new();
        let mut plain_literal_patterns: Vec<Vec<u32>> = Vec::new();
        let mut plain_always_mark: Vec<u32> = Vec::new();

        for (idx, (pattern, _keywords)) in fallback.iter().enumerate() {
            let ci = pattern.regex.is_case_insensitive();
            if let Some(pattern_literals) = required_prefix_literals(pattern.regex.as_str(), ci) {
                // Register every literal and map it back to this pattern.
                for lit in &pattern_literals {
                    let id = *literal_ids.entry(lit.clone()).or_insert_with(|| {
                        literals.push(lit.clone());
                        literal_patterns.push(Vec::new());
                        literals.len() - 1
                    });
                    literal_patterns[id].push(idx as u32);
                }
                eligible[idx] = true;
                anchored[idx] = Some(AnchoredRegex::new(pattern.regex.as_str(), ci));
                continue;
            }
            // Not eligible via the unicode prefix (homoglyph cross-products go
            // infinite). For PLAIN (homoglyph) patterns, drive the ASCII chunk
            // path from the FOLDED leading literals instead.
            if !ci {
                // Fold out non-ASCII ONCE: the same fold drives the leading
                // -literal AC and the anchored verify regex.
                let folded_src: String = pattern
                    .regex
                    .as_str()
                    .chars()
                    .filter(char::is_ascii)
                    .collect();
                match leading_literals_of_folded(&folded_src) {
                    Some(lits) => {
                        for lit in &lits {
                            let id = *plain_literal_ids.entry(lit.clone()).or_insert_with(|| {
                                plain_literals.push(lit.clone());
                                plain_literal_patterns.push(Vec::new());
                                plain_literals.len() - 1
                            });
                            plain_literal_patterns[id].push(idx as u32);
                        }
                        // Verify with the FOLDED (ASCII) regex `\A(?:fold)`, not
                        // the unicode one: on the ASCII chunks where this path
                        // runs it is match-equivalent but its DFA is far simpler
                        // (ASCII classes), so each candidate verify — dominated
                        // by quick-fails at common-keyword positions — is much
                        // cheaper. Case-sensitive (the fold carries the case).
                        anchored[idx] = Some(AnchoredRegex::new(&folded_src, false));
                    }
                    None => plain_always_mark.push(idx as u32),
                }
            }
        }

        let eligible_count = eligible.iter().filter(|&&e| e).count();
        if eligible_count == 0 && plain_literals.is_empty() && plain_always_mark.is_empty() {
            return None;
        }

        // Mark eligible always-active patterns: these leave the RegexSet
        // prefilter entirely and are gated by the shared AC instead.
        let mut always_active_eligible = vec![false; fallback.len()];
        for &i in always_active_indices {
            if eligible.get(i).copied().unwrap_or(false) {
                always_active_eligible[i] = true;
            }
        }

        // MatchKind::Standard is required for find_overlapping_iter; ASCII-case
        // -insensitive so a single lowercase literal anchors all case variants.
        let anchor_ac = if literals.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .ascii_case_insensitive(true)
                    .build(&literals)
                    .ok()?,
            )
        };
        // Case-SENSITIVE AC for the plain folded literals (the fold keeps exact
        // ASCII members, e.g. `[lOo]`, so case-sensitivity is already encoded).
        let plain_anchor_ac = if plain_literals.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .build(&plain_literals)
                .ok()
        };

        Some(Self {
            anchor_ac,
            literal_patterns,
            eligible,
            always_active_eligible,
            anchored,
            eligible_count,
            plain_anchor_ac,
            plain_literal_patterns,
            plain_always_mark,
        })
    }

    /// Collect candidate `(fallback_idx, byte_pos)` anchors for the eligible
    /// patterns that are marked active in `is_active`. One shared AC pass over
    /// `text`. Results are pushed into `out` (caller-owned, reused scratch);
    /// `out` is sorted + deduped on return so each (pattern, pos) is verified
    /// once even when overlapping literals report the same start.
    /// A candidate `(pat, pos)` is collected when the pattern can fire here:
    ///   * an eligible ALWAYS-ACTIVE pattern is gated solely by anchor presence
    ///     (it left the RegexSet prefilter), so any AC hit activates it;
    ///   * an eligible KEYWORD-TRIGGERED pattern keeps its keyword gate, so it
    ///     is collected only when `is_active` (its keyword fired) — preserving
    ///     the exact current active-set semantics.
    pub(crate) fn collect_candidates(
        &self,
        text: &str,
        is_active: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        out.clear();
        let Some(ac) = &self.anchor_ac else {
            return;
        };
        for m in ac.find_overlapping_iter(text) {
            let lit_id = m.pattern().as_usize();
            let pos = m.start() as u32;
            if let Some(pats) = self.literal_patterns.get(lit_id) {
                for &pat in pats {
                    let p = pat as usize;
                    if self.is_always_active_eligible(p) || is_active(p) {
                        out.push((pat, pos));
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
    }

    /// The anchored regex for `fallback_idx`, or `None` if not eligible or the
    /// anchored build failed (caller must then use the whole-chunk path).
    pub(crate) fn anchored_regex(&self, fallback_idx: usize) -> Option<&Regex> {
        self.anchored.get(fallback_idx)?.as_ref()?.get()
    }

    /// Whether the localized homoglyph path has any work (an AC or always-mark
    /// set); when false the caller keeps plain patterns on the prefilter path
    /// (the ASCII-fold). `KEYHOG_LOCALIZER=0` forces it off — the localizer's
    /// per-chunk AC overhead is a net end-to-end LOSS on decode-recursion-heavy
    /// inputs (many small sub-chunks), so the lighter single-RegexSet fold is
    /// the better default; the toggle lets it be A/B'd.
    pub(crate) fn has_plain_localizer(&self) -> bool {
        if !localizer_enabled() {
            return false;
        }
        self.plain_anchor_ac.is_some() || !self.plain_always_mark.is_empty()
    }

    /// Plain patterns with no folded leading literal — run whole-chunk on ASCII.
    pub(crate) fn plain_always_mark(&self) -> &[u32] {
        &self.plain_always_mark
    }

    /// Collect `(plain_fallback_idx, byte_pos)` candidates from one pass of the
    /// case-sensitive folded-literal AC over a pure-ASCII `text`. Plain patterns
    /// are always-active, so every AC hit is a candidate (no `is_active` gate).
    /// Sorted + deduped so each `(pat, pos)` is verified once.
    pub(crate) fn collect_plain_candidates(&self, text: &str, out: &mut Vec<(u32, u32)>) {
        out.clear();
        let Some(ac) = &self.plain_anchor_ac else {
            return;
        };
        for m in ac.find_overlapping_iter(text) {
            let lit_id = m.pattern().as_usize();
            let pos = m.start() as u32;
            if let Some(pats) = self.plain_literal_patterns.get(lit_id) {
                for &pat in pats {
                    out.push((pat, pos));
                }
            }
        }
        out.sort_unstable();
        out.dedup();
    }
}

/// Required-prefix literals of an already-folded (non-ASCII-stripped) plain
/// regex `folded` (`[sѕｓ]`→`[s]`, `[lіІιΙｌΟοоOo]`→`[lOo]`). Every match of the
/// homoglyph variant on pure-ASCII text begins with one of these. Case
/// -SENSITIVE parse (plain variants match case-sensitively; the fold's ASCII
/// members carry the case). `None` for an infinite/oversized seq, a member
/// below the anchor floor, or a non-UTF-8 literal — caller runs whole-chunk.
fn leading_literals_of_folded(folded: &str) -> Option<Vec<String>> {
    const MAX_VARIANTS: usize = 64;
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(folded)
        .ok()?;
    let mut extractor = Extractor::new();
    extractor.kind(ExtractKind::Prefix);
    let seq = extractor.extract(&hir);
    if !seq.is_finite() {
        return None;
    }
    let literals = seq.literals()?;
    if literals.is_empty() || literals.len() > MAX_VARIANTS {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(literals.len());
    for lit in literals {
        if lit.len() < MIN_ANCHOR_LEN {
            return None;
        }
        out.push(std::str::from_utf8(lit.as_bytes()).ok()?.to_string());
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Extract the finite set of required prefix literals for `src`, ASCII
/// -lowercased + deduped, or `None` if the pattern is not anchor-eligible
/// (infinite/oversized literal set, or any literal below `MIN_ANCHOR_LEN`).
///
/// `case_insensitive` mirrors the pattern's runtime flag so the extracted
/// literals reflect the real match semantics; case variants collapse under the
/// ASCII-lowercase fold (the shared AC matches case-insensitively).
fn required_prefix_literals(src: &str, case_insensitive: bool) -> Option<Vec<String>> {
    let hir = regex_syntax::ParserBuilder::new()
        .case_insensitive(case_insensitive)
        .build()
        .parse(src)
        .ok()?;
    let mut extractor = Extractor::new();
    extractor.kind(ExtractKind::Prefix);
    let seq = extractor.extract(&hir);

    // Reject infinite/unknown seqs: those carry no sound prefix prefilter.
    if !seq.is_finite() {
        return None;
    }
    let literals = seq.literals()?;
    if literals.is_empty() {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(literals.len());
    for lit in literals {
        // A literal below the anchor floor (or, defensively, an empty one)
        // disqualifies the whole pattern: a 1-2 byte anchor doesn't prune.
        if lit.len() < MIN_ANCHOR_LEN {
            return None;
        }
        // Required-prefix literals are ASCII for the detectors that benefit;
        // a non-UTF-8 literal can't be a `&str` needle, so disqualify.
        let s = std::str::from_utf8(lit.as_bytes())
            .ok()?
            .to_ascii_lowercase();
        out.push(s);
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > MAX_LITERALS_PER_PATTERN {
        return None;
    }
    Some(out)
}

impl CompiledScanner {
    /// Verify one eligible fallback pattern at its candidate anchor positions
    /// using the `\A`-anchored regex, emitting matches via `process_match`.
    ///
    /// This reproduces the whole-chunk `find_iter` walk EXACTLY — non
    /// -overlapping, leftmost, zero-width-skipping — so the produced match set
    /// is byte-identical to `extract_matches` on the same pattern:
    ///   * `positions` are this pattern's candidate starts (sorted, ascending);
    ///     every real match starts at one of them (the anchor is required).
    ///   * `next_allowed` mirrors the whole-chunk cursor: after a match `[s,e)`
    ///     the next search resumes at `e` (or `s+1` for a zero-width match), so
    ///     candidate positions that fall inside an already-consumed match are
    ///     skipped — exactly as the cursor-advance loop skips them.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn extract_anchored(
        &self,
        entry: &CompiledPattern,
        anchored_re: &Regex,
        positions: &[(u32, u32)],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        let Some(detector) = self.detectors.get(entry.detector_index) else {
            tracing::warn!(
                detector_index = entry.detector_index,
                "extract_anchored: detector_index out of range; skipping pattern"
            );
            return;
        };
        let search_text: &str = &preprocessed.text;
        let bytes_total = search_text.len();
        // Per-pattern signal cache: constant across this pattern's matches but
        // expensive (O(K x |chunk|) keyword scan + path AC). Computed at most
        // once, on the first surviving match — same contract as extract.rs.
        let signals = OnceCell::<(bool, bool)>::new();
        let mut locs = anchored_re.capture_locations();
        let groups_total = locs.len();
        let group = entry.group;
        // Mirror the whole-chunk cursor: next match must start at-or-after this.
        let mut next_allowed: usize = 0;
        // Same per-pattern hard cap + deadline cadence as extract.rs's inner
        // loops so an adversarial chunk can't run unbounded under the anchored
        // path either.
        const MAX_INNER_LOOP_ITERS: usize = 1_000_000;
        let mut iters: usize = 0;
        for &(_, pos) in positions {
            let pos = pos as usize;
            if pos < next_allowed {
                continue;
            }
            if iters >= MAX_INNER_LOOP_ITERS {
                break;
            }
            if let Some(deadline) = deadline {
                if iters.is_multiple_of(64) && iters > 0 && std::time::Instant::now() >= deadline {
                    break;
                }
            }
            iters += 1;
            if pos > bytes_total || !search_text.is_char_boundary(pos) {
                continue;
            }
            let slice = &search_text[pos..];
            let Some(whole) = anchored_re.captures_read(&mut locs, slice) else {
                continue;
            };
            // `\A` guarantees a hit starts at slice offset 0; guard defensively.
            if whole.start() != 0 {
                continue;
            }
            let full_start = pos;
            let full_end = pos + whole.end();
            // Zero-width match: skip emission (matches extract.rs) and advance
            // one byte so an empty-shape pattern can't stall.
            if full_end == full_start {
                next_allowed = pos + 1;
                continue;
            }
            next_allowed = full_end;

            // Resolve the credential bytes. For grouped patterns, read the
            // configured capture group (relative to `slice`), with the same
            // variable-name fallback to a value-shaped sibling group as
            // extract_grouped_matches; for plain patterns, the whole match.
            let credential: &str = match group {
                Some(group) => {
                    let (cs, ce) = locs.get(group).unwrap_or((whole.start(), whole.end()));
                    let mut cred = &slice[cs..ce];
                    if looks_like_variable_name(cred) && groups_total > 2 {
                        for g in 1..groups_total {
                            if g == group {
                                continue;
                            }
                            if let Some((s, e)) = locs.get(g) {
                                let cand = &slice[s..e];
                                if !looks_like_variable_name(cand) && cand.len() >= 8 {
                                    cred = cand;
                                    break;
                                }
                            }
                        }
                    }
                    cred
                }
                None => &slice[whole.start()..whole.end()],
            };

            let &(keyword_nearby, sensitive_file) =
                signals.get_or_init(|| super::scan_filters::compute_pattern_signals(detector, chunk));
            self.process_match(
                entry,
                detector,
                search_text,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                credential,
                full_start,
                full_end,
                0,
                0,
                keyword_nearby,
                sensitive_file,
            );
        }
    }
}
