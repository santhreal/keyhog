//! Shared-anchor localization for the keyword-gated phase-2 scan.
//!
//! ## The problem
//!
//! `scan_phase2_patterns` runs each fired phase-2 pattern's capture regex
//! over the WHOLE chunk. The per-pattern profile (`phase2_pattern_profile`)
//! shows ~82 patterns active on a 16 KiB chunk, each effectively doing its own
//! `memchr`/prefilter pass over the chunk for its literal: 82 redundant chunk
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
//! `\A`-anchored copy of the pattern's regex at exactly that position. For
//! non-zero positions, verification includes the real previous character before
//! the candidate so left-boundary constructs remain whole-chunk-equivalent. The
//! 82 chunk passes collapse to one shared AC pass plus a handful of O(match
//! length) anchored verifications.
//!
//! ## Soundness (recall is identical, proven by differential test)
//!
//! For an eligible pattern P with required-prefix literal set L(P): every match
//! M of P starts with some l ∈ L(P), so M's start byte is a position where the
//! AC reports l. Verifying P anchored at every AC-reported position therefore
//! finds every match the whole-chunk walk would (`phase2_anchor_parity`
//! asserts byte-identical `RawMatch` sets over the corpora + generated inputs).
//! A pattern whose required-literal set cannot be proven finite/short (pure
//! char-class bodies, homoglyph unicode cross-products) is NOT eligible and
//! keeps the whole-chunk path (never a silent recall trade).

use super::phase2::{ascii_fold_regex_src, gate_prefix_literals, MIN_PREFIX_BYTES};
use super::phase2_first_bigram::FirstBigramSet;
use crate::anchored_regex::AnchoredRegex;
use crate::types::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use std::sync::{Arc, Mutex, OnceLock};

/// Cap on distinct (ASCII-lowercased) required-prefix literals per pattern.
/// Canonical ASCII detector patterns with optional separators/case spellings
/// can produce more than the old 8-literal floor (`mx[_-]?api[_-]?key` has
/// 29) while still being selective and cheap to verify. Homoglyph cross
/// products and giant alternations still exceed this and stay whole-chunk.
const MAX_LITERALS_PER_PATTERN: usize = 32;
pub(crate) const CONFIRMED_MAX_LITERALS_PER_PATTERN: usize = 8;

struct LazyAnchorAc {
    literals: Mutex<Option<Box<[Arc<str>]>>>,
    ascii_case_insensitive: bool,
    failure_message: &'static str,
    cell: OnceLock<Option<AhoCorasick>>,
}

impl LazyAnchorAc {
    fn new(
        literals: Vec<Arc<str>>,
        ascii_case_insensitive: bool,
        failure_message: &'static str,
    ) -> Self {
        Self {
            literals: Mutex::new(Some(literals.into_boxed_slice())),
            ascii_case_insensitive,
            failure_message,
            cell: OnceLock::new(),
        }
    }

    fn get(&self) -> (Option<&AhoCorasick>, bool) {
        let already_initialized = self.cell.get().is_some();
        let anchor = self.cell.get_or_init(|| {
            let literals = self
                .literals
                .lock()
                // LAW10: poison recovery retains the immutable literal set; anchor construction still runs in full.
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .expect("lazy phase-2 anchor literals must exist before initialization");
            match AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(self.ascii_case_insensitive)
                .build(literals.iter().map(|literal| literal.as_bytes()))
            {
                Ok(anchor) => Some(anchor),
                Err(error) => {
                    tracing::warn!(
                        literals = literals.len(),
                        %error,
                        "{}",
                        self.failure_message
                    );
                    None
                }
            }
        });
        (anchor.as_ref(), !already_initialized)
    }

    fn is_available(&self) -> bool {
        !matches!(self.cell.get(), Some(None))
    }
}

fn intern_anchor_literal(
    ids: &mut std::collections::HashMap<Arc<str>, usize>,
    literals: &mut Vec<Arc<str>>,
    literal: &str,
) -> usize {
    if let Some(&id) = ids.get(literal) {
        return id;
    }
    let literal: Arc<str> = Arc::from(literal);
    let id = literals.len();
    literals.push(Arc::clone(&literal));
    ids.insert(literal, id);
    id
}

/// Per-scanner index that drives shared-anchor phase-2 localization AND
/// replaces the always-active RegexSet prefilter for eligible patterns.
pub(crate) struct Phase2AnchorIndex {
    /// One lazily built automaton over every eligible pattern's required-prefix
    /// literals. The first-bigram gate runs before initialization, so empty and
    /// no-candidate scans never materialize this dominant startup owner.
    anchor_ac: Option<LazyAnchorAc>,
    /// First-bigram prescreen for `anchor_ac`.
    anchor_first_bigram: Option<FirstBigramSet>,
    /// `anchor_ac` pattern id -> phase-2 indices that declared this literal.
    literal_patterns: super::CsrU32,
    /// Per phase-2 index: eligible for the anchored fast path.
    eligible: Box<[bool]>,
    /// Per phase-2 index: eligible AND always-active (no >=4-char keyword).
    /// These are gated+located purely by the shared AC, so they are REMOVED
    /// from the expensive always-active RegexSet prefilter (the main win).
    always_active_eligible: Box<[bool]>,
    /// Separate AC over only always-active eligible literals. Sparse
    /// keyword-triggered chunks can use this small index for always-active
    /// semantics and run the few active keyword patterns whole-window instead
    /// of paying the all-eligible shared AC scan.
    always_anchor_ac: Option<AhoCorasick>,
    /// Literal rows backing `always_anchor_ac`, in the same order as the AC
    /// pattern IDs. The GPU producer appends these after detector literals and
    /// phase-2 keywords so an all-zero tail row proves this small AC has no
    /// possible match in that chunk.
    always_anchor_literals: Box<[String]>,
    /// First-bigram prescreen for `always_anchor_ac`.
    always_anchor_first_bigram: Option<FirstBigramSet>,
    /// `always_anchor_ac` pattern id -> always-active phase-2 indices.
    always_literal_patterns: super::CsrU32,
    /// Per phase-2 index: the anchored regex (Some iff eligible OR plain
    /// -anchorable (the localized homoglyph path also runs `\A(?:regex)`)).
    anchored: Box<[Option<AnchoredRegex>]>,
    /// Count of eligible patterns (diagnostics).
    eligible_count: usize,

    // --- Localized homoglyph path (ASCII chunks only) ---
    /// Lazily built case-sensitive Aho-Corasick over the plain (homoglyph)
    /// patterns' folded leading literals. Disabled or no-candidate scans retain
    /// only the compact literal source until this localizer is actually used.
    plain_anchor_ac: Option<LazyAnchorAc>,
    /// First-bigram prescreen for `plain_anchor_ac`.
    plain_anchor_first_bigram: Option<FirstBigramSet>,
    /// `plain_anchor_ac` literal id -> plain phase-2 indices.
    plain_literal_patterns: super::CsrU32,
    /// Plain patterns with NO usable folded literal: run whole-chunk on ASCII
    /// chunks (they are few (homoglyph variants almost always have a prefix)).
    plain_always_mark: Box<[u32]>,
}

pub(crate) fn compile_localization_hint(
    pattern: &CompiledPattern,
) -> crate::compiler::compiler_build::Phase2LocalizationHint {
    use crate::compiler::compiler_build::Phase2LocalizationHint;

    let source = pattern.regex.as_str();
    if let Some(literals) = required_prefix_literals(source) {
        return Phase2LocalizationHint::Prefix { literals };
    }
    if pattern.regex.is_case_insensitive() {
        return Phase2LocalizationHint::None;
    }
    let folded_regex = ascii_fold_regex_src(source);
    Phase2LocalizationHint::Plain {
        literals: leading_literals_of_folded(&folded_regex),
        folded_regex,
    }
}

impl Phase2AnchorIndex {
    pub(crate) fn eligible_count(&self) -> usize {
        self.eligible_count
    }
    /// Build scan-time automata before a non-empty batch allocates per-chunk
    /// scratch. Empty sources keep only compact literal rows. Returns whether
    /// this call materialized any new automaton.
    pub(crate) fn materialize_for_batch(&self, plain_localizer: bool) -> bool {
        let mut materialized = self.anchor_ac.as_ref().is_some_and(|anchor| anchor.get().1);
        if plain_localizer {
            materialized |= self
                .plain_anchor_ac
                .as_ref()
                .is_some_and(|anchor| anchor.get().1);
        }
        materialized
    }

    #[inline]
    pub(crate) fn is_eligible(&self, phase2_idx: usize) -> bool {
        if !self
            .anchor_ac
            .as_ref()
            .is_some_and(LazyAnchorAc::is_available)
        {
            return false;
        }
        matches!(self.eligible.get(phase2_idx), Some(true)) // LAW10: pattern not anchor-eligible => caller runs whole-chunk; anchor is a prefilter opt, recall-preserving
    }

    #[inline]
    pub(crate) fn is_always_active_eligible(&self, phase2_idx: usize) -> bool {
        if self.always_anchor_ac.is_none() {
            return false;
        }
        matches!(self.always_active_eligible.get(phase2_idx), Some(true)) // LAW10: pattern not anchor-eligible => caller runs whole-chunk; anchor is a prefilter opt, recall-preserving
    }

    pub(crate) fn always_anchor_literals(&self) -> &[String] {
        &self.always_anchor_literals
    }

    /// Build the index from the compiled phase-2 set. `always_active_indices`
    /// are the phase-2 patterns with no >=4-char keyword (gated today by the
    /// RegexSet prefilter); the eligible subset of those is recorded so the
    /// caller can shrink the prefilter to only the non-eligible remainder.
    /// Always succeeds: a pattern whose required-prefix literals can't be proven
    /// finite/short simply isn't eligible (whole-chunk). Returns `None` only when
    /// NO pattern is eligible (the anchored path is then a no-op and skipped).
    pub(crate) fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
    ) -> Option<Self> {
        Self::build_with_hints(phase2_patterns, always_active_indices, None)
    }

    pub(crate) fn build_with_hints(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        localization_hints: Option<Vec<crate::compiler::compiler_build::Phase2LocalizationHint>>,
    ) -> Option<Self> {
        if localization_hints.is_none() {
            crate::execution_pack::matcher_sections::record_runtime_localization_hint_fallback();
        }
        let mut localization_hints = localization_hints.map(Vec::into_iter);
        Self::build_from_hints(
            phase2_patterns,
            always_active_indices,
            &mut localization_hints,
        )
    }

    fn build_from_hints(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active_indices: &[usize],
        localization_hints: &mut Option<
            std::vec::IntoIter<crate::compiler::compiler_build::Phase2LocalizationHint>,
        >,
    ) -> Option<Self> {
        let mut eligible = vec![false; phase2_patterns.len()];
        let mut anchored: Vec<Option<AnchoredRegex>> =
            (0..phase2_patterns.len()).map(|_| None).collect();
        // The compiler map and retained literal row share each unique source.
        let mut literal_ids: std::collections::HashMap<Arc<str>, usize> =
            std::collections::HashMap::new();
        let mut literals: Vec<Arc<str>> = Vec::new();
        let mut literal_pattern_pairs = Vec::new();
        // Plain (homoglyph) localized path: separate case-sensitive AC.
        let mut plain_literal_ids: std::collections::HashMap<Arc<str>, usize> =
            std::collections::HashMap::new();
        let mut plain_literals: Vec<Arc<str>> = Vec::new();
        let mut plain_literal_pattern_pairs = Vec::new();
        let mut plain_always_mark: Vec<u32> = Vec::new();

        for (idx, (pattern, _keywords)) in phase2_patterns.iter().enumerate() {
            use crate::compiler::compiler_build::Phase2LocalizationHint;

            let hint = match localization_hints.as_mut() {
                // LAW10: authenticated hint cardinality drift is a loud build-invariant panic.
                Some(hints) => hints.next().unwrap_or_else(|| {
                    panic!(
                        "BUILD-INVARIANT VIOLATION: phase-2 localization hint cardinality is shorter than the compiled pattern set"
                    )
                }),
                None => compile_localization_hint(pattern),
            };
            match hint {
                Phase2LocalizationHint::Prefix {
                    literals: pattern_literals,
                } => {
                    for literal in &pattern_literals {
                        let id = intern_anchor_literal(&mut literal_ids, &mut literals, literal);
                        literal_pattern_pairs.push((id, idx));
                    }
                    eligible[idx] = true;
                    anchored[idx] = Some(AnchoredRegex::new(
                        pattern.regex.as_str(),
                        pattern.regex.is_case_insensitive(),
                    ));
                }
                Phase2LocalizationHint::Plain {
                    folded_regex,
                    literals: Some(pattern_literals),
                } => {
                    for literal in &pattern_literals {
                        let id = intern_anchor_literal(
                            &mut plain_literal_ids,
                            &mut plain_literals,
                            literal,
                        );
                        plain_literal_pattern_pairs.push((id, idx));
                    }
                    anchored[idx] = Some(AnchoredRegex::new(&folded_regex, false));
                }
                Phase2LocalizationHint::Plain { literals: None, .. } => {
                    plain_always_mark.push(idx as u32);
                }
                Phase2LocalizationHint::None => {}
            }
        }
        // Drop compiler lookup tables before CSR and automaton construction;
        // their shared source allocations remain owned by the compact rows.
        drop(literal_ids);
        drop(plain_literal_ids);

        let literal_patterns = super::CsrU32::from_pairs(literals.len(), literal_pattern_pairs);
        let plain_literal_patterns =
            super::CsrU32::from_pairs(plain_literals.len(), plain_literal_pattern_pairs);

        let eligible_count = eligible.iter().filter(|&&e| e).count();
        if eligible_count == 0 && plain_literals.is_empty() && plain_always_mark.is_empty() {
            return None;
        }

        // Mark eligible always-active patterns: these leave the RegexSet
        // prefilter entirely and are gated by the shared AC instead.
        let mut always_active_eligible = vec![false; phase2_patterns.len()];
        for &i in always_active_indices {
            if eligible.get(i).copied().is_some_and(|v| v) {
                // Law 10: pattern not anchor-eligible => caller runs whole-chunk; anchor is a prefilter opt, recall-preserving
                always_active_eligible[i] = true;
            }
        }
        let mut always_literals: Vec<String> = Vec::new();
        let mut always_literal_pattern_pairs = Vec::new();
        for (literal_id, patterns) in literal_patterns.iter().enumerate() {
            let always_literal_id = always_literals.len();
            let mut retained_literal = false;
            for &pattern in patterns {
                if matches!(always_active_eligible.get(pattern as usize), Some(true)) {
                    if !retained_literal {
                        if let Some(literal) = literals.get(literal_id) {
                            always_literals.push(literal.to_string());
                        }
                        retained_literal = true;
                    }
                    always_literal_pattern_pairs.push((always_literal_id, pattern as usize));
                }
            }
        }
        let always_literal_patterns =
            super::CsrU32::from_pairs(always_literals.len(), always_literal_pattern_pairs);
        // MatchKind::Standard is required for find_overlapping_iter; ASCII-case
        // -insensitive so a single lowercase literal anchors all case variants.
        let anchor_first_bigram = (!literals.is_empty()).then(|| {
            FirstBigramSet::from_literals(literals.iter().map(|literal| literal.as_bytes()), true)
        });
        let anchor_ac = (!literals.is_empty()).then(|| {
            LazyAnchorAc::new(
                literals,
                true,
                "phase-2 shared-anchor Aho-Corasick build failed; keyword-triggered anchored patterns stay on the whole-chunk path (recall preserved)",
            )
        });
        let always_anchor_first_bigram = (!always_literals.is_empty()).then(|| {
            FirstBigramSet::from_literals(always_literals.iter().map(String::as_bytes), true)
        });
        let always_anchor_ac = if always_literals.is_empty() {
            None
        } else {
            match AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(true)
                .build(&always_literals)
            {
                Ok(ac) => Some(ac),
                Err(error) => {
                    tracing::warn!(
                        literals = always_literals.len(),
                        %error,
                        "phase-2 always-active shared-anchor Aho-Corasick build failed; always-active anchored patterns stay on the RegexSet path (recall preserved)"
                    );
                    None
                }
            }
        };
        // Case-SENSITIVE AC for the plain folded literals (the fold keeps exact
        // ASCII members, e.g. `[s]` from `[sѕｓ]`, so case-sensitivity is already
        // encoded).
        let plain_anchor_first_bigram = (!plain_literals.is_empty()).then(|| {
            FirstBigramSet::from_literals(
                plain_literals.iter().map(|literal| literal.as_bytes()),
                false,
            )
        });
        let plain_anchor_ac = (!plain_literals.is_empty()).then(|| {
            LazyAnchorAc::new(
                plain_literals,
                false,
                "phase-2 plain-anchor Aho-Corasick build failed; plain patterns stay on the folded RegexSet path (recall preserved)",
            )
        });

        Some(Self {
            anchor_ac,
            anchor_first_bigram,
            literal_patterns,
            eligible: eligible.into_boxed_slice(),
            always_active_eligible: always_active_eligible.into_boxed_slice(),
            always_anchor_ac,
            always_anchor_literals: always_literals.into_boxed_slice(),
            always_anchor_first_bigram,
            always_literal_patterns,
            anchored: anchored.into_boxed_slice(),
            eligible_count,
            plain_anchor_ac,
            plain_anchor_first_bigram,
            plain_literal_patterns,
            plain_always_mark: plain_always_mark.into_boxed_slice(),
        })
    }

    #[inline]
    fn collect_ac_candidates<'a>(
        ac: impl FnOnce() -> Option<&'a AhoCorasick>,
        first_bigram: Option<&FirstBigramSet>,
        literal_patterns: &super::CsrU32,
        text: &str,
        mut predicate: impl FnMut(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        out.clear();
        if first_bigram.is_some_and(|gate| !gate.may_have_match(text)) {
            return;
        }
        let Some(ac) = ac() else {
            return;
        };
        for m in ac.find_overlapping_iter(text) {
            let lit_id = m.pattern().as_usize();
            let pos = m.start() as u32;
            if let Some(pats) = literal_patterns.get(lit_id) {
                for &pat in pats {
                    if predicate(pat as usize) {
                        out.push((pat, pos));
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
    }

    /// Collect candidate `(phase2_idx, byte_pos)` anchors for the eligible
    /// patterns that are marked active in `is_active`. One shared AC pass over
    /// `text`. Results are pushed into `out` (caller-owned, reused scratch);
    /// `out` is sorted + deduped on return so each (pattern, pos) is verified
    /// once even when overlapping literals report the same start.
    /// A candidate `(pat, pos)` is collected when the pattern can fire here:
    ///   * an eligible ALWAYS-ACTIVE pattern is gated solely by anchor presence
    ///     (it left the RegexSet prefilter), so any AC hit activates it;
    ///   * an eligible KEYWORD-TRIGGERED pattern keeps its keyword gate, so it
    ///     is collected only when `is_active` (its keyword fired), preserving
    ///     the exact current active-set semantics.
    pub(crate) fn collect_candidates(
        &self,
        text: &str,
        is_active: impl Fn(usize) -> bool,
        is_allowed: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        Self::collect_ac_candidates(
            || self.anchor_ac.as_ref().and_then(|anchor| anchor.get().0),
            self.anchor_first_bigram.as_ref(),
            &self.literal_patterns,
            text,
            |pat| is_allowed(pat) && (self.is_always_active_eligible(pat) || is_active(pat)),
            out,
        );
    }

    pub(crate) fn collect_always_active_candidates(
        &self,
        text: &str,
        is_allowed: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        Self::collect_ac_candidates(
            || self.always_anchor_ac.as_ref(),
            self.always_anchor_first_bigram.as_ref(),
            &self.always_literal_patterns,
            text,
            is_allowed,
            out,
        );
    }

    /// Expand complete literal positions from the fused GPU matcher into the
    /// same canonical `(phase2_pattern, offset)` candidates as the host AC.
    pub(crate) fn collect_always_active_candidates_from_literal_matches(
        &self,
        literal_matches: &[(u32, u32)],
        is_allowed: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        out.clear();
        for &(literal_id, pos) in literal_matches {
            let Some(patterns) = self.always_literal_patterns.get(literal_id as usize) else {
                continue;
            };
            for &pattern in patterns {
                if is_allowed(pattern as usize) {
                    out.push((pattern, pos));
                }
            }
        }
        out.sort_unstable();
        out.dedup();
    }

    /// The anchored regex owner for `phase2_idx`, or `None` if not eligible.
    /// The caller chooses the no-context or left-context compiled variant for
    /// each candidate position.
    pub(crate) fn anchored_regex(&self, phase2_idx: usize) -> Option<&AnchoredRegex> {
        let anchored = self.anchored.get(phase2_idx)?.as_ref()?;
        // The slot's presence IS eligibility; `AnchoredRegex::get()` is now
        // fail-closed (compiles-or-panics, never None), so no compile pre-check.
        Some(anchored)
    }

    /// Whether the localized homoglyph path has any work (an AC or always-mark
    /// set); when false the caller keeps plain patterns on the prefilter path
    /// (the ASCII-fold). The localizer's per-chunk AC overhead is a net
    /// end-to-end LOSS on decode-recursion-heavy inputs (many small sub-chunks),
    /// so the lighter single-RegexSet fold is the better default; explicit
    /// tuning lets it be A/B'd.
    pub(crate) fn has_plain_localizer(&self, phase2_plain_localizer: bool) -> bool {
        if !phase2_plain_localizer {
            return false;
        }
        self.plain_anchor_ac
            .as_ref()
            .is_some_and(LazyAnchorAc::is_available)
            || (!self.plain_always_mark.is_empty() && self.plain_anchor_ac.is_none())
    }

    /// Plain patterns with no folded leading literal (run whole-chunk on ASCII).
    pub(crate) fn plain_always_mark(&self) -> &[u32] {
        &self.plain_always_mark
    }

    /// Collect `(plain_phase2_idx, byte_pos)` candidates from one pass of the
    /// case-sensitive folded-literal AC over a pure-ASCII `text`. Plain patterns
    /// are always-active, so every AC hit is a candidate (no `is_active` gate).
    /// Sorted + deduped so each `(pat, pos)` is verified once.
    pub(crate) fn collect_plain_candidates(
        &self,
        text: &str,
        is_allowed: impl Fn(usize) -> bool,
        out: &mut Vec<(u32, u32)>,
    ) {
        Self::collect_ac_candidates(
            || self.plain_anchor_ac.as_ref().and_then(|a| a.get().0),
            self.plain_anchor_first_bigram.as_ref(),
            &self.plain_literal_patterns,
            text,
            is_allowed,
            out,
        );
    }
}

/// Required-prefix literals of an already-folded (non-ASCII-stripped) plain
/// regex `folded` (`[sѕｓ]`→`[s]`, `[lіІιΙｌΟοо]`→`[l]`). Every match of the
/// homoglyph variant on pure-ASCII text begins with one of these. Case
/// -SENSITIVE parse (plain variants match case-sensitively; the fold's ASCII
/// members carry the case). `None` for an infinite/oversized seq, a member
/// below the anchor floor, or a non-UTF-8 literal (caller runs whole-chunk).
fn leading_literals_of_folded(folded: &str) -> Option<Vec<String>> {
    const MAX_VARIANTS: usize = 64;
    let hir = regex_syntax::ParserBuilder::new()
        .build()
        .parse(folded)
        .ok()?; // LAW10: pattern not anchor-eligible => caller runs whole-chunk; anchor is a prefilter opt, recall-preserving
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
        if lit.len() < MIN_PREFIX_BYTES {
            return None;
        }
        out.push(std::str::from_utf8(lit.as_bytes()).ok()?.to_string()); // LAW10: pattern not anchor-eligible => caller runs whole-chunk; anchor is a prefilter opt, recall-preserving
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// Extract the finite set of required prefix literals for `src`, ASCII
/// -lowercased + deduped, or `None` if the pattern is not anchor-eligible.
///
/// The proof source is the same `gate_prefix_literals` primitive used by the
/// phase-2 no-candidate gate: canonical regex parse, finite prefix literals,
/// every member ASCII and at least `MIN_PREFIX_BYTES`. The localizer's AC is
/// ASCII-case-insensitive and the verifier runs the exact runtime regex at the
/// candidate start, so canonical ASCII literals are sound even for detector
/// regexes compiled with global case-insensitive matching. Non-ASCII prefixes
/// stay whole-chunk rather than relying on incomplete ASCII folding.
pub(crate) fn required_prefix_literals(src: &str) -> Option<Vec<String>> {
    required_prefix_literals_with_cap(src, MAX_LITERALS_PER_PATTERN)
}

pub(crate) fn required_prefix_literals_with_cap(
    src: &str,
    max_literals_per_pattern: usize,
) -> Option<Vec<String>> {
    let literals = gate_prefix_literals(src)?;
    let mut out: Vec<String> = Vec::with_capacity(literals.len());
    for lit in literals {
        debug_assert!(lit.len() >= MIN_PREFIX_BYTES);
        debug_assert!(lit.is_ascii());
        let s = std::str::from_utf8(&lit)
            .ok()? // LAW10: pattern not anchor-eligible => caller runs whole-chunk; anchor is a prefilter opt, recall-preserving
            .to_ascii_lowercase();
        out.push(s);
    }
    out.sort_unstable();
    out.dedup();
    if out.len() > max_literals_per_pattern {
        return None;
    }
    Some(out)
}
