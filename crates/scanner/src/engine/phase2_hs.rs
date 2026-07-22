//! Hyperscan engine for one always-active phase-2 ownership scope.

use super::phase2::ActivePatternsScratch;
use super::*;
use crate::simd::backend::{HsCompileOpts, HsScanner};
use std::time::Instant;

/// Hyperscan-backed always-active prefilter engine. See the `hs` field on
/// [`Phase2AlwaysActivePrefilter`].
///
/// Holds up to two compiled sub-databases:
///   * `full`: every pattern in the selected ownership scope.
///   * `ascii_lean`: that scope's non-homoglyph subset. On a pure-ASCII chunk the
///     homoglyph variants are inert: their look-alike prefixes cannot appear in
///     ASCII bytes, and any match on the ASCII ORIGINAL is already produced by the
///     base pattern via the AC/confirmed path, the exact invariant the RegexSet
///     path's `homoglyph_ascii_skip` (and its `homoglyph_ascii_skip_parity_default`
///     gate) rely on. `None` when the scope has no homoglyph variants to drop.
pub(crate) struct Phase2HsEngine {
    full: HsSubEngine,
    ascii_lean: Option<HsSubEngine>,
}

/// One compiled HS sub-database over a chosen slice of always-active patterns.
struct HsSubEngine {
    scanner: HsScanner,
    /// HS pattern id -> always-active phase-2 index (the `det_idx` slot we set
    /// on each surviving pattern at build).
    hs_to_phase2: Vec<usize>,
    /// Patterns HS could not compile (PCRE feature / over-long): a LOUD host
    /// path (Law 10). Each keeps its own compiled regex and is marked per chunk
    /// via `is_match`, so its recall is preserved, never silently dropped.
    dropped: Vec<(usize, LazyRegex)>,
}

impl HsSubEngine {
    /// Compile an HS database over the given always-active `indices`. Each pattern
    /// carries its OWN case flag (`is_case_insensitive`) so the marked set is
    /// identical to the per-pattern `regex` reference, plus `SINGLEMATCH` so a
    /// broad always-active pattern fires once instead of storming the callback.
    /// Returns `None` (caller keeps the RegexSet path) if no pattern survives.
    fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        indices: &[usize],
    ) -> Option<Self> {
        let mut refs: Vec<(usize, usize, &str, bool)> = Vec::with_capacity(indices.len());
        let mut caseless: Vec<bool> = Vec::with_capacity(indices.len());
        let mut dropped = Vec::new();
        for &idx in indices {
            let (pat, _) = &phase2_patterns[idx];
            if hs_prefilter_requires_host_regex(pat.regex.as_str()) {
                dropped.push((idx, pat.regex.clone()));
                continue;
            }
            // det_idx slot carries the phase-2 index back through `pattern_info`.
            refs.push((idx, 0, pat.regex.as_str(), false));
            caseless.push(pat.regex.is_case_insensitive());
        }
        if refs.is_empty() {
            return None;
        }
        let opts = HsCompileOpts {
            singlematch: true,
            caseless: Some(&caseless),
            // ONE database: the prefilter scans every chunk against all patterns,
            // so a sharded scan would pay the per-shard overhead N times per
            // chunk and lose to the RegexSet on tiny files. A single DB + the
            // no-alloc `scan_each` is the fast path.
            shard_target: Some(usize::MAX),
            // Byte mode (UTF8 off): both the pattern source and the haystack are
            // UTF-8 bytes, so byte matching is correct for the unicode homoglyph
            // classes, and HS_FLAG_UTF8 actually REJECTS many of these patterns
            // at compile (→ silent fallback to RegexSet). Byte mode keeps them on
            // the fast path; findings parity holds (`..._findings_parity`).
            utf8: false,
            parallel_prepare: false,
        };
        let (scanner, unsupported) = match HsScanner::compile_with_opts(&refs, opts) {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(
                    target: "keyhog::phase2",
                    %error,
                    "HS always-active prefilter compile failed; using the regex::RegexSet path",
                );
                return None;
            }
        };
        let mut hs_to_phase2 = vec![0usize; scanner.pattern_count()];
        for hs_id in 0..scanner.pattern_count() {
            if let Some((fb, _, _)) = scanner.pattern_info(hs_id) {
                hs_to_phase2[hs_id] = fb;
            }
        }
        // `unsupported` indexes `refs`; map back to phase-2 indices and keep
        // each on its own compiled regex (the LOUD host path, Law 10).
        for &i in &unsupported {
            let Some((phase2_idx, _, _, _)) = refs.get(i).copied() else {
                panic!(
                    "compiled scanner invariant violation: HS always-active prefilter returned unsupported pattern id outside refs; unsupported_id={i}; refs_len={}; refusing to disable the prefilter",
                    refs.len()
                );
            };
            dropped.push((phase2_idx, phase2_patterns[phase2_idx].0.regex.clone()));
        }
        if !dropped.is_empty() {
            // LAW10: NOT a degrade, these patterns run on the regex host path
            // (see `mark`/`any_match`) with RECALL IDENTICAL to the HS path, so
            // there is nothing to surface loudly. It is a static capability fact
            // (the same count every build), so a per-scan WARN was pure stderr
            // noise that also masked real errors in the installer's first-line
            // reason capture. Demoted to debug (visible via RUST_LOG); recall is
            // unaffected and no fallback is hidden.
            tracing::debug!(
                target: "keyhog::phase2",
                count = dropped.len(),
                "HS prefilter: {} always-active pattern(s) run on the regex host path (HS-incompatible); recall identical",
                dropped.len(),
            );
        }
        Some(Self {
            scanner,
            hs_to_phase2,
            dropped,
        })
    }

    #[inline]
    fn mark(
        &self,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
    ) -> std::result::Result<(), String> {
        // Profile-gated timing split (#68): only take `Instant` when the unified
        // profiler is on, so the unprofiled hot path pays nothing. Attributes the
        // HS-served prefilter cost between the SIMD scan and the dropped host loop.
        let prof = super::profile::enabled();
        let hs_to_phase2 = &self.hs_to_phase2;
        let t_scan = if prof { Some(Instant::now()) } else { None };
        self.scanner
            .scan_each_result(match_text.as_bytes(), |hs_id| {
                if let Some(&fb) = hs_to_phase2.get(hs_id) {
                    scratch.mark(fb);
                }
            })?;
        if let Some(t) = t_scan {
            super::phase2::record_hs_mark_scan_ns(t.elapsed().as_nanos() as u64);
        }
        let t_dropped = if prof { Some(Instant::now()) } else { None };
        for (idx, re) in &self.dropped {
            if re.get().is_match(match_text) {
                scratch.mark(*idx);
            }
        }
        if let Some(t) = t_dropped {
            super::phase2::record_hs_mark_dropped_ns(t.elapsed().as_nanos() as u64);
        }
        Ok(())
    }

    #[inline]
    fn any_match(&self, match_text: &str) -> std::result::Result<bool, String> {
        if self.scanner.any_match_result(match_text.as_bytes())? {
            return Ok(true);
        }
        for (_idx, re) in &self.dropped {
            if re.get().is_match(match_text) {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Phase2HsEngine {
    /// Compile the selected ownership scope and, when useful, its non-homoglyph
    /// ASCII subset. Returns `None` when no pattern survives compilation.
    pub(crate) fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active: &[usize],
    ) -> Option<Self> {
        let full = HsSubEngine::build(phase2_patterns, always_active)?;
        // Lean ASCII sub-DB: the non-homoglyph always-active patterns. Built ONLY
        // when it is a strict subset (there are homoglyph variants to skip on
        // ASCII); otherwise ASCII reuses `full` (no second DB, no extra memory).
        let non_homoglyph: Vec<usize> = always_active
            .iter()
            .copied()
            .filter(|&i| !phase2_patterns[i].0.homoglyph_variant)
            .collect();
        let ascii_lean = if non_homoglyph.len() < always_active.len() {
            HsSubEngine::build(phase2_patterns, &non_homoglyph)
        } else {
            None
        };
        Some(Self { full, ascii_lean })
    }

    /// Pick the sub-engine for this chunk: the lean ASCII DB when the caller has
    /// determined the homoglyph-ASCII skip applies (pure-ASCII chunk +
    /// `homoglyph_ascii_skip` tuning on) and a lean DB exists; else the full DB.
    #[inline]
    fn engine_for(&self, skip_homoglyph_ascii: bool) -> &HsSubEngine {
        if skip_homoglyph_ascii {
            self.ascii_lean.as_ref().map_or(&self.full, |engine| engine)
        } else {
            &self.full
        }
    }

    /// Mark every pattern in this ownership scope that can match `match_text`. One SIMD
    /// scan marks the HS-covered patterns; the loud host path marks the few
    /// HS-incompatible ones. The marked set is a sound superset of the matching
    /// patterns (extraction filters), identical to the RegexSet path.
    ///
    /// `skip_homoglyph_ascii` MUST be computed by the caller as `chunk.is_ascii()
    /// && tuning.homoglyph_ascii_skip`, the same predicate the RegexSet path uses
    /// to skip homoglyph batches (so the two engines stay findings-consistent).
    #[inline]
    pub(crate) fn mark(
        &self,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
        skip_homoglyph_ascii: bool,
    ) -> std::result::Result<(), String> {
        self.engine_for(skip_homoglyph_ascii)
            .mark(match_text, scratch)
    }

    /// True iff ANY always-active pattern can fire on `match_text`. The BOOLEAN
    /// companion to [`mark`](Self::mark): one SIMD scan that early-exits at the
    /// first hit (HS native termination), plus the loud host path for the few
    /// HS-incompatible patterns. Recall-identical to `mark(...)` followed by a
    /// non-empty check (same patterns, same haystack (without building the set)).
    #[inline]
    pub(crate) fn any_match(
        &self,
        match_text: &str,
        skip_homoglyph_ascii: bool,
    ) -> std::result::Result<bool, String> {
        self.engine_for(skip_homoglyph_ascii).any_match(match_text)
    }
}

pub(crate) fn hs_prefilter_requires_host_regex(src: &str) -> bool {
    let mut escaped = false;
    let mut in_class = false;
    for ch in src.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '^' | '$' if !in_class => return true,
            _ => {}
        }
    }
    false
}
