//! Hyperscan-backed always-active phase-2 prefilter engine (`Phase2HsEngine`).
//! Extracted from `phase2.rs`; simd-only (the whole module is cfg-gated). Holds
//! the compiled HS database for the always-active phase-2 set and marks matches
//! into the caller's scratch. Pure move, no behaviour change. The module is
//! gated `#[cfg(feature = "simd")]` at its `mod` declaration in `engine/mod.rs`.

use super::phase2::ActivePatternsScratch;
use super::*;
use crate::simd::backend::{HsCompileOpts, HsScanner};

/// Hyperscan-backed always-active prefilter engine. See the `hs` field on
/// [`Phase2AlwaysActivePrefilter`].
pub(crate) struct Phase2HsEngine {
    scanner: HsScanner,
    /// HS pattern id -> always-active phase-2 index (the `det_idx` slot we set
    /// on each surviving pattern at build).
    hs_to_phase2: Vec<usize>,
    /// Patterns HS could not compile (PCRE feature / over-long): a LOUD host
    /// path (Law 10). Each keeps its own compiled regex and is marked per chunk
    /// via `is_match`, so its recall is preserved, never silently dropped.
    dropped: Vec<(usize, LazyRegex)>,
}

impl Phase2HsEngine {
    /// Compile an HS database over the always-active patterns. Each pattern
    /// carries its OWN case flag (`is_case_insensitive`) so the marked set is
    /// identical to the per-pattern `regex` reference, plus `SINGLEMATCH` so a
    /// broad always-active pattern fires once instead of storming the callback.
    /// Returns `None` (caller keeps the RegexSet path) if no pattern survives.
    pub(crate) fn build(
        phase2_patterns: &[(CompiledPattern, Vec<String>)],
        always_active: &[usize],
    ) -> Option<Self> {
        let mut refs: Vec<(usize, usize, &str, bool)> = Vec::with_capacity(always_active.len());
        let mut caseless: Vec<bool> = Vec::with_capacity(always_active.len());
        let mut dropped = Vec::new();
        for &idx in always_active {
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
        };
        let (scanner, unsupported) = match HsScanner::compile_with_opts(&refs, opts) {
            Ok(v) => v,
            Err(error) => {
                tracing::warn!(
                    target: "keyhog::phase2",
                    %error,
                    "HS always-active prefilter compile failed — using the regex::RegexSet path",
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
            // LAW10: NOT a degrade — these patterns run on the regex host path
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

    /// Mark every always-active pattern that can match `match_text`. One SIMD
    /// scan marks the HS-covered patterns; the loud host path marks the few
    /// HS-incompatible ones. The marked set is a sound superset of the matching
    /// patterns (extraction filters), identical to the RegexSet path.
    #[inline]
    pub(crate) fn mark(
        &self,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
    ) -> std::result::Result<(), String> {
        let hs_to_phase2 = &self.hs_to_phase2;
        self.scanner
            .scan_each_result(match_text.as_bytes(), |hs_id| {
                if let Some(&fb) = hs_to_phase2.get(hs_id) {
                    scratch.mark(fb);
                }
            })?;
        for (idx, re) in &self.dropped {
            if re.get().is_match(match_text) {
                scratch.mark(*idx);
            }
        }
        Ok(())
    }

    /// True iff ANY always-active pattern can fire on `match_text`. The BOOLEAN
    /// companion to [`mark`](Self::mark): one SIMD scan that early-exits at the
    /// first hit (HS native termination), plus the loud host path for the few
    /// HS-incompatible patterns. Recall-identical to `mark(...)` followed by a
    /// non-empty check — same patterns, same haystack — without building the set.
    #[inline]
    pub(crate) fn any_match(&self, match_text: &str) -> std::result::Result<bool, String> {
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
