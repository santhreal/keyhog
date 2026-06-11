//! Hyperscan-backed always-active fallback prefilter engine (`HsFallbackEngine`).
//! Extracted from `fallback.rs`; simd-only (the whole module is cfg-gated). Holds
//! the compiled HS database for the always-active fallback set and marks matches
//! into the caller's scratch. Pure move, no behaviour change.
#![cfg(feature = "simd")]

use super::fallback::ActivePatternsScratch;
use super::*;
use crate::simd::backend::{HsCompileOpts, HsScanner};

/// Hyperscan-backed always-active prefilter engine. See the `hs` field on
/// [`AlwaysActiveFallbackPrefilter`].
pub(crate) struct HsFallbackEngine {
    scanner: HsScanner,
    /// HS pattern id -> always-active fallback index (the `det_idx` slot we set
    /// on each surviving pattern at build).
    hs_to_fallback: Vec<usize>,
    /// Patterns HS could not compile (PCRE feature / over-long): a LOUD host
    /// path (Law 10). Each keeps its own compiled regex and is marked per chunk
    /// via `is_match`, so its recall is preserved, never silently dropped.
    dropped: Vec<(usize, LazyRegex)>,
}

impl HsFallbackEngine {
    /// Compile an HS database over the always-active patterns. Each pattern
    /// carries its OWN case flag (`is_case_insensitive`) so the marked set is
    /// identical to the per-pattern `regex` reference, plus `SINGLEMATCH` so a
    /// broad always-active pattern fires once instead of storming the callback.
    /// Returns `None` (caller keeps the RegexSet path) if no pattern survives.
    pub(crate) fn build(
        fallback: &[(CompiledPattern, Vec<String>)],
        always_active: &[usize],
    ) -> Option<Self> {
        let mut refs: Vec<(usize, usize, &str, bool)> = Vec::with_capacity(always_active.len());
        let mut caseless: Vec<bool> = Vec::with_capacity(always_active.len());
        for &idx in always_active {
            let Some((pat, _)) = fallback.get(idx) else {
                continue;
            };
            // det_idx slot carries the fallback index back through `pattern_info`.
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
                    target: "keyhog::fallback",
                    %error,
                    "HS always-active prefilter compile failed — using the regex::RegexSet path",
                );
                return None;
            }
        };
        let mut hs_to_fallback = vec![0usize; scanner.pattern_count()];
        for hs_id in 0..scanner.pattern_count() {
            if let Some((fb, _, _)) = scanner.pattern_info(hs_id) {
                hs_to_fallback[hs_id] = fb;
            }
        }
        // `unsupported` indexes `refs`; map back to fallback indices and keep
        // each on its own compiled regex (the LOUD host path, Law 10).
        let dropped: Vec<(usize, LazyRegex)> = unsupported
            .iter()
            .filter_map(|&i| refs.get(i).map(|r| r.0))
            .map(|fb_idx| (fb_idx, fallback[fb_idx].0.regex.clone()))
            .collect();
        if !dropped.is_empty() {
            tracing::warn!(
                target: "keyhog::fallback",
                count = dropped.len(),
                "HS prefilter: {} always-active pattern(s) on the loud regex host path (HS-incompatible)",
                dropped.len(),
            );
        }
        Some(Self {
            scanner,
            hs_to_fallback,
            dropped,
        })
    }

    /// Mark every always-active pattern that can match `match_text`. One SIMD
    /// scan marks the HS-covered patterns; the loud host path marks the few
    /// HS-incompatible ones. The marked set is a sound superset of the matching
    /// patterns (extraction filters), identical to the RegexSet path.
    #[inline]
    pub(crate) fn mark(&self, match_text: &str, scratch: &mut ActivePatternsScratch) {
        let hs_to_fallback = &self.hs_to_fallback;
        self.scanner.scan_each(match_text.as_bytes(), |hs_id| {
            if let Some(&fb) = hs_to_fallback.get(hs_id) {
                scratch.mark(fb);
            }
        });
        for (idx, re) in &self.dropped {
            if re.get().is_match(match_text) {
                scratch.mark(*idx);
            }
        }
    }
}
