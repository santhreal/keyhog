//! Anchored-position verification for the shared-anchor phase-2 localizer.
//!
//! Split out of `phase2_anchor.rs` (Law 5, 500-LOC ceiling). That file owns
//! the `Phase2AnchorIndex` build + candidate-collection machinery; this is the
//! consumer side: `CompiledScanner::extract_anchored` replays the whole-chunk
//! `find_iter` walk for ONE eligible pattern at its candidate anchor positions,
//! emitting byte-identical matches via `process_match`. See `phase2_anchor.rs`
//! for the soundness argument (every match starts at a required-prefix literal,
//! so anchoring at every AC-reported position finds every whole-chunk match).
use super::scan_filters::looks_like_variable_name;
use super::CompiledScanner;
use crate::types::*;
use keyhog_core::Chunk;
use regex::Regex;
use std::cell::OnceCell;

impl CompiledScanner {
    /// Verify one eligible phase-2 pattern at its candidate anchor positions
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
            crate::telemetry::record_invalid_detector_index_skip();
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
            let (credential, credential_start, credential_end): (&str, usize, usize) = match group {
                Some(group) => {
                    let (mut cs, mut ce) = locs.get(group).unwrap_or((whole.start(), whole.end())); // LAW10: bounds-checked lookup; out-of-range => documented default (total fn), recall-safe
                    let mut cred = &slice[cs..ce];
                    if looks_like_variable_name(cred) && groups_total > 2 {
                        for g in 1..groups_total {
                            if g == group {
                                continue;
                            }
                            if let Some((s, e)) = locs.get(g) {
                                let cand = &slice[s..e];
                                if !looks_like_variable_name(cand) && cand.len() >= 8 {
                                    cs = s;
                                    ce = e;
                                    cred = cand;
                                    break;
                                }
                            }
                        }
                    }
                    (cred, pos + cs, pos + ce)
                }
                None => (&slice[whole.start()..whole.end()], full_start, full_end),
            };

            let &(keyword_nearby, sensitive_file) = signals
                .get_or_init(|| super::scan_filters::compute_pattern_signals(detector, chunk));
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
                credential_start,
                credential_end,
                0,
                0,
                keyword_nearby,
                sensitive_file,
            );
        }
    }
}
