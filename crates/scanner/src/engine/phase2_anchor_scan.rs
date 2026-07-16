//! Anchored-position verification for the shared-anchor phase-2 localizer.
//!
//! Split out of `phase2_anchor.rs` (Law 5, 500-LOC ceiling). That file owns
//! the `Phase2AnchorIndex` build + candidate-collection machinery; this is the
//! consumer side: `CompiledScanner::extract_anchored` replays the whole-chunk
//! `find_iter` walk for ONE eligible pattern at its candidate anchor positions,
//! emitting byte-identical matches via `process_match`. See `phase2_anchor.rs`
//! for the soundness argument (every match starts at a required-prefix literal,
//! so anchoring at every AC-reported position finds every whole-chunk match).
use super::CompiledScanner;
use crate::anchored_regex::AnchoredRegex;
use crate::types::*;
use keyhog_core::Chunk;
use std::cell::OnceCell;

impl CompiledScanner {
    /// Verify one eligible phase-2 pattern at its candidate anchor positions
    /// using the `\A`-anchored regex, emitting matches via `process_match`.
    ///
    /// This reproduces the whole-chunk `find_iter` walk EXACTLY, non
    /// -overlapping, leftmost, zero-width-skipping, so the produced match set
    /// is byte-identical to `extract_matches` on the same pattern:
    ///   * `positions` are this pattern's candidate starts (sorted, ascending);
    ///     every real match starts at one of them (the anchor is required).
    ///   * `next_allowed` mirrors the whole-chunk cursor: after a match `[s,e)`
    ///     the next search resumes at `e` (or `s+1` for a zero-width match), so
    ///     candidate positions that fall inside an already-consumed match are
    ///     skipped (exactly as the cursor-advance loop skips them).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn extract_anchored(
        &self,
        entry: &CompiledPattern,
        anchored_re: &AnchoredRegex,
        positions: &[(u32, u32)],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        let execution_policy = self.detector_execution_policies.get(entry.detector_index);
        let search_text: &str = &preprocessed.text;
        let bytes_total = search_text.len();
        // Per-pattern signal cache: constant across this pattern's matches but
        // expensive (O(K x |chunk|) keyword scan + path AC). Computed at most
        // once, on the first surviving match (same contract as extract.rs).
        let signals = OnceCell::<(bool, bool)>::new();
        // Fail closed in the LazyLock init (see `AnchoredRegex::compile`): a build
        // failure of the anchored verifier PANICS rather than returning `None`, so
        // `get()` here can never silently drop this pattern's matches (Law 10). The
        // former `let Some(..) else { return }` was the recall-losing swallow this
        // sweep removed, a build bug now aborts loudly instead of degrading recall
        // invisibly on the anchored fast path (which has no whole-chunk fallback).
        let no_context_re = anchored_re.get();
        let mut no_context_locs = no_context_re.capture_locations();
        // Compile the left-context variant only when some candidate position is > 0
        // and therefore actually needs the synthetic preceding character; otherwise
        // it is never consulted. `None` here means "not needed", NOT a swallowed
        // compile failure (that path panics in the init above).
        let left_context_re = if positions.iter().any(|&(_, pos)| pos > 0) {
            Some(anchored_re.get_with_left_context())
        } else {
            None
        };
        let mut left_context_locs = left_context_re.map(|re| re.capture_locations());
        let group = entry.group;
        // Mirror the whole-chunk cursor: next match must start at-or-after this.
        let mut next_allowed: usize = 0;
        // Same per-pattern hard cap + deadline cadence as extract.rs's inner
        // loops so an adversarial chunk can't run unbounded under the anchored
        // path either. Canonical cap lives in `engine::MAX_INNER_LOOP_ITERS`.
        use super::MAX_INNER_LOOP_ITERS;
        let loop_deadline = crate::deadline::LoopDeadline::from_deadline(deadline);
        let mut iters: usize = 0;
        for &(_, pos) in positions {
            let pos = pos as usize;
            if pos < next_allowed {
                continue;
            }
            if iters >= MAX_INNER_LOOP_ITERS {
                break;
            }
            if crate::deadline::loop_expired_on_cadence(
                loop_deadline,
                iters,
                crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
            ) {
                break;
            }
            iters += 1;
            if pos > bytes_total || !search_text.is_char_boundary(pos) {
                continue;
            }
            let context_start = if pos == 0 {
                0
            } else {
                super::floor_char_boundary(search_text, pos.saturating_sub(1))
            };
            let left_context_len = pos - context_start;
            let use_left_context = left_context_len > 0;
            let (re, locs) = if use_left_context {
                let Some(re) = left_context_re else {
                    continue;
                };
                let Some(locs) = left_context_locs.as_mut() else {
                    continue;
                };
                (re, locs)
            } else {
                (no_context_re, &mut no_context_locs)
            };
            let slice = &search_text[context_start..];
            let Some(whole) = re.captures_read(locs, slice) else {
                continue;
            };
            // `\A` guarantees a hit starts at slice offset 0. For non-zero
            // candidate positions the anchored regex consumes exactly one real
            // preceding character before the detector pattern, so left-boundary
            // constructs (`\b`, multiline `^`, etc.) see the same context as a
            // whole-chunk regex walk instead of a fabricated haystack start.
            if whole.start() != 0 {
                continue;
            }
            let full_start = pos;
            let full_end = context_start + whole.end();
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
                    let groups_total = locs.len();
                    let (mut cs, mut ce) = match locs.get(group) {
                        Some(range) => range,
                        None => (left_context_len, whole.end()),
                    };
                    // Group 0 belongs to the detector regex, not the synthetic
                    // left-context byte that lets boundary assertions see the
                    // real preceding character.
                    if use_left_context && group == 0 {
                        cs = left_context_len;
                    }
                    // Shared with `extract_grouped_matches`: a variable-name
                    // group falls back to a value-shaped sibling group.
                    (cs, ce) = super::scan_filters::resolve_value_shaped_group(
                        locs,
                        slice,
                        group,
                        groups_total,
                        (cs, ce),
                    );
                    let cred = &slice[cs..ce];
                    (cred, context_start + cs, context_start + ce)
                }
                None => (&slice[left_context_len..whole.end()], full_start, full_end),
            };

            let &(keyword_nearby, sensitive_file) = signals.get_or_init(|| {
                super::scan_filters::compute_pattern_signals(
                    entry,
                    execution_policy,
                    chunk,
                    preprocessed,
                )
            });
            self.process_match(
                entry,
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
                keyword_nearby,
                sensitive_file,
            );
            if crate::deadline::loop_expired(loop_deadline) {
                break;
            }
        }
    }
}
