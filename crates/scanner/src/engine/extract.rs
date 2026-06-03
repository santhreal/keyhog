//! Pattern-level extraction loops.
//!
//! Extracted from `scan.rs` to keep individual files under the 500-line
//! cap. Houses the four entry points the scanner uses to walk each
//! triggered pattern's regex over the prepared chunk:
//!
//! * `extract_matches` - public wrapper preserving the legacy
//!   no-cursor-range call shape.
//! * `extract_matches_inner` - dispatches between grouped and plain.
//! * `extract_grouped_matches` - patterns with a capture-group target.
//! * `extract_plain_matches` - patterns with no capture group.
//!
//! Both inner loops call `process_match` (in `engine/process.rs`) for
//! every surviving candidate. Their shared per-pattern signal cache
//! is built from `super::scan::compute_pattern_signals`.

use super::scan_filters::*;
use super::CompiledScanner;
use crate::types::*;
use keyhog_core::{Chunk, DetectorSpec};

impl CompiledScanner {
    pub(crate) fn extract_matches(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
        // Per-pattern deadline. Inner regex loops can produce many
        // matches on adversarial inputs (false_prefix_storm); without
        // a deadline-check inside those loops, --timeout is a lie for
        // those chunks. Threaded down to the inner loops below.
        deadline: Option<std::time::Instant>,
    ) {
        self.extract_matches_inner(
            entry,
            preprocessed,
            line_offsets,
            code_lines,
            documentation_lines,
            chunk,
            scan_state,
            base_line,
            base_offset,
            None,
            deadline,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn extract_matches_inner(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
        cursor_range: Option<(usize, usize)>,
        deadline: Option<std::time::Instant>,
    ) {
        // Resilient lookup: a malformed `entry.detector_index` would otherwise
        // panic mid-scan and abort the whole rayon worker. The compiler should
        // never produce out-of-range indices, but this is the kind of
        // invariant whose violation should degrade one finding gracefully
        // rather than crash an entire repository scan.
        let Some(detector) = self.detectors.get(entry.detector_index) else {
            tracing::warn!(
                detector_index = entry.detector_index,
                detectors_len = self.detectors.len(),
                "extract_matches: detector_index out of range; skipping pattern"
            );
            return;
        };

        if let Some(group) = entry.group {
            self.extract_grouped_matches(
                entry,
                detector,
                group,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                base_line,
                base_offset,
                cursor_range,
                deadline,
            );
            return;
        }
        self.extract_plain_matches(
            entry,
            detector,
            preprocessed,
            line_offsets,
            code_lines,
            documentation_lines,
            chunk,
            scan_state,
            base_line,
            base_offset,
            cursor_range,
            deadline,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_grouped_matches(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        group: usize,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
        cursor_range: Option<(usize, usize)>,
        deadline: Option<std::time::Instant>,
    ) {
        let search_text = &preprocessed.text;
        // Lazy per-pattern dedup of two signals that are constant
        // across this pattern's matches but expensive to compute:
        //   `keyword_nearby` = `O(K x |chunk|)` substring scans.
        //   `sensitive_file` = Aho-Corasick scan over the file path.
        // Computing eagerly at `extract_matches` level regressed the
        // entropy_noise bench by -36% because many patterns trigger via
        // AC but produce zero matches, paying for compute they
        // never use. The OnceCell here keeps: zero-match patterns
        // pay nothing; first-match populates; subsequent matches
        // reuse the cached value.
        let signals = std::cell::OnceCell::<(bool, bool)>::new();
        // Reuse one CaptureLocations buffer across every iter tick instead of
        // allocating a fresh `Captures` per match. For a 100k-file scan
        // hitting 10k matches across a handful of hot patterns, that's tens
        // of thousands of avoided allocations per scan.
        // Compile-on-first-use: this pattern's regex is built here the first
        // time it is actually needed (see LazyRegex), then cached. Bind once
        // so the inner match loop reuses the same `&Regex`.
        let rx = entry.regex.get();
        let mut locs = rx.capture_locations();
        let groups_total = locs.len();
        let bytes_total = search_text.len();
        // GPU-anchored path: caller restricts the scan to a small
        // window around a literal hit. `cursor_end` is the upper
        // bound for match *starts*: a regex match whose start lies
        // past `cursor_end` is treated as "no match" for window
        // termination. We still let a match *end* past `cursor_end`
        // because credentials are typically longer than the literal
        // prefix that anchored them.
        let (mut cursor, cursor_end) = match cursor_range {
            Some((start, end)) => (start.min(bytes_total), end.min(bytes_total)),
            None => (0usize, bytes_total),
        };
        while cursor < cursor_end && cursor > 0 && !search_text.is_char_boundary(cursor) {
            cursor -= 1;
        }
        // Inner-loop deadline check counter. Same `is_multiple_of(64)`
        // cadence as `scan_fallback_patterns`: frequent enough that
        // a hung pattern aborts within a few ms, infrequent enough
        // that the `Instant::now()` syscall isn't a hot-path tax.
        // Without this, a single regex producing 100k+ matches on an
        // adversarial chunk (false_prefix_storm, regex catastrophic
        // backtracking) would run unboundedly even with --timeout.
        //
        // kimi-engine audit: when deadline is None (--timeout unset)
        // the above guard never fires and a regex matching every byte
        // on a 64 MiB chunk would loop ~64M times. The deadline path
        // is the operator's defense; this hard cap is the per-pattern
        // budget. 1M iterations per pattern is ~6 orders of magnitude
        // above any legitimate detector's per-chunk match count.
        const MAX_INNER_LOOP_ITERS: usize = 1_000_000;
        let mut match_count: usize = 0;
        while cursor <= cursor_end {
            if match_count >= MAX_INNER_LOOP_ITERS {
                break;
            }
            if let Some(deadline) = deadline {
                if match_count.is_multiple_of(64)
                    && match_count > 0
                    && std::time::Instant::now() >= deadline
                {
                    break;
                }
            }
            match_count += 1;
            let Some(whole) = rx.captures_read_at(&mut locs, search_text, cursor) else {
                break;
            };
            let full_start = whole.start();
            let full_end = whole.end();
            // Anchored-window termination: a regex match whose
            // *start* is past the caller's window means we've walked
            // off the literal hit that brought us here. Stop instead
            // of paying for the full-chunk scan we were trying to
            // avoid.
            if full_start > cursor_end {
                break;
            }
            // Advance the cursor up front so any `continue` below keeps the
            // loop progressing. Zero-width matches bump by one byte (and
            // align onto a UTF-8 boundary) to avoid an infinite loop.
            let mut next = if full_end == cursor {
                full_end + 1
            } else {
                full_end
            };
            while next < bytes_total && !search_text.is_char_boundary(next) {
                next += 1;
            }
            cursor = next;

            // Skip zero-width matches without surfacing them. The previous
            // `captures_iter`-based implementation never emitted these (its
            // internal iter advanced past them silently) so any downstream
            // logic (entropy, ML scoring, dedup) was never asked to grade
            // an empty credential. Replicating that semantics avoids a
            // behavior change disguised as a perf optimization.
            if full_end == full_start {
                continue;
            }

            // Resolve the configured capture group, falling back to the full
            // match when the group didn't participate (e.g. a top-level
            // alternation where one branch lacks the inner group).
            let credential_range = locs.get(group).unwrap_or((full_start, full_end));
            let mut credential = &search_text[credential_range.0..credential_range.1];

            // Variable-name heuristic: if the captured group looks like a
            // variable name rather than a secret, scan the other groups for
            // a value-shaped candidate. Same semantics as before, just
            // reading from CaptureLocations directly.
            if looks_like_variable_name(credential) && groups_total > 2 {
                for g in 1..groups_total {
                    if g == group {
                        continue;
                    }
                    if let Some((s, e)) = locs.get(g) {
                        let candidate_str = &search_text[s..e];
                        if !looks_like_variable_name(candidate_str) && candidate_str.len() >= 8 {
                            credential = candidate_str;
                            break;
                        }
                    }
                }
            }

            let &(keyword_nearby, sensitive_file) =
                signals.get_or_init(|| super::scan::compute_pattern_signals(detector, chunk));
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
                base_line,
                base_offset,
                keyword_nearby,
                sensitive_file,
            );
        }
    }

    #[allow(clippy::too_many_arguments, clippy::explicit_counter_loop)]
    fn extract_plain_matches(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
        cursor_range: Option<(usize, usize)>,
        deadline: Option<std::time::Instant>,
    ) {
        let search_text = &preprocessed.text;
        // Same lazy-on-first-match dedup as `extract_grouped_matches`;
        // see that function's doc-comment for the rationale.
        let signals = std::cell::OnceCell::<(bool, bool)>::new();
        let bytes_total = search_text.len();
        // GPU-anchored path: same contract as `extract_grouped_matches`.
        // None = legacy whole-text scan. Some((start, end)) = run
        // anchored at `start`, stop once a match starts past `end`.
        let (range_start, range_end) = match cursor_range {
            Some((start, end)) => (start.min(bytes_total), end.min(bytes_total)),
            None => (0usize, bytes_total),
        };
        // Inner-loop deadline counter: same `is_multiple_of(64)`
        // cadence as the grouped path so --timeout aborts cleanly
        // even on patterns that fire 100k+ matches per chunk.
        // `match_count` is named for readability (it represents an
        // iteration index used for deadline gating, not a generic
        // enumerator); the function-level `clippy::explicit_counter_loop`
        // allow keeps that clearer naming.
        //
        // kimi-engine audit: same hard cap as `extract_grouped_matches`.
        // When deadline is None the previous logic had no bound: a
        // pattern matching every byte on a 64 MiB chunk looped ~64M
        // times. 1M iterations per pattern is a generous floor still
        // 6 orders of magnitude above any legitimate detector count.
        const MAX_INNER_LOOP_ITERS: usize = 1_000_000;
        let mut match_count: usize = 0;
        // `find_iter` doesn't take a start position; walk it manually
        // via `find_at` so the anchored-window path stays cheap. The
        // legacy path (range_start=0, range_end=bytes_total) behaves
        // identically to the prior `find_iter` loop.
        let mut cursor = range_start;
        // Compile-on-first-use (see LazyRegex); bind once for the walk.
        let rx = entry.regex.get();
        while cursor <= range_end {
            if match_count >= MAX_INNER_LOOP_ITERS {
                break;
            }
            if let Some(deadline) = deadline {
                if match_count.is_multiple_of(64)
                    && match_count > 0
                    && std::time::Instant::now() >= deadline
                {
                    break;
                }
            }
            let Some(matched) = rx.find_at(search_text, cursor) else {
                break;
            };
            if matched.start() > range_end {
                break;
            }
            // Advance cursor before any early-continue so zero-width
            // matches don't loop forever.
            let mut next = if matched.end() == cursor {
                matched.end() + 1
            } else {
                matched.end()
            };
            while next < bytes_total && !search_text.is_char_boundary(next) {
                next += 1;
            }
            cursor = next;
            match_count += 1;
            // Skip zero-width matches without surfacing them: same
            // semantics as `extract_grouped_matches` (see the longer
            // comment there). Without this guard, a regex whose
            // outermost shape matches zero bytes (lookahead-only,
            // empty alternation branch) emits an empty-credential
            // finding on every iteration; downstream scoring would
            // then be asked to grade `""`.
            if matched.end() == matched.start() {
                continue;
            }
            let &(keyword_nearby, sensitive_file) =
                signals.get_or_init(|| super::scan::compute_pattern_signals(detector, chunk));
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
                matched.as_str(),
                matched.start(),
                matched.end(),
                base_line,
                base_offset,
                keyword_nearby,
                sensitive_file,
            );
        }
    }
}
