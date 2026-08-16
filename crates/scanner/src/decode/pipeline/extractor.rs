//! Pre-decoding extraction of encoded values (Base64, Hex, URL, etc.).

/// MEASUREMENT: call count + total bytes + wall time of
/// `extract_encoded_values`, to size the redundant-extraction lever. The
/// keyhog-profile runtime owns all three (typed counters; the wall time is a
/// nanosecond sum because extraction nests inside the `Decode` stage span, so
/// a span would double-count the stage total). Counts/bytes record through the
/// runtime gate (a no-op when no runtime is active); the `Instant` is taken
/// only when profiling is on. The unified profiler drains and prints the line
/// via [`format_extract_profile`].

/// Render the extraction profile line the unified profiler prints. Pure (no
/// I/O) so the formatting is unit-testable.
#[cfg(feature = "decode")]
pub(crate) fn format_extract_profile(calls: u64, bytes: u64, ns: u64) -> String {
    let ms = ns as f64 / 1e6;
    format!(
        "extract_encoded_values: calls={calls} bytes={bytes} time={ms:.1}ms ({:.2} µs/call)",
        if calls > 0 {
            ms * 1000.0 / calls as f64
        } else {
            0.0
        }
    )
}

/// Build the extraction figures from one drained typed-metric batch. Missing
/// counters read as zero; the caller prints nothing when all three are zero.
#[cfg(feature = "decode")]
pub(crate) fn extract_profile_from_typed(
    metrics: &[keyhog_profile::TypedMetricRecordV2],
) -> (u64, u64, u64) {
    let value = |counter: keyhog_profile::CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    (
        value(keyhog_profile::CounterId::DecodeExtractCalls),
        value(keyhog_profile::CounterId::DecodeExtractBytes),
        value(keyhog_profile::CounterId::DecodeExtractNs),
    )
}

#[derive(Clone, Debug)]
pub(crate) struct ExtractedValue {
    pub(crate) value: std::sync::Arc<str>,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl ExtractedValue {
    pub(crate) fn new(value: impl Into<std::sync::Arc<str>>, start: usize, end: usize) -> Self {
        Self {
            value: value.into(),
            start,
            end,
        }
    }

    pub(crate) fn span(&self) -> (usize, usize) {
        (self.start, self.end)
    }
}

thread_local! {
    /// Per-BFS-item shared WHOLE-CHUNK candidate cache. `decode_chunk` primes
    /// this once per chunk so the ~5 whole-chunk decoders (base64/hex/url/caesar/
    /// reverse) reuse ONE extraction instead of each recomputing the identical
    /// chunk candidate extraction (it was ~67% of decode-gen, called
    /// 5-6× per chunk on the same input). Keyed by the chunk text's (ptr,len) and
    /// cleared per item, so a per-line call (different ptr) or a later chunk
    /// (different ptr) never reads a stale result.
    static SHARED_CANDIDATES: std::cell::RefCell<Option<(usize, usize, Vec<ExtractedValue>)>> =
        const { std::cell::RefCell::new(None) };
}

/// Pre-compute and cache the whole-chunk extraction for reuse by this BFS item's
/// decoders. Call once per item before the decoder loop; pair with
/// [`clear_shared_candidates`] after.
pub(super) fn prime_shared_candidates(text: &str, prune_default_impossible: bool) {
    let cands = extract_encoded_value_spans_raw(text, prune_default_impossible);
    SHARED_CANDIDATES.with(|c| {
        *c.borrow_mut() = Some((text.as_ptr() as usize, text.len(), cands));
    });
}

/// Drop the primed cache so it can never be read for a different chunk.
pub(super) fn clear_shared_candidates() {
    SHARED_CANDIDATES.with(|c| *c.borrow_mut() = None);
}

pub(crate) fn with_extracted_value_spans<R>(
    text: &str,
    f: impl FnOnce(&[ExtractedValue]) -> R,
) -> R {
    SHARED_CANDIDATES.with(|c| {
        let borrowed = c.borrow();
        if let Some((_, _, cands)) = borrowed
            .as_ref()
            .filter(|(ptr, len, _)| *ptr == text.as_ptr() as usize && *len == text.len())
        {
            return f(cands);
        }
        drop(borrowed);

        let cands = extract_encoded_value_spans_raw(text, false);
        f(&cands)
    })
}

/// Minimum length of a freestanding base64/url-safe alphabet run before it is
/// kept as a decode candidate. A ~16-char run is the shortest that can carry a
/// credential-length payload; shorter alphanumeric runs are ordinary
/// identifiers/words, not encoded secrets. Named so the single `flush_b64` gate
/// has one owner (sibling of [`MIN_EXTRACTED_VALUE_LEN`]).
const MIN_B64_BLOCK_LEN: usize = 16;

fn extract_encoded_value_spans_raw(
    text: &str,
    prune_default_impossible: bool,
) -> Vec<ExtractedValue> {
    // Minimum length for a quoted-string or assignment value to be worth keeping
    // as a decode candidate. Both extraction paths apply the same floor; one
    // owner so they can never drift to different cutoffs.
    const MIN_EXTRACTED_VALUE_LEN: usize = 4;
    keyhog_profile::add_counter(keyhog_profile::CounterId::DecodeExtractCalls, 1);
    keyhog_profile::add_counter(
        keyhog_profile::CounterId::DecodeExtractBytes,
        text.len() as u64,
    );
    let _extract = keyhog_profile::counter_span(keyhog_profile::CounterId::DecodeExtractNs);
    let mut values = Vec::new();
    // Intern repeated candidate payloads within this extraction. Long single-line
    // JSON often repeats the same opaque token tens of thousands of times; each
    // occurrence still needs its own span, but sharing the `Arc<str>` avoids
    // allocating a fresh String per hit and makes later per-value decode memos
    // hit with pointer-cheap clones.
    let mut value_intern: std::collections::HashMap<u64, std::sync::Arc<str>> =
        std::collections::HashMap::new();
    let mut intern_value = |raw: &str| -> std::sync::Arc<str> {
        let key = hash_fast(raw.as_bytes());
        if let Some(existing) = value_intern.get(&key) {
            if existing.as_ref() == raw {
                return std::sync::Arc::clone(existing);
            }
        }
        let owned: std::sync::Arc<str> = std::sync::Arc::from(raw);
        value_intern.insert(key, std::sync::Arc::clone(&owned));
        owned
    };
    // Base64 block accumulator - collected in the SAME pass as quoted/assigned values.
    let mut b64_block = String::new();
    let mut b64_start: Option<usize> = None;
    let mut b64_end = 0usize;
    // Percent-encoded run accumulator - picks up freestanding `%41%57…`
    // blobs that don't sit immediately after `=`/`:` (e.g.
    // `Authorization: Bearer %41%57…` where the b64 accumulator
    // breaks on `%` and the assignment-value extractor stops at the
    // first whitespace after `Bearer`). Without this the url-percent
    // decode-through path lost ~25% of contract positives whose
    // credential lived past a non-trivial prefix word. Tracked by
    // `encoding_explosion_runner` url-percent floor.
    let mut pct_block = String::new();
    let mut pct_start: Option<usize> = None;
    let mut pct_end = 0usize;
    // Running count of '%' pushed into `pct_block`, maintained incrementally so
    // `flush_pct` reads it instead of rescanning the whole accumulated run.
    let mut pct_percent_count = 0usize;

    let is_b64_char =
        |ch: char| -> bool { ch.is_ascii() && crate::decode::is_base64_candidate_byte(ch as u8) };
    // Members of a percent-run AFTER the leading `%`: hex digits + the
    // `%` itself (which restarts a fresh triplet). Anything else
    // terminates the run.
    let is_pct_run_char = |ch: char| -> bool { ch == '%' || ch.is_ascii_hexdigit() };

    // Flush a pending base64 block: push it as a candidate only if it reached at
    // least MIN_B64_BLOCK_LEN chars (a credential-length run), otherwise discard it. Shorter
    // alphanumeric runs are ordinary identifiers/words, not encoded secrets.
    fn flush_b64(
        values: &mut Vec<ExtractedValue>,
        b64_block: &mut String,
        b64_start: &mut Option<usize>,
        b64_end: usize,
    ) {
        if b64_block.len() >= MIN_B64_BLOCK_LEN {
            if let Some(start) = b64_start.take() {
                values.push(ExtractedValue::new(
                    std::mem::take(b64_block),
                    start,
                    b64_end,
                ));
            } else {
                b64_block.clear();
            }
        } else {
            b64_block.clear();
            *b64_start = None;
        }
    }

    fn push_b64_subruns(
        values: &mut Vec<ExtractedValue>,
        text: &str,
        container_start: usize,
        container_end: usize,
        intern: &mut impl FnMut(&str) -> std::sync::Arc<str>,
    ) {
        let container = &text[container_start..container_end];
        if container.starts_with("=?") && container.ends_with("?=") {
            return;
        }

        let mut run_start = None;
        for (relative_index, byte) in text.as_bytes()[container_start..container_end]
            .iter()
            .copied()
            .enumerate()
        {
            let index = container_start + relative_index;
            if crate::decode::is_base64_candidate_byte(byte) {
                run_start.get_or_insert(index);
                continue;
            }
            if let Some(start) = run_start.take() {
                if index.saturating_sub(start) >= MIN_B64_BLOCK_LEN
                    && (start != container_start || index != container_end)
                {
                    values.push(ExtractedValue::new(
                        intern(&text[start..index]),
                        start,
                        index,
                    ));
                }
            }
        }
        if let Some(start) = run_start {
            if container_end.saturating_sub(start) >= MIN_B64_BLOCK_LEN && start != container_start
            {
                values.push(ExtractedValue::new(
                    intern(&text[start..container_end]),
                    start,
                    container_end,
                ));
            }
        }
    }

    fn flush_pct(
        values: &mut Vec<ExtractedValue>,
        pct_block: &mut String,
        pct_start: &mut Option<usize>,
        pct_end: usize,
        pct_percent_count: &mut usize,
    ) {
        // One triplet (3 chars, e.g. `%41`) is the floor: short percent-encoded
        // dev IDs and other compact secrets that `encoding_explosion_runner`
        // percent-encodes wholesale can be a single triplet, so accept a run of
        // at least one `%`-triplet rather than gating freestanding runs higher.
        const MIN_PCT_TRIPLETS: usize = 1;
        if pct_block.len() >= MIN_PCT_TRIPLETS * 3 && *pct_percent_count >= MIN_PCT_TRIPLETS {
            if let Some(start) = pct_start.take() {
                values.push(ExtractedValue::new(
                    std::mem::take(pct_block),
                    start,
                    pct_end,
                ));
            } else {
                pct_block.clear();
            }
        } else {
            pct_block.clear();
            *pct_start = None;
        }
        // `pct_block` is empty after every flush path, so the running count resets.
        *pct_percent_count = 0;
    }

    // Single-pass char-level iteration. Safe for UTF-8 (no mid-codepoint splits).
    let mut chars = text.char_indices().peekable();
    while let Some(&(idx, ch)) = chars.peek() {
        // ── Quoted strings ──────────────────────────────────────────
        if ch == '"' || ch == '\'' || ch == '`' {
            // Flush any pending b64 block
            flush_b64(&mut values, &mut b64_block, &mut b64_start, b64_end);
            flush_pct(
                &mut values,
                &mut pct_block,
                &mut pct_start,
                pct_end,
                &mut pct_percent_count,
            );

            let quote = ch;
            chars.next();
            let mut escaping = false;
            let mut cleaned = String::with_capacity(32);
            let mut value_start: Option<usize> = None;
            let mut value_end = idx + ch.len_utf8();

            while let Some(&(current_idx, current)) = chars.peek() {
                chars.next();
                if escaping {
                    value_start.get_or_insert(current_idx.saturating_sub(1));
                    value_end = current_idx + current.len_utf8();
                    cleaned.push('\\');
                    cleaned.push(current);
                    escaping = false;
                } else if current == '\\' {
                    value_start.get_or_insert(current_idx);
                    value_end = current_idx + current.len_utf8();
                    escaping = true;
                } else if current == quote {
                    if cleaned.len() >= MIN_EXTRACTED_VALUE_LEN {
                        if let Some(start) = value_start {
                            push_b64_subruns(
                                &mut values,
                                text,
                                start,
                                value_end,
                                &mut intern_value,
                            );
                            values.push(ExtractedValue::new(
                                intern_value(&cleaned),
                                start,
                                value_end,
                            ));
                        }
                    }
                    break;
                } else if !current.is_ascii_whitespace() {
                    value_start.get_or_insert(current_idx);
                    value_end = current_idx + current.len_utf8();
                    cleaned.push(current);
                }
            }
            continue;
        }

        // An `=` after a credential-length alphabet run may be base64 padding,
        // not an assignment delimiter. Admit only the two legal terminal
        // shapes (`xx==` or `xxx=`); ordinary `key=value` still takes the
        // assignment branch.
        let equals_is_base64_padding = ch == '='
            && b64_block.len() >= MIN_B64_BLOCK_LEN
            && match text.as_bytes().get(idx + 1).copied() {
                Some(b'=') => b64_block.len() % 4 == 2,
                None => b64_block.len() % 4 == 3,
                Some(next) if !crate::decode::is_base64_candidate_byte(next) => {
                    b64_block.len() % 4 == 3
                }
                Some(_) => false,
            };
        if equals_is_base64_padding {
            b64_end = idx + ch.len_utf8();
            b64_block.push(ch);
            chars.next();
            continue;
        }

        // ── Assignment values (key=value / key: value) ──────────────
        if (ch == ':' || ch == '=') && !equals_is_base64_padding {
            flush_b64(&mut values, &mut b64_block, &mut b64_start, b64_end);
            flush_pct(
                &mut values,
                &mut pct_block,
                &mut pct_start,
                pct_end,
                &mut pct_percent_count,
            );

            chars.next();
            // Skip whitespace after delimiter
            while chars.peek().is_some_and(|&(_, c)| c.is_ascii_whitespace()) {
                chars.next();
            }
            let mut value_start: Option<usize> = None;
            let mut value_end = idx + ch.len_utf8();
            while let Some(&(current_idx, c)) = chars.peek() {
                if c.is_ascii_whitespace()
                    || c == ';'
                    || c == ','
                    || c == '"'
                    || c == '\''
                    || c == '`'
                {
                    break;
                }
                value_start.get_or_insert(current_idx);
                value_end = current_idx + c.len_utf8();
                chars.next();
            }
            if let Some(start) = value_start {
                let value = &text[start..value_end];
                let default_impossible = prune_default_impossible
                    && value.len() < super::super::limits::MIN_BASE64_CANDIDATE_LEN
                    && value.bytes().all(|byte| byte.is_ascii_alphanumeric());
                if value.len() >= MIN_EXTRACTED_VALUE_LEN && !default_impossible {
                    push_b64_subruns(&mut values, text, start, value_end, &mut intern_value);
                    values.push(ExtractedValue::new(intern_value(value), start, value_end));
                }
            }
            continue;
        }

        // ── Percent-run accumulation ────────────────────────────────
        // Percent starts a new triplet. Hex digits extend it. Anything
        // else terminates the run; a sufficiently long run is pushed
        // as its own candidate so the url_decode pass picks it up
        // regardless of whether it sat after `=`/`:` or inside quotes.
        if is_pct_run_char(ch) {
            // A run can only LEGITIMATELY start with '%'. If we see a
            // bare hex digit and the block is empty, ignore it (it's
            // ordinary text, not the leading byte of a percent run).
            if pct_block.is_empty() && ch != '%' {
                // fallthrough to b64 accumulator below
            } else {
                pct_start.get_or_insert(idx);
                pct_end = idx + ch.len_utf8();
                if ch == '%' {
                    pct_percent_count += 1;
                }
                pct_block.push(ch);
                // Don't fall into the b64 accumulator branch on the
                // same char; `%` and the hex digits are still valid
                // base64 chars only for the alphanumerics, and we
                // don't want a `%41%57` blob to ALSO accumulate as a
                // base64 candidate (`4157`) - which would generate
                // spurious decode candidates downstream.
                chars.next();
                continue;
            }
        } else if !pct_block.is_empty() {
            flush_pct(
                &mut values,
                &mut pct_block,
                &mut pct_start,
                pct_end,
                &mut pct_percent_count,
            );
        }

        // ── Base64 block accumulation (merged from old second pass) ─
        if is_b64_char(ch) {
            b64_start.get_or_insert(idx);
            b64_end = idx + ch.len_utf8();
            b64_block.push(ch);
        } else if matches!(ch, '\r' | '\n') {
            // A padded candidate is complete by definition; the physical
            // newline belongs to the surrounding document, not the blob.
            if b64_block.ends_with('=') {
                flush_b64(&mut values, &mut b64_block, &mut b64_start, b64_end);
            }
        } else {
            flush_b64(&mut values, &mut b64_block, &mut b64_start, b64_end);
        }
        // Unpadded physical line wraps may split one base64 blob. Horizontal
        // whitespace separates ordinary tokens and terminates the candidate.

        chars.next();
    }

    // Flush trailing b64 block
    flush_b64(&mut values, &mut b64_block, &mut b64_start, b64_end);
    flush_pct(
        &mut values,
        &mut pct_block,
        &mut pct_start,
        pct_end,
        &mut pct_percent_count,
    );

    values
}

/// Fast non-cryptographic hash for dedup, re-exported from the crate-canonical
/// FNV-1a in [`crate::util_hash`]. The loop body used to live here (and was
/// copy-pasted into entropy/ml_scorer/decode_structure); it now has a single
/// home so a seed/prime change can never silently re-key only some caches.
/// Keep this re-export so `decode::pipeline` callers that import
/// `extractor::hash_fast` stay unchanged.
pub(crate) use crate::util_hash::hash_fast;
