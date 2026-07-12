//! Pre-decoding extraction of encoded values (Base64, Hex, URL, etc.).

/// MEASUREMENT (`keyhog scan --profile`): call count + total bytes + wall time of
/// `extract_encoded_values`, to size the redundant-extraction lever. Folded
/// into the unified scanner profiler so profiling has one env owner.
static EXTRACT_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXTRACT_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXTRACT_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Debug)]
pub(crate) struct ExtractedValue {
    pub(crate) value: String,
    pub(crate) start: Option<usize>,
    pub(crate) end: Option<usize>,
}

impl ExtractedValue {
    pub(crate) fn new(value: String, start: usize, end: usize) -> Self {
        Self {
            value,
            start: Some(start),
            end: Some(end),
        }
    }

    pub(crate) fn synthetic(value: String) -> Self {
        Self {
            value,
            start: None,
            end: None,
        }
    }

    pub(crate) fn span(&self) -> Option<(usize, usize)> {
        Some((self.start?, self.end?))
    }
}
fn extract_prof_enabled() -> bool {
    crate::engine::profile::enabled()
}
pub(crate) fn extract_profile_dump() {
    use std::sync::atomic::Ordering::Relaxed;
    let calls = EXTRACT_CALLS.swap(0, Relaxed);
    let bytes = EXTRACT_BYTES.swap(0, Relaxed);
    let ms = EXTRACT_NS.swap(0, Relaxed) as f64 / 1e6;
    if calls == 0 && bytes == 0 && ms == 0.0 {
        return;
    }
    eprintln!(
        "extract_encoded_values: calls={calls} bytes={bytes} time={ms:.1}ms ({:.2} µs/call)",
        if calls > 0 {
            ms * 1000.0 / calls as f64
        } else {
            0.0
        }
    );
}

pub(crate) fn extract_profile_reset() {
    use std::sync::atomic::Ordering::Relaxed;
    EXTRACT_CALLS.store(0, Relaxed);
    EXTRACT_BYTES.store(0, Relaxed);
    EXTRACT_NS.store(0, Relaxed);
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
pub(super) fn prime_shared_candidates(text: &str) {
    let cands = extract_encoded_value_spans_raw(text);
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

        let cands = extract_encoded_value_spans_raw(text);
        f(&cands)
    })
}

/// Minimum length of a freestanding base64/url-safe alphabet run before it is
/// kept as a decode candidate. A ~16-char run is the shortest that can carry a
/// credential-length payload; shorter alphanumeric runs are ordinary
/// identifiers/words, not encoded secrets. Named so the single `flush_b64` gate
/// has one owner (sibling of [`MIN_EXTRACTED_VALUE_LEN`]).
const MIN_B64_BLOCK_LEN: usize = 16;

fn extract_encoded_value_spans_raw(text: &str) -> Vec<ExtractedValue> {
    // Minimum length for a quoted-string or assignment value to be worth keeping
    // as a decode candidate. Both extraction paths apply the same floor; one
    // owner so they can never drift to different cutoffs.
    const MIN_EXTRACTED_VALUE_LEN: usize = 4;
    let _prof = extract_prof_enabled().then(|| {
        use std::sync::atomic::Ordering::Relaxed;
        EXTRACT_CALLS.fetch_add(1, Relaxed);
        EXTRACT_BYTES.fetch_add(text.len() as u64, Relaxed);
        std::time::Instant::now()
    });
    let _guard = ExtractTimer(_prof);
    struct ExtractTimer(Option<std::time::Instant>);
    impl Drop for ExtractTimer {
        fn drop(&mut self) {
            if let Some(t) = self.0 {
                EXTRACT_NS.fetch_add(
                    t.elapsed().as_nanos() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    }
    let mut values = Vec::new();
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
                            values.push(ExtractedValue::new(cleaned, start, value_end));
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

        // ── Assignment values (key=value / key: value) ──────────────
        if ch == ':' || ch == '=' {
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
            let mut cleaned = String::with_capacity(32);
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
                cleaned.push(c);
                chars.next();
            }
            if cleaned.len() >= MIN_EXTRACTED_VALUE_LEN {
                if let Some(start) = value_start {
                    values.push(ExtractedValue::new(cleaned, start, value_end));
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
        } else if !ch.is_whitespace() {
            flush_b64(&mut values, &mut b64_block, &mut b64_start, b64_end);
        }
        // whitespace inside a b64 block is skipped (line continuations) WITHOUT
        // advancing b64_end: the span must end at the last real base64 char, not
        // past trailing whitespace.

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
