//! Pre-decoding extraction of encoded values (Base64, Hex, URL, etc.).

/// MEASUREMENT (env `KEYHOG_PROFILE_EXTRACT=1`): call count + total bytes + wall
/// time of `extract_encoded_values`, to size the redundant-extraction lever
/// (it's called ~5-6× per chunk on identical input by base64/hex/url/caesar/
/// reverse). `extract_profile_dump()` prints + resets. Zero-cost unset.
static EXTRACT_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXTRACT_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static EXTRACT_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn extract_prof_enabled() -> bool {
    static EN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *EN.get_or_init(|| std::env::var("KEYHOG_PROFILE_EXTRACT").as_deref() == Ok("1"))
}
pub fn extract_profile_dump() {
    use std::sync::atomic::Ordering::Relaxed;
    let calls = EXTRACT_CALLS.swap(0, Relaxed);
    let bytes = EXTRACT_BYTES.swap(0, Relaxed);
    let ms = EXTRACT_NS.swap(0, Relaxed) as f64 / 1e6;
    eprintln!(
        "extract_encoded_values: calls={calls} bytes={bytes} time={ms:.1}ms ({:.2} µs/call)",
        if calls > 0 {
            ms * 1000.0 / calls as f64
        } else {
            0.0
        }
    );
}

thread_local! {
    /// Per-BFS-item shared WHOLE-CHUNK candidate cache. `decode_chunk` primes
    /// this once per chunk so the ~5 whole-chunk decoders (base64/hex/url/caesar/
    /// reverse) reuse ONE extraction instead of each recomputing the identical
    /// `extract_encoded_values(&chunk.data)` (it was ~67% of decode-gen, called
    /// 5-6× per chunk on the same input). Keyed by the chunk text's (ptr,len) and
    /// cleared per item, so a per-line call (different ptr) or a later chunk
    /// (different ptr) never reads a stale result.
    static SHARED_CANDIDATES: std::cell::RefCell<Option<(usize, usize, Vec<String>)>> =
        const { std::cell::RefCell::new(None) };
}

/// Pre-compute and cache the whole-chunk extraction for reuse by this BFS item's
/// decoders. Call once per item before the decoder loop; pair with
/// [`clear_shared_candidates`] after.
pub(super) fn prime_shared_candidates(text: &str) {
    let cands = extract_encoded_values_raw(text);
    SHARED_CANDIDATES.with(|c| {
        *c.borrow_mut() = Some((text.as_ptr() as usize, text.len(), cands));
    });
}

/// Drop the primed cache so it can never be read for a different chunk.
pub(super) fn clear_shared_candidates() {
    SHARED_CANDIDATES.with(|c| *c.borrow_mut() = None);
}

/// Extract candidates for decoding (freestanding Base64, quotes, delimited
/// key/values, percent runs). Returns the pipeline-primed whole-chunk result
/// when called for that same text (same ptr+len); per-line / different-chunk
/// calls compute fresh. The result is identical either way (pure function), so
/// sharing is recall-preserving.
pub(crate) fn extract_encoded_values(text: &str) -> Vec<String> {
    let hit = SHARED_CANDIDATES.with(|c| {
        c.borrow().as_ref().and_then(|(ptr, len, cands)| {
            (*ptr == text.as_ptr() as usize && *len == text.len()).then(|| cands.clone())
        })
    });
    hit.unwrap_or_else(|| extract_encoded_values_raw(text))
}

fn extract_encoded_values_raw(text: &str) -> Vec<String> {
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
    // Percent-encoded run accumulator - picks up freestanding `%41%57…`
    // blobs that don't sit immediately after `=`/`:` (e.g.
    // `Authorization: Bearer %41%57…` where the b64 accumulator
    // breaks on `%` and the assignment-value extractor stops at the
    // first whitespace after `Bearer`). Without this the url-percent
    // decode-through path lost ~25% of contract positives whose
    // credential lived past a non-trivial prefix word. Tracked by
    // `encoding_explosion_runner` url-percent floor.
    let mut pct_block = String::new();

    let is_b64_char = |ch: char| -> bool {
        ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
    };
    // Members of a percent-run AFTER the leading `%`: hex digits + the
    // `%` itself (which restarts a fresh triplet). Anything else
    // terminates the run.
    let is_pct_run_char = |ch: char| -> bool { ch == '%' || ch.is_ascii_hexdigit() };

    // Flush a pending percent run if it covers at least 2 triplets
    // (6 chars). Shorter runs are usually printf/URL noise; 2 triplets
    // is enough for compact percent-encoded dev IDs in contracts.
    fn flush_pct(values: &mut Vec<String>, pct_block: &mut String) {
        // Two triplets (6 decoded bytes) covers short numeric dev IDs and
        // other compact secrets that `encoding_explosion_runner` percent-
        // encodes wholesale. Three triplets remains the default bar for
        // freestanding runs to keep `%2F`-style URL noise out.
        const MIN_PCT_TRIPLETS: usize = 1;
        if pct_block.len() >= MIN_PCT_TRIPLETS * 3
            && pct_block.matches('%').count() >= MIN_PCT_TRIPLETS
        {
            values.push(std::mem::take(pct_block));
        }
        pct_block.clear();
    }

    // Single-pass char-level iteration. Safe for UTF-8 (no mid-codepoint splits).
    let mut chars = text.char_indices().peekable();
    while let Some(&(_, ch)) = chars.peek() {
        // ── Quoted strings ──────────────────────────────────────────
        if ch == '"' || ch == '\'' || ch == '`' {
            // Flush any pending b64 block
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
            flush_pct(&mut values, &mut pct_block);

            let quote = ch;
            chars.next();
            let mut escaping = false;
            let mut cleaned = String::with_capacity(32);

            while let Some(&(_, current)) = chars.peek() {
                chars.next();
                if escaping {
                    cleaned.push(current);
                    escaping = false;
                } else if current == '\\' {
                    escaping = true;
                } else if current == quote {
                    if cleaned.len() >= 4 {
                        values.push(cleaned);
                    }
                    break;
                } else if !current.is_ascii_whitespace() {
                    cleaned.push(current);
                }
            }
            continue;
        }

        // ── Assignment values (key=value / key: value) ──────────────
        if ch == ':' || ch == '=' {
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
            flush_pct(&mut values, &mut pct_block);

            chars.next();
            // Skip whitespace after delimiter
            while chars.peek().is_some_and(|&(_, c)| c.is_ascii_whitespace()) {
                chars.next();
            }
            let mut cleaned = String::with_capacity(32);
            while let Some(&(_, c)) = chars.peek() {
                if c.is_ascii_whitespace()
                    || c == ';'
                    || c == ','
                    || c == '"'
                    || c == '\''
                    || c == '`'
                {
                    break;
                }
                cleaned.push(c);
                chars.next();
            }
            if cleaned.len() >= 4 {
                values.push(cleaned);
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
            flush_pct(&mut values, &mut pct_block);
        }

        // ── Base64 block accumulation (merged from old second pass) ─
        if is_b64_char(ch) {
            b64_block.push(ch);
        } else if !ch.is_whitespace() {
            if b64_block.len() >= 16 {
                values.push(std::mem::take(&mut b64_block));
            }
            b64_block.clear();
        }
        // else: whitespace inside b64 blocks is allowed (line continuations)

        chars.next();
    }

    // Flush trailing b64 block
    if b64_block.len() >= 16 {
        values.push(b64_block);
    }
    flush_pct(&mut values, &mut pct_block);

    values
}

/// Fast non-cryptographic hash for dedup, re-exported from the crate-canonical
/// FNV-1a in [`crate::util_hash`]. The loop body used to live here (and was
/// copy-pasted into entropy/ml_scorer/decode_structure); it now has a single
/// home so a seed/prime change can never silently re-key only some caches.
/// Keep this re-export so `decode::pipeline` callers that import
/// `extractor::hash_fast` stay unchanged.
pub(crate) use crate::util_hash::hash_fast;
