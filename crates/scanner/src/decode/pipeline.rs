use keyhog_core::Chunk;
use std::collections::{HashSet, VecDeque};

const MAX_DECODED_CHUNKS_PER_ROOT: usize = 1000;
const MAX_DECODED_TOTAL_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn decode_chunk(
    chunk: &Chunk,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&crate::alphabet_filter::AlphabetScreen>,
) -> Vec<Chunk> {
    // NOTE: a blanket `has_decodable_payload` early-out was tried here
    // (AUD-speed-2) and reverted: that predicate only recognises base64/hex
    // alphabet runs, but the pipeline also runs URL/percent, HTML-entity,
    // hex/octal/unicode-escape, MIME-word, quoted-printable and JSON decoders
    // whose triggers it does not cover. Gating the whole fan-out on it silently
    // dropped ~7% of credentials under structured-format wrapping
    // (`every_contract_positive_fires_under_every_format_wrapper`). A correct
    // superset gate fires on `% & \ " { =` — which saturate real source — so it
    // buys almost nothing; the genuine cost (Caesar's 25× fan-out over the full
    // chunk) belongs gated at the Caesar decoder on its own alphabetic-run
    // precondition, not as a pipeline-wide recall hazard.
    let mut decoded_chunks = Vec::new();
    let mut queue = VecDeque::from([(chunk.clone(), 0usize)]);
    // Use hash of data instead of full string to save memory on large files.
    let mut seen = HashSet::from([hash_fast(chunk.data.as_bytes())]);
    let mut total_bytes = 0usize;
    // Count EVERY unique decoded chunk against the per-root fan-out cap,
    // not just the ones that pass the alphabet screen and get returned
    // (M2). Screen-failing chunks were still queued and recursively
    // re-decoded but never incremented `decoded_chunks.len()`, so on the
    // live screen-enabled path the 1000-chunk DoS guard never bound a
    // high-fan-out decoder (Caesar emits up to 25 variants/candidate,
    // most failing the screen). The screen decides whether a chunk is
    // RETURNED for scanning; this counter decides the recursion budget.
    let mut produced = 0usize;

    let decoders = registry::active_decoders();
    // Defensive: drop any cache left by a prior `decode_chunk` that early-returned
    // (budget exhausted) before its final clear, so no stale (ptr,len) can be read.
    extractor::clear_shared_candidates();

    while let Some((current, depth)) = queue.pop_front() {
        if crate::deadline::expired(deadline) {
            tracing::debug!(
                path = ?chunk.metadata.path,
                "decode caller deadline exhausted; stopping decode-through"
            );
            crate::telemetry::record_decode_truncation();
            break;
        }
        if depth >= max_depth {
            continue;
        }

        // Prime the whole-chunk extraction ONCE per BFS item so the ~5
        // whole-chunk decoders reuse it instead of each recomputing
        // `extract_encoded_values(&current.data)` (it was ~67% of decode-gen).
        extractor::prime_shared_candidates(&current.data);
        let prof_dec = registry::profile_enabled();
        for (dec_i, decoder) in decoders.iter().enumerate() {
            // Re-check the caller deadline BEFORE each decoder's
            // candidate fan-out (C9). The top-of-loop check only fires
            // once per BFS dequeue, so a single chunk could run all 14
            // decoders to completion with no deadline check. This check stops
            // us from even invoking the next decoder once the deadline trips;
            // the matching check inside the inner loop below stops us
            // consuming the CURRENT decoder's (un-bounded) output.
            if crate::deadline::expired(deadline) {
                tracing::debug!(
                    path = ?chunk.metadata.path,
                    "decode caller deadline exhausted mid-fan-out; stopping decode-through"
                );
                crate::telemetry::record_decode_truncation();
                extractor::clear_shared_candidates();
                return decoded_chunks;
            }
            let dec_t0 = prof_dec.then(std::time::Instant::now);
            let decoded_out = decoder.decode_chunk(&current);
            if let Some(t0) = dec_t0 {
                registry::record_decoder_run(dec_i, t0.elapsed(), decoded_out.len());
            }
            for decoded in decoded_out {
                // Re-check the deadline WHILE consuming this decoder's output
                // (C9 root cause). The pre-decoder check above only fires
                // once per decoder, but `decode_chunk` returns a fully
                // materialized Vec whose length is O(chunk size) -
                // `extract_encoded_values` yields one candidate per quoted
                // string / `key=value` / base64 run, and Caesar fans each out
                // 25x. Without this check the pipeline still hashes, screens,
                // clones, and queues every one of those results after the
                // caller deadline has passed. The
                // `decoder.decode_chunk` call itself cannot be interrupted
                // (trait returns an owned Vec), but bailing here bounds the
                // post-deadline overrun to one decoder's fan-out at most -
                // and stops the (dominant) per-result processing cost dead.
                if crate::deadline::expired(deadline) {
                    tracing::debug!(
                        path = ?chunk.metadata.path,
                        "decode caller deadline exhausted while consuming decoder output; \
                         stopping decode-through"
                    );
                    crate::telemetry::record_decode_truncation();
                    extractor::clear_shared_candidates();
                    return decoded_chunks;
                }
                if seen.insert(hash_fast(decoded.data.as_bytes())) {
                    // Optional sanitization (kimi-wave1 audit finding 5.1).
                    // When `validate=true`, drop decoded chunks containing
                    // NUL bytes - these are typically buggy-decoder output
                    // (mis-decoded binary, broken-encoded base64) and feed
                    // garbage into downstream regex scanning. C1 controls
                    // (0x80-0x9F) are kept because legitimate UTF-8 multi-
                    // byte sequences include those bytes.
                    if validate && decoded.data.as_bytes().contains(&0u8) {
                        continue;
                    }
                    let passes_screen = if let Some(screen) = screen {
                        screen.screen(decoded.data.as_bytes())
                    } else {
                        true
                    };

                    // Count this unique decoded chunk against the fan-out
                    // budget REGARDLESS of screen result (M2): a chunk that
                    // fails the screen is still queued and recursively
                    // re-decoded, so it must consume the recursion budget.
                    produced += 1;
                    total_bytes += decoded.data.len();
                    if produced > MAX_DECODED_CHUNKS_PER_ROOT
                        || total_bytes > MAX_DECODED_TOTAL_BYTES
                    {
                        // Demoted from `warn!` - hitting the recursive
                        // decode limit is a benign cap, not an error.
                        // Files with dense nested encoding (audit logs,
                        // sealed blobs, base64-of-base64-of-zlib...)
                        // trip it routinely on every scan, which made
                        // routine output (e.g. `keyhog scan ~/.config`)
                        // look like the scanner was failing. Real
                        // scanner failures use `warn!`/`error!`.
                        tracing::debug!(
                            path = ?chunk.metadata.path,
                            "decode depth/size cap reached: chunk truncated to limit"
                        );
                        crate::telemetry::record_decode_truncation();
                        extractor::clear_shared_candidates();
                        return decoded_chunks;
                    }

                    queue.push_back((decoded.clone(), depth + 1));
                    if passes_screen {
                        decoded_chunks.push(decoded);
                    }
                }
            }
        }
    }
    extractor::clear_shared_candidates();
    decoded_chunks
}

mod extractor;
mod registry;
mod splice;
pub(super) use extractor::{
    extract_encoded_values, hash_fast, with_extracted_value_spans, ExtractedValue,
};
pub(crate) use extractor::{extract_profile_dump, extract_profile_reset};
pub use registry::register_decoder;
pub(crate) use registry::{decoder_profile_dump, decoder_profile_reset};
#[cfg(test)]
pub(crate) use registry::{register_thread_decoder, ScopedDecoderRegistration};
pub(super) use splice::{
    decode_candidate_spans_exact, decode_candidates, push_decoded_text_chunk,
    push_decoded_text_chunk_spliced, push_decoded_text_chunk_spliced_at,
};
