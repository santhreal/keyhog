use super::limits::{MAX_DECODED_CHUNKS_PER_ROOT, MAX_DECODED_TOTAL_BYTES};
use keyhog_core::Chunk;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

#[cfg(feature = "decode")]
pub(crate) fn decode_chunk_with_policy(
    chunk: &Chunk,
    policy: &super::policy::CompiledDecodeTransformPolicy,
    decoder_plan: &registry::CompiledDecoderPlan,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&crate::alphabet_filter::AlphabetScreen>,
) -> Vec<Chunk> {
    decode_chunk_with_decoders(
        chunk,
        policy,
        decoder_plan.decoders(),
        Some(decoder_plan),
        max_depth,
        validate,
        deadline,
        screen,
    )
}

pub(crate) fn decode_chunk_with_active_decoders(
    chunk: &Chunk,
    policy: &super::policy::CompiledDecodeTransformPolicy,
    max_depth: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&crate::alphabet_filter::AlphabetScreen>,
) -> Vec<Chunk> {
    let decoders = registry::active_decoders();
    decode_chunk_with_decoders(
        chunk, policy, &decoders, None, max_depth, validate, deadline, screen,
    )
}

fn decode_chunk_with_decoders(
    chunk: &Chunk,
    policy: &super::policy::CompiledDecodeTransformPolicy,
    decoders: &[registry::RegisteredDecoder],
    decoder_plan: Option<&registry::CompiledDecoderPlan>,
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
    // superset gate fires on `% & \ " { =`: which saturate real source, so it
    // buys almost nothing; the genuine cost (Caesar's 25× fan-out over the full
    // chunk) belongs gated at the Caesar decoder on its own alphabetic-run
    // precondition, not as a pipeline-wide recall hazard.
    let mut decoded_chunks: Vec<Arc<Chunk>> = Vec::new();
    let root = Arc::new(chunk.clone());
    // Decode independent source regions in nondecreasing source order. Without
    // this cursor, companion-context splices explore every permutation of the
    // same independent replacements (A→B and B→A), exhausting the bounded
    // fan-out before later nested payloads are reached. Equal offsets remain
    // eligible so true same-value nesting (base64(base64(secret))) still works.
    let root_decode_cursor = chunk.metadata.base_offset;
    let mut queue = VecDeque::from([(Arc::clone(&root), 0usize, root_decode_cursor)]);
    // 128-bit content key instead of the full payload to save memory on large
    // files. A single 64-bit FNV would silently drop a genuinely-distinct
    // decoded payload on a hash collision (an unannotated recall loss, Law 10);
    // the 128-bit key (see `dedup_key`) makes that vanishingly improbable
    // without retaining the bytes.
    let mut seen: HashSet<u128> = HashSet::from([dedup_key(chunk.data.as_bytes())]);
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

    // Defensive: drop any cache left by a prior `decode_chunk` that early-returned
    // (budget exhausted) before its final clear, so no stale (ptr,len) can be read.
    extractor::clear_shared_candidates();

    while let Some((current, depth, decode_cursor)) = queue.pop_front() {
        if crate::deadline::expired(deadline) {
            // LAW10: deadline truncation is counted as a typed scanner coverage gap and reported by CLI/reporting surfaces.
            tracing::debug!( // LAW10: the typed decode-truncation counter below is the operator-visible surface.
                path = ?chunk.metadata.path,
                "decode caller deadline exhausted; stopping decode-through"
            );
            crate::telemetry::record_decode_truncation();
            break;
        }
        if depth >= max_depth {
            continue;
        }
        if decoder_plan.is_some_and(|plan| !plan.all_decoder_may_match(&current.data)) {
            continue;
        }

        // Prime whole-chunk extraction once per BFS item. Decoder admission
        // proofs and the decoders that survive them reuse the same candidates.
        // This avoids invoking every decoder when only one representation is
        // present without adding another extraction pass.
        extractor::prime_shared_candidates(&current.data);
        let prof_dec = registry::profile_enabled();
        for (dec_i, decoder) in decoders.iter().enumerate() {
            // Re-check the caller deadline BEFORE each decoder's
            // candidate fan-out (C9). The top-of-loop check only fires
            // once per BFS dequeue, so a single chunk could run all 14 default
            // decoders to completion with no deadline check. This check stops
            // us from even invoking the next decoder once the deadline trips;
            // the matching check inside the inner loop below stops us
            // consuming the CURRENT decoder's (un-bounded) output.
            if crate::deadline::expired(deadline) {
                // LAW10: deadline truncation is counted as a typed scanner coverage gap and reported by CLI/reporting surfaces.
                tracing::debug!( // LAW10: the typed decode-truncation counter below is the operator-visible surface.
                    path = ?chunk.metadata.path,
                    "decode caller deadline exhausted mid-fan-out; stopping decode-through"
                );
                crate::telemetry::record_decode_truncation();
                extractor::clear_shared_candidates();
                return unwrap_decoded_chunks(decoded_chunks);
            }
            if matches!(
                decoder.admission(&current, policy),
                super::DecodeAdmission::Impossible
            ) {
                continue;
            }
            let dec_t0 = prof_dec.then(std::time::Instant::now);
            let (exhaustion, emitted, last_decoded_bytes) = {
                let mut sink = BoundedDecodeSink {
                    decoded_chunks: &mut decoded_chunks,
                    queue: &mut queue,
                    seen: &mut seen,
                    produced: &mut produced,
                    total_bytes: &mut total_bytes,
                    depth,
                    decode_cursor,
                    validate,
                    deadline,
                    screen,
                    exhaustion: None,
                    emitted: 0,
                    last_decoded_bytes: 0,
                };
                decoder.decode_chunk_into(&current, policy, &mut sink);
                (sink.exhaustion, sink.emitted, sink.last_decoded_bytes)
            };
            if let Some(t0) = dec_t0 {
                registry::record_decoder_run(dec_i, t0.elapsed(), emitted);
            }
            if let Some(exhaustion) = exhaustion {
                match exhaustion {
                    DecodeSinkExhaustion::Deadline => {
                        tracing::debug!( // LAW10: the typed decode-truncation counter below is the operator-visible surface.
                            path = ?chunk.metadata.path,
                            decoder = decoder.name(),
                            depth,
                            "decode caller deadline exhausted while producing decoder output; \
                             stopping decode-through"
                        );
                    }
                    DecodeSinkExhaustion::Budget => {
                        tracing::debug!( // LAW10: the typed decode-truncation counter below is the operator-visible surface.
                            path = ?chunk.metadata.path,
                            decoder = decoder.name(),
                            depth,
                            produced,
                            total_bytes,
                            current_bytes = current.data.len(),
                            decoded_bytes = last_decoded_bytes,
                            max_chunks = MAX_DECODED_CHUNKS_PER_ROOT,
                            max_total_bytes = MAX_DECODED_TOTAL_BYTES,
                            "decode depth/size cap reached while producing output"
                        );
                    }
                }
                crate::telemetry::record_decode_truncation();
                extractor::clear_shared_candidates();
                return unwrap_decoded_chunks(decoded_chunks);
            }
        }
    }
    extractor::clear_shared_candidates();
    unwrap_decoded_chunks(decoded_chunks)
}

#[derive(Clone, Copy)]
enum DecodeSinkExhaustion {
    Deadline,
    Budget,
}

struct BoundedDecodeSink<'a> {
    decoded_chunks: &'a mut Vec<Arc<Chunk>>,
    queue: &'a mut VecDeque<(Arc<Chunk>, usize, usize)>,
    seen: &'a mut HashSet<u128>,
    produced: &'a mut usize,
    total_bytes: &'a mut usize,
    depth: usize,
    decode_cursor: usize,
    validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&'a crate::alphabet_filter::AlphabetScreen>,
    exhaustion: Option<DecodeSinkExhaustion>,
    emitted: usize,
    last_decoded_bytes: usize,
}

impl super::DecodeOutputSink for BoundedDecodeSink<'_> {
    fn push(&mut self, decoded: Chunk) -> bool {
        self.emitted = self.emitted.saturating_add(1);
        self.last_decoded_bytes = decoded.data.len();
        // LAW10: closing for the caller deadline is reported immediately after
        // the producer returns through the typed decode-truncation counter.
        if crate::deadline::expired(self.deadline) {
            self.exhaustion = Some(DecodeSinkExhaustion::Deadline);
            return false;
        }

        let decoded_offset = decoded
            .metadata
            .decoded_span
            .map_or(decoded.metadata.base_offset, |(start, _)| {
                decoded.metadata.base_offset.saturating_add(start)
            });
        // LAW10: recall-preserving: the original root bytes still take the
        // whole-chunk scan path unchanged; the canonical source-order branch
        // reaches the same decoded state without the reverse-order permutation.
        if decoded_offset < self.decode_cursor {
            return true;
        }
        // LAW10: recall-preserving: the original root bytes still take the
        // whole-chunk scan path unchanged; identical decoded bytes add no finding.
        if !self.seen.insert(dedup_key(decoded.data.as_bytes())) {
            return true;
        }
        // LAW10: recall-preserving: the original encoded root bytes still take
        // the whole-chunk scan path unchanged; validation rejects only binary views.
        if self.validate && decoded.data.as_bytes().contains(&0u8) {
            return true;
        }

        let next_produced = self.produced.saturating_add(1);
        let next_total_bytes = self.total_bytes.saturating_add(decoded.data.len());
        // LAW10: a shared-budget cut is recorded immediately after production
        // stops through the typed decode-truncation counter.
        if next_produced > MAX_DECODED_CHUNKS_PER_ROOT || next_total_bytes > MAX_DECODED_TOTAL_BYTES
        {
            self.exhaustion = Some(DecodeSinkExhaustion::Budget);
            return false;
        }
        *self.produced = next_produced;
        *self.total_bytes = next_total_bytes;

        // LAW10: recall-preserving: the decoded bytes still take the decode-through
        // queue unchanged; the screen proves only the direct scanner pass impossible.
        let passes_screen = self
            .screen
            .is_none_or(|screen| screen.screen(decoded.data.as_bytes()));
        if passes_screen {
            let shared = Arc::new(decoded);
            self.queue
                .push_back((Arc::clone(&shared), self.depth + 1, decoded_offset));
            self.decoded_chunks.push(shared);
        } else {
            self.queue
                .push_back((Arc::new(decoded), self.depth + 1, decoded_offset));
        }

        if *self.produced == MAX_DECODED_CHUNKS_PER_ROOT
            || *self.total_bytes == MAX_DECODED_TOTAL_BYTES
        {
            self.exhaustion = Some(DecodeSinkExhaustion::Budget);
            false
        } else {
            true
        }
    }
}

fn unwrap_decoded_chunks(chunks: Vec<Arc<Chunk>>) -> Vec<Chunk> {
    chunks
        .into_iter()
        .map(|arc| match Arc::try_unwrap(arc) {
            Ok(chunk) => chunk,
            Err(shared) => (*shared).clone(),
        })
        .collect()
}

/// Salt distinguishing the high 64 bits of [`dedup_key`] from the low. Any fixed
/// non-empty byte string works; distinctness is what makes the two FNV passes
/// independent enough that a 64-bit collision cannot become a 128-bit one.
const DEDUP_KEY_SALT: &[u8] = &[0x9e, 0x37, 0x79, 0xb9];

/// 128-bit content key for BFS decode dedup: the crate-canonical FNV-1a in the
/// low 64 bits, a salted second FNV pass in the high 64 bits. Distinct decoded
/// payloads collide only if they collide under BOTH passes, over the ≤1000 keys
/// a single root can produce (`MAX_DECODED_CHUNKS_PER_ROOT`), the probability is
/// ~n²/2¹²⁹, i.e. unreachable, so the dedup never silently drops a genuinely
/// distinct payload (Law 10) while still keying on 16 bytes, not the payload.
#[inline]
fn dedup_key(data: &[u8]) -> u128 {
    use crate::util_hash::FnvHasher;
    let lo = hash_fast(data);
    let mut hi = FnvHasher::new();
    hi.write(DEDUP_KEY_SALT);
    hi.write(data);
    (u128::from(hi.finish()) << 64) | u128::from(lo)
}

pub(crate) fn canonical_decode_order_probe_for_test() -> Result<usize, String> {
    struct IndependentMarkerDecoder;

    impl super::Decoder for IndependentMarkerDecoder {
        fn name(&self) -> &'static str {
            "canonical-order-probe"
        }

        fn decode_chunk_into(&self, chunk: &Chunk, sink: &mut dyn super::DecodeOutputSink) {
            const ENCODED: [&str; 10] = [
                "E00", "E01", "E02", "E03", "E04", "E05", "E06", "E07", "E08", "E09",
            ];
            const DECODED: [&str; 10] = [
                "D00", "D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08", "D09",
            ];

            for (encoded, decoded) in ENCODED.into_iter().zip(DECODED) {
                if let Some(start) = chunk.data.find(encoded) {
                    if !splice::push_decoded_text_chunk_spliced_at(
                        sink,
                        chunk,
                        Some((start, start + encoded.len())),
                        encoded,
                        decoded.to_owned(),
                        self.name(),
                    ) {
                        return;
                    }
                }
            }
        }
    }

    let chunk = Chunk {
        data: "E00 E01 E02 E03 E04 E05 E06 E07 E08 E09".into(),
        metadata: Default::default(),
    };
    let policy = super::policy::CompiledDecodeTransformPolicy::compile(&[])?;
    let decoders = [registry::RegisteredDecoder::Shared(Arc::new(
        IndependentMarkerDecoder,
    ))];
    Ok(decode_chunk_with_decoders(&chunk, &policy, &decoders, None, 4, false, None, None).len())
}

mod extractor;
mod registry;
mod splice;
pub(crate) use extractor::with_extracted_value_spans;
pub(crate) use extractor::{extract_profile_dump, extract_profile_reset};
pub(super) use extractor::{hash_fast, ExtractedValue};
#[cfg(feature = "decode")]
pub(crate) use registry::default_decoder_names;
pub(crate) use registry::CompiledDecoderPlan;
#[cfg(feature = "decode")]
pub(crate) use registry::{
    active_decoder_admission_sketch, decoder_admission, decoder_admission_sketch,
};
pub(crate) use registry::{decoder_profile_dump, decoder_profile_reset};
pub use registry::{register_decoder, try_register_decoder, DecoderRegistrationError};
#[cfg(test)]
pub(crate) use registry::{register_thread_decoder, ScopedDecoderRegistration};
pub(crate) use splice::{bytecount_newlines, splice_decoded_payload_at};
pub(super) use splice::{
    push_decoded_replacements_spliced, push_decoded_text_chunk, push_decoded_text_chunk_spliced_at,
    stream_batched_decoded_replacements, stream_candidate_refs_exact, stream_candidate_spans_exact,
    DecodedReplacementBatcher, DECODE_REPLACEMENT_BATCH_SOURCE_BYTES,
};
