use super::MAX_RETAINED_WORKER_SCRATCH_BYTES;

/// WHY: a hostile large candidate must not leave credential-adjacent uppercase
/// bytes or its allocation resident on every reused worker thread.
#[test]
fn oversized_ascii_uppercase_scratch_is_not_retained() {
    let input = "a".repeat(crate::types::MAX_SCAN_CHUNK_BYTES + 1);

    assert_eq!(
        crate::ascii_ci::retained_upper_scratch_capacity_after_for_test(&input),
        0
    );
}

/// WHY: custom checksum policies may admit large base64 payloads; decoded bytes
/// must be zeroed and an outlier allocation must not survive in worker TLS.
#[test]
fn oversized_checksum_base64_scratch_is_not_retained() {
    let encoded_len = crate::types::MAX_SCAN_CHUNK_BYTES * 2;
    let payload = "A".repeat(encoded_len);

    assert_eq!(
        crate::checksum::base64_scratch_capacity_after_payload_for_test(&payload),
        0
    );
}

/// WHY: decode evidence is absent on most chunks, so each worker must start
/// without the former eager 256-entry hash-table allocation.
#[test]
fn decode_facts_cache_starts_without_reserved_slots() {
    assert_eq!(
        crate::decode_structure::reset_decode_facts_cache_capacity_for_test(),
        0
    );
}

/// WHY: newline-dense chunks can produce one generic-keyword candidate per
/// line; that transient index must not leave multiple MiB resident per worker.
#[test]
fn oversized_generic_keyword_line_scratch_is_not_retained() {
    assert_eq!(
        super::phase2_generic::retained_keyword_line_bytes_after_for_test(
            MAX_RETAINED_WORKER_SCRATCH_BYTES + 1,
        ),
        0
    );
}
