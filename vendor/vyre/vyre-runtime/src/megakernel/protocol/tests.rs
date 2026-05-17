use super::{
    control, count_done_ring_slots, debug, read_debug_log_into, read_metrics_into, slot,
    try_encode_control, try_encode_empty_debug_log, try_encode_empty_ring,
    try_encode_empty_ring_into, try_read_debug_log_into, try_read_metrics_into,
    MAX_ENCODED_DEBUG_RECORDS, MAX_ENCODED_OBSERVABLE_SLOTS, MAX_ENCODED_RING_SLOTS, STATUS_WORD,
};

#[test]
#[allow(clippy::assertions_on_constants)]
fn control_regions_do_not_alias() {
    let metrics_end = control::METRICS_BASE + control::METRICS_SLOTS;
    assert!(metrics_end <= control::EPOCH);
    assert!(control::EPOCH < control::OBSERVABLE_BASE);
}

#[test]
fn count_done_ring_slots_counts_only_done_status_words() {
    let mut ring = Vec::new();
    try_encode_empty_ring_into(4, &mut ring).unwrap();
    for (slot_idx, status) in [slot::DONE, slot::CLAIMED, slot::DONE, slot::EMPTY]
        .into_iter()
        .enumerate()
    {
        let word_idx = slot_idx * super::SLOT_WORDS as usize + STATUS_WORD as usize;
        let byte_idx = word_idx * 4;
        ring[byte_idx..byte_idx + 4].copy_from_slice(&status.to_le_bytes());
    }
    assert_eq!(count_done_ring_slots(&ring, 4), Some(2));
    assert_eq!(count_done_ring_slots(&ring, 0), None);
    assert_eq!(count_done_ring_slots(&ring[..8], 4), None);
    let mut unaligned = vec![0xAA];
    unaligned.extend_from_slice(&ring);
    assert_eq!(count_done_ring_slots(&unaligned[1..], 4), Some(2));
}

#[test]
fn allocating_encoders_reject_allocation_cap_before_reserving() {
    assert!(try_encode_control(false, 1, MAX_ENCODED_OBSERVABLE_SLOTS + 1).is_err());
    assert!(try_encode_empty_ring(MAX_ENCODED_RING_SLOTS + 1).is_err());
    assert!(try_encode_empty_debug_log(MAX_ENCODED_DEBUG_RECORDS + 1).is_err());
}

#[test]
fn allocating_encoders_preallocate_exact_protocol_capacity() {
    let control = try_encode_control(false, 1, 16).unwrap();
    assert_eq!(control.capacity(), control.len());

    let ring = try_encode_empty_ring(16).unwrap();
    assert_eq!(ring.capacity(), ring.len());

    let debug_log = try_encode_empty_debug_log(16).unwrap();
    assert_eq!(debug_log.capacity(), debug_log.len());
}

#[test]
fn metrics_decode_into_reuses_capacity_without_overreserve() {
    let mut control = super::try_encode_control(false, 1, 0).unwrap();
    let word_idx = control::METRICS_BASE as usize;
    control[word_idx * 4..word_idx * 4 + 4].copy_from_slice(&9_u32.to_le_bytes());

    let mut out = Vec::with_capacity(control::METRICS_SLOTS as usize);
    let initial_capacity = out.capacity();
    read_metrics_into(&control, &mut out);
    assert_eq!(out, vec![(0, 9)]);
    assert_eq!(out.capacity(), initial_capacity);

    try_read_metrics_into(&control, &mut out).unwrap();
    assert_eq!(out, vec![(0, 9)]);
    assert_eq!(out.capacity(), initial_capacity);
}

#[test]
fn debug_log_decode_into_reuses_capacity_without_overreserve() {
    let mut debug_log = super::try_encode_empty_debug_log(2).unwrap();
    debug_log[(debug::CURSOR_WORD as usize) * 4..(debug::CURSOR_WORD as usize) * 4 + 4]
        .copy_from_slice(&debug::RECORD_WORDS.to_le_bytes());
    let record_start = debug::RECORDS_BASE as usize * 4;
    for (idx, value) in [7_u32, 1, 2, 3].into_iter().enumerate() {
        let byte_idx = record_start + idx * 4;
        debug_log[byte_idx..byte_idx + 4].copy_from_slice(&value.to_le_bytes());
    }

    let mut out = Vec::with_capacity(1);
    let initial_capacity = out.capacity();
    read_debug_log_into(&debug_log, &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].fmt_id, 7);
    assert_eq!(out.capacity(), initial_capacity);

    try_read_debug_log_into(&debug_log, &mut out).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out.capacity(), initial_capacity);
}
