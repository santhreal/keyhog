use keyhog_scanner::testing::csr_from_pairs_snapshot_for_test;

/// WHY: flat relation builders emit interleaved row/value pairs, so compaction
/// must restore row order while preserving encounter order inside each row and
/// retaining exactly the two flat vectors.
#[test]
fn flat_pairs_roundtrip_with_exact_two_vector_storage() {
    let snapshot = csr_from_pairs_snapshot_for_test(3, vec![(2, 2), (0, 4), (2, 7), (0, 9)]);

    assert_eq!(snapshot.row_count, 3);
    assert!(!snapshot.is_empty);
    assert_eq!(snapshot.rows, vec![vec![4, 9], vec![], vec![2, 7]]);
    assert!(snapshot.out_of_range_is_none);
    assert_eq!(
        snapshot.storage_lengths,
        (4, 4),
        "four values and row_count + 1 offsets are the complete retained representation"
    );
}

/// WHY: all-empty detector partitions previously retained one inner vector
/// header per detector; CSR must encode those rows with offsets only and zero
/// data entries.
#[test]
fn empty_rows_consume_no_data_slots() {
    let snapshot = csr_from_pairs_snapshot_for_test(3, vec![]);
    assert_eq!(snapshot.rows, vec![Vec::<u32>::new(); 3]);
    assert_eq!(snapshot.storage_lengths, (0, 4));
}

/// WHY: a malformed builder row would otherwise disappear from the retained
/// table and silently under-route a detector.
#[test]
#[should_panic(expected = "CSR pair row 3 exceeds 3")]
fn out_of_range_row_fails_closed() {
    let _ = csr_from_pairs_snapshot_for_test(3, vec![(3, 0)]);
}

/// WHY: narrowing a detector index must never wrap and route a match to a
/// different detector.
#[test]
#[should_panic(expected = "CSR value exceeds the u32 representation")]
fn out_of_range_value_fails_closed() {
    let _ = csr_from_pairs_snapshot_for_test(1, vec![(0, u32::MAX as usize + 1)]);
}
