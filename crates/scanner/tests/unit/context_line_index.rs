use super::*;

#[test]
fn empty_text_has_no_iterated_line_but_maps_offset_to_first_line() {
    let index = LineContextIndex::try_new("").unwrap();
    assert_eq!(index.len(), 1);
    assert_eq!(index.lines("").collect::<Vec<_>>(), Vec::<&str>::new());
    assert_eq!(index.line_number_for_offset(0), 1);
}

#[test]
fn final_newline_preserves_offset_mapping_without_materializing_empty_line() {
    let text = "first\nsecond\n";
    let index = LineContextIndex::try_new(text).unwrap();
    assert_eq!(index.lines(text).collect::<Vec<_>>(), ["first", "second"]);
    assert_eq!(index.line_number_for_offset(text.len()), 3);
    assert_eq!(index.line(text, 2), None);
}

#[test]
fn dense_lines_use_compact_storage_and_lookup_exact_offsets() {
    let text = "1234567\n".repeat(128 * 1024);
    let index = LineContextIndex::try_new(&text).unwrap();
    assert!(index.storage_bytes() < 550_000);
    assert_eq!(index.line_number_for_offset(0), 1);
    assert_eq!(index.line_number_for_offset(7), 1);
    assert_eq!(index.line_number_for_offset(8), 2);
    assert_eq!(index.line_index_for_offset(text.len() - 1), 128 * 1024 - 1);
}

#[test]
fn rejects_offsets_that_do_not_fit_u32() {
    assert_eq!(checked_text_len(u32::MAX as usize), Ok(()));
    if usize::BITS > u32::BITS {
        assert_eq!(
            checked_text_len(u32::MAX as usize + 1),
            Err(LineIndexOverflow)
        );
    }
}

#[test]
fn documentation_flags_are_bit_packed_and_exact() {
    let text = "code\n```rust\nexample\n```\ncode\n\"\"\"docs\nmore\n\"\"\"\ncode";
    let index = LineContextIndex::try_new(text).unwrap();
    let flags: Vec<_> = (0..index.len())
        .map(|line| index.is_documentation(line))
        .collect();
    assert_eq!(
        flags,
        [false, true, true, true, false, false, true, true, false]
    );
    assert_eq!(index.documentation.len(), 1);
}

#[test]
fn context_window_matches_line_boundaries() {
    let text = "zero\none\ntwo\nthree\nfour";
    let index = LineContextIndex::try_new(text).unwrap();
    assert_eq!(index.context_window(text, 3, 1), "one\ntwo\nthree");
    assert_eq!(index.context_window(text, 1, 0), "zero");
}
