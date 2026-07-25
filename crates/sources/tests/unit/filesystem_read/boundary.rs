//! Boundary responsibility tests for filesystem read: overlapping-window
//! slicing arithmetic and special-file safety at every read entry point.

use keyhog_sources::testing::{SourceTestApi, TestApi};
// ----- slice_into_windows: pure-function boundary behavior -----

/// Regression: preserves the externally observable `slice_into_windows_empty_input_returns_empty` behavior after the inline suite split.
#[test]
fn slice_into_windows_empty_input_returns_empty() {
    assert!(TestApi.slice_into_windows_with_offsets(&[], 64, 8).is_empty());
}

/// Regression: preserves the externally observable `slice_into_windows_smaller_than_window_yields_one_window` behavior after the inline suite split.
#[test]
fn slice_into_windows_smaller_than_window_yields_one_window() {
    let bytes = b"hello, world";
    let ws = TestApi.slice_into_windows_with_offsets(bytes, 64, 8);
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].0, 0);
    assert_eq!(ws[0].1, "hello, world");
}

/// Regression: preserves the externally observable `slice_into_windows_exactly_one_window_size` behavior after the inline suite split.
#[test]
fn slice_into_windows_exactly_one_window_size() {
    let bytes = vec![b'a'; 64];
    let ws = TestApi.slice_into_windows_with_offsets(&bytes, 64, 8);
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].0, 0);
    assert_eq!(ws[0].1.len(), 64);
}

/// Regression: preserves the externally observable `slice_into_windows_one_byte_over_window_emits_two_windows` behavior after the inline suite split.
#[test]
fn slice_into_windows_one_byte_over_window_emits_two_windows() {
    // A 65-byte input with window=64, overlap=8 - stride is 56,
    // so window 1 starts at offset 56 and runs 56..65 = 9 bytes.
    let bytes: Vec<u8> = (0..65u8).collect();
    let ws = TestApi.slice_into_windows_with_offsets(&bytes, 64, 8);
    assert_eq!(ws.len(), 2);
    assert_eq!(ws[0].0, 0);
    assert_eq!(ws[0].1.len(), 64);
    assert_eq!(ws[1].0, 56);
    assert_eq!(ws[1].1.len(), 9);
}

/// Regression: preserves the externally observable `slice_into_windows_overlap_bytes_match_between_neighbours` behavior after the inline suite split.
#[test]
fn slice_into_windows_overlap_bytes_match_between_neighbours() {
    // The whole point of overlap: a secret straddling the cut
    // appears in both windows. Use ASCII-only input so lossy
    // decode is a no-op and byte length is preserved across
    // the String round-trip - otherwise U+FFFD substitution
    // makes the post-decode lengths drift from the raw slice.
    let bytes: Vec<u8> = b"0123456789abcdefghijklmnopqrstuvwxyz"
        .iter()
        .copied()
        .cycle()
        .take(200)
        .collect();
    let ws = TestApi.slice_into_windows_with_offsets(&bytes, 100, 16);
    assert!(ws.len() >= 2);
    for pair in ws.windows(2) {
        let prev = &pair[0];
        let next = &pair[1];
        let prev_tail = &prev.1.as_bytes()[prev.1.len() - 16..];
        let next_head = &next.1.as_bytes()[..16];
        assert_eq!(prev_tail, next_head, "overlap mismatch at {}", next.0);
        assert_eq!(next.0 - prev.0, 100 - 16);
    }
}

/// Regression: preserves the externally observable `slice_into_windows_offsets_cover_the_whole_input` behavior after the inline suite split.
#[test]
fn slice_into_windows_offsets_cover_the_whole_input() {
    // Coverage check requires that decoded text length equals raw
    // slice length, so use ASCII-only bytes and assert that
    // every byte offset is touched by at least one window.
    let bytes: Vec<u8> = (b'a'..=b'z').cycle().take(10_000).collect();
    let ws = TestApi.slice_into_windows_with_offsets(&bytes, 256, 32);
    let mut covered = vec![false; bytes.len()];
    for w in &ws {
        assert_eq!(
            w.1.len(),
            (w.0 + w.1.len()).min(bytes.len()) - w.0,
            "ASCII input → text len equals slice len"
        );
        let end = (w.0 + w.1.len()).min(bytes.len());
        covered[w.0..end].fill(true);
    }
    assert!(
        covered.iter().all(|&c| c),
        "every byte must be covered by some window"
    );
}

/// Regression: preserves the externally observable `slice_into_windows_secret_straddling_cut_present_in_both_windows` behavior after the inline suite split.
#[test]
fn slice_into_windows_secret_straddling_cut_present_in_both_windows() {
    // Motivating case. window=128, overlap=32 → stride=96.
    // For exactly 2 windows we need len in (128, 128+96] = (128, 224].
    // Pick 200; windows are [0..128) and [96..200). The secret at
    // offset 100..120 sits in both - so the scanner can't miss it.
    let mut bytes = vec![b'.'; 200];
    // Bytes form is needed because `copy_from_slice` requires &[u8].
    // `bconcat!` was a defunct internal macro removed in c031c84;
    // the equivalent is `concat!(...).as_bytes()`.
    let secret = concat!("AK", "IAIOSFODNN7EXAMPLE").as_bytes();
    bytes[100..100 + secret.len()].copy_from_slice(secret);
    let ws = TestApi.slice_into_windows_with_offsets(&bytes, 128, 32);
    assert_eq!(
        ws.len(),
        2,
        "expected exactly 2 windows for len=200, ws=128, ov=32"
    );
    let s = std::str::from_utf8(secret).unwrap();
    assert!(
        ws[0].1.contains(s),
        "window 0 must carry the straddling secret"
    );
    assert!(
        ws[1].1.contains(s),
        "window 1 must carry the straddling secret"
    );
}

/// Regression: preserves the externally observable `slice_into_windows_invalid_utf8_at_boundary_decodes_lossy` behavior after the inline suite split.
#[test]
fn slice_into_windows_invalid_utf8_at_boundary_decodes_lossy() {
    // A multi-byte UTF-8 sequence cut by the window edge must not
    // panic - it becomes U+FFFD on the side that has the partial
    // bytes, and decodes correctly on the side that has the full
    // sequence. Use the snowman (☃, 0xE2 0x98 0x83) split at the
    // cut between window 0 (ends at byte 64) and window 1
    // (starts at byte 56). Picked len=120 for exactly 2 windows
    // given window=64, overlap=8 → stride=56 (max len for 2 wins
    // is 64+56=120).
    let mut bytes = vec![b'a'; 120];
    bytes[63] = 0xE2;
    bytes[64] = 0x98;
    bytes[65] = 0x83;
    let ws = TestApi.slice_into_windows_with_offsets(&bytes, 64, 8);
    assert_eq!(ws.len(), 2, "expected 2 windows for len=120, ws=64, ov=8");
    // Window 0 covers 0..64 → only 0xE2 of the sequence is present.
    // Lossy decode replaces the dangling lead byte with U+FFFD.
    assert!(ws[0].1.ends_with('\u{FFFD}'));
    // Window 1 covers 56..120 → full snowman at relative 7..10.
    assert!(ws[1].1.contains('☃'));
}

/// Regression: preserves the externally observable `slice_into_windows_large_input_window_count_matches_formula` behavior after the inline suite split.
#[test]
fn slice_into_windows_large_input_window_count_matches_formula() {
    // len = 4096, window = 1024, overlap = 64 → stride = 960.
    // Windows: starts at 0, 960, 1920, 2880, 3840 - 5 windows
    // (the last one ending exactly at 4096).
    let bytes = vec![b'x'; 4096];
    let ws = TestApi.slice_into_windows_with_offsets(&bytes, 1024, 64);
    assert_eq!(ws.len(), 5);
    assert_eq!(ws[0].0, 0);
    assert_eq!(ws[1].0, 960);
    assert_eq!(ws[2].0, 1920);
    assert_eq!(ws[3].0, 2880);
    assert_eq!(ws[4].0, 3840);
    assert_eq!(ws[4].1.len(), 256);
}

/// Regression: preserves the externally observable `slice_into_windows_panics_when_overlap_geq_window` behavior after the inline suite split.
#[test]
#[should_panic(expected = "window must exceed overlap")]
fn slice_into_windows_panics_when_overlap_geq_window() {
    // Same-as-window overlap means stride == 0 → infinite loop.
    // Catch it as a programming error at the API surface.
    TestApi.slice_into_windows_with_offsets(b"abc", 16, 16);
}

#[cfg(unix)]
#[path = "special_files.rs"]
mod special_files;

#[cfg(unix)]
#[path = "higher_read_path_special_files.rs"]
mod higher_read_path_special_files;
