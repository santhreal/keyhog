//! Tests for the read module. Kept in one place so cross-module
//! invariants (e.g. mmap-vs-pure-helper equivalence) are easy to
//! verify side-by-side. Submodules expose the test-visible helpers
//! through `pub(in crate::filesystem::read)`.

use super::bytes::read_file_for_compressed_input;
use super::decode::{
    decode_text_file, decode_text_file_owned_or_bytes, decode_utf16, looks_binary,
    looks_binary_prefix,
};
use super::window::{for_each_file_windowed_mmap, read_file_windowed_mmap, slice_into_windows};

#[test]
fn looks_binary_empty_input_is_text() {
    assert!(!looks_binary(&[]));
}

#[test]
fn looks_binary_clean_ascii_is_text() {
    let s = "hello world\nfoo = bar\n".repeat(1024);
    assert!(!looks_binary(s.as_bytes()));
}

#[test]
fn looks_binary_dense_controls_is_binary() {
    let mut bytes = vec![b'a'; 1024];
    for b in bytes.iter_mut().take(200) {
        *b = 0x03; // ETX, well over the 5% threshold
    }
    assert!(looks_binary(&bytes));
}

#[test]
fn looks_binary_sparse_controls_is_text() {
    // Below threshold - exactly 5% would equal `suspicious * 20 == total`,
    // which is `>` test → still text.
    let mut bytes = vec![b'a'; 1000];
    for b in bytes.iter_mut().take(50) {
        *b = 0x03;
    }
    assert!(!looks_binary(&bytes));
}

#[test]
fn looks_binary_single_control_in_short_text_is_text() {
    let bytes = b"KEY\0VALUE\n";
    assert!(
        !looks_binary(bytes),
        "one embedded NUL/control byte is not enough evidence to skip a text file"
    );
}

#[test]
fn looks_binary_repeated_nul_run_is_binary() {
    let bytes = b"prefix\0\0\0\0suffix";
    assert!(looks_binary(bytes));
}

#[test]
fn decode_text_rejects_dense_control_prefix_even_with_invalid_utf8_tail() {
    let mut bytes = vec![b'a'; 100_000];
    bytes[..300].fill(0x03);
    bytes.push(0xFF);

    assert!(decode_text_file(&bytes).is_none());
    assert!(decode_text_file_owned_or_bytes(bytes).is_err());
}

#[test]
fn binary_magic_short_ascii_prefixes_require_structure() {
    assert!(!looks_binary(b"BM_TOKEN=text_prefix_value"));
    assert!(!looks_binary_prefix(b"BM_TOKEN=text"));
    assert!(!looks_binary(b"MZ_TOKEN=text_prefix_value"));
    assert!(!looks_binary_prefix(b"MZ_TOKEN=text"));
    assert!(!looks_binary(b"BZh_TOKEN=text_prefix_value"));
    assert!(!looks_binary_prefix(b"BZh_TOKEN=text"));
}

#[test]
fn binary_magic_structural_bmp_pe_and_bzip2_headers_are_binary() {
    let bmp = [b'B', b'M', 70, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, b'd', b'a'];
    assert!(looks_binary(&bmp));
    assert!(looks_binary_prefix(&bmp));

    let mut pe = vec![0u8; 132];
    pe[0..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&128u32.to_le_bytes());
    pe[128..132].copy_from_slice(b"PE\0\0");
    assert!(looks_binary(&pe));
    assert!(looks_binary_prefix(&pe));

    assert!(looks_binary(b"BZh1compressed"));
    assert!(looks_binary_prefix(b"BZh1compressed"));
}

#[test]
fn binary_magic_pe_prefix_can_live_beyond_256_bytes() {
    let mut pe = vec![b'A'; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&512u32.to_le_bytes());
    pe[512..516].copy_from_slice(b"PE\0\0");

    assert!(!looks_binary_prefix(&pe[..256]));
    assert!(looks_binary_prefix(&pe));
    assert!(decode_text_file(&pe).is_none());
}

#[test]
fn binary_magic_zstd_header_is_binary_in_full_and_prefix_paths() {
    let mut bytes = crate::magic::ZSTD_FRAME_MAGIC.to_vec();
    bytes.extend_from_slice(&[0x00, b'a', b'b', b'c']);
    bytes.extend_from_slice(&[b'a'; 256]);

    assert!(looks_binary(&bytes));
    assert!(looks_binary_prefix(&bytes));
    assert!(decode_text_file(&bytes).is_none());
}

#[test]
fn binary_magic_pickle_header_is_full_file_only() {
    let bytes = [0x80, 0x02, b'}'];

    assert!(looks_binary(&bytes));
    assert!(!looks_binary_prefix(&bytes));
    assert!(decode_text_file(&bytes).is_none());
}

#[test]
fn looks_binary_short_circuit_matches_full_scan() {
    // Random fixed-seed mix; exhaustive comparison against the
    // previous "filter().count()" implementation for several sizes
    // and densities, including the page-boundary cases where the
    // remaining-bytes early-text exit fires.
    for size in [1, 100, 4095, 4096, 4097, 8192, 16384, 100_000] {
        for density in [0u8, 1, 4, 5, 6, 50] {
            let mut bytes = vec![b'.'; size];
            for i in (0..size)
                .step_by(100usize.saturating_div(density.max(1) as usize).max(1))
                .take((size * density as usize) / 100)
            {
                bytes[i] = 0x03;
            }
            let suspicious = bytes
                .iter()
                .filter(|&&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t' | 0x0C))
                .count() as u64;
            let expected = suspicious >= 4 && suspicious * 20 > bytes.len().max(1) as u64;
            assert_eq!(
                looks_binary(&bytes),
                expected,
                "size={size} density={density}"
            );
        }
    }
}

// ── NUL-run boundary (BINARY_NUL_RUN = 4 consecutive NULs) ─────────────────
// A run of >= 4 consecutive NULs is binary; fewer (or non-consecutive NULs at
// low density) stay text so a planted ASCII secret beside a stray NUL is still
// scanned. These pin the exact run length so a future edit to BINARY_NUL_RUN is
// caught.

/// Pad `core` with `filler` 'x' bytes so its control density is well under 5%,
/// isolating the NUL-run logic from the density gate.
fn diluted(core: &[u8], filler: usize) -> Vec<u8> {
    let mut bytes = core.to_vec();
    bytes.resize(bytes.len() + filler, b'x');
    bytes
}

#[test]
fn looks_binary_three_consecutive_nuls_is_text() {
    assert!(!looks_binary(b"prefix\0\0\0suffix"));
}

#[test]
fn looks_binary_four_consecutive_nuls_is_binary() {
    assert!(looks_binary(b"prefix\0\0\0\0suffix"));
}

#[test]
fn looks_binary_five_consecutive_nuls_is_binary() {
    assert!(looks_binary(b"x\0\0\0\0\0y"));
}

#[test]
fn looks_binary_four_nuls_at_buffer_end_is_binary() {
    assert!(looks_binary(b"trailing\0\0\0\0"));
}

#[test]
fn looks_binary_three_nuls_at_buffer_end_is_text() {
    // No 4-run, and three controls is below the SUSPICIOUS_CONTROL_BINARY_MIN
    // floor, so a short tail of three NULs stays text.
    assert!(!looks_binary(b"trailing\0\0\0"));
}

#[test]
fn looks_binary_non_consecutive_nuls_low_density_is_text() {
    // Six scattered single NULs, none consecutive, diluted well below 5%.
    assert!(!looks_binary(&diluted(b"a\0b\0c\0d\0e\0f\0g", 1000)));
}

#[test]
fn looks_binary_separated_nul_pairs_low_density_is_text() {
    // Two 2-NUL runs (each below the 4-run threshold), diluted below 5%.
    assert!(!looks_binary(&diluted(b"ab\0\0cd\0\0ef", 1000)));
}

// ── C0 control-exemption set ───────────────────────────────────────────────
// looks_binary counts a byte as a binary-control signal iff it is < 0x20 and is
// NOT one of the text-layout whitespace bytes \n \r \t and form-feed (0x0C).
// These pin which dense single-byte fills stay text vs flip to binary.

#[test]
fn looks_binary_dense_form_feed_is_text() {
    // 0x0C (form feed) is exempt layout whitespace.
    assert!(!looks_binary(&vec![0x0C; 1000]));
}

#[test]
fn looks_binary_dense_newline_is_text() {
    assert!(!looks_binary(&vec![b'\n'; 1000]));
}

#[test]
fn looks_binary_dense_carriage_return_is_text() {
    assert!(!looks_binary(&vec![b'\r'; 1000]));
}

#[test]
fn looks_binary_dense_tab_is_text() {
    assert!(!looks_binary(&vec![b'\t'; 1000]));
}

#[test]
fn looks_binary_mixed_layout_whitespace_is_text() {
    let bytes: Vec<u8> = b"\n\r\t\x0C".iter().copied().cycle().take(1000).collect();
    assert!(!looks_binary(&bytes));
}

#[test]
fn looks_binary_dense_vertical_tab_is_binary() {
    // 0x0B (vertical tab) is < 0x20 and NOT in the exempt set.
    assert!(looks_binary(&vec![0x0B; 1000]));
}

#[test]
fn looks_binary_dense_escape_is_binary() {
    // 0x1B (ESC) is a binary-control signal.
    assert!(looks_binary(&vec![0x1B; 1000]));
}

#[test]
fn looks_binary_dense_bell_is_binary() {
    // 0x07 (BEL) is a binary-control signal.
    assert!(looks_binary(&vec![0x07; 1000]));
}

#[test]
fn looks_binary_dense_high_bytes_is_text() {
    // 0xFF is not < 0x20, so it is not a C0-control signal; UTF-8 validity is a
    // separate downstream concern, not looks_binary's job.
    assert!(!looks_binary(&vec![0xFF; 1000]));
}

#[test]
fn looks_binary_dense_del_is_text() {
    // DEL (0x7F) is not < 0x20, so looks_binary does not count it.
    assert!(!looks_binary(&vec![0x7F; 1000]));
}

// ── density gate: exact absolute verdict at the 5% / min-4 edges ────────────

#[test]
fn looks_binary_just_over_five_percent_is_binary() {
    // 51 controls of 1000 ⇒ 51*20 = 1020 > 1000.
    let mut bytes = vec![b'a'; 1000];
    bytes[..51].fill(0x03);
    assert!(looks_binary(&bytes));
}

#[test]
fn looks_binary_exactly_five_percent_is_text() {
    // 50 of 1000 ⇒ 50*20 = 1000, not strictly greater ⇒ text.
    let mut bytes = vec![b'a'; 1000];
    bytes[..50].fill(0x03);
    assert!(!looks_binary(&bytes));
}

#[test]
fn looks_binary_just_under_five_percent_is_text() {
    let mut bytes = vec![b'a'; 1000];
    bytes[..49].fill(0x03);
    assert!(!looks_binary(&bytes));
}

#[test]
fn looks_binary_three_controls_high_density_is_text() {
    // 3 controls in a 10-byte file is 30% density, but below the four-control
    // minimum, so a short file with a few controls stays text.
    assert!(!looks_binary(b"a\x03b\x03c\x03defg"));
}

#[test]
fn looks_binary_four_controls_over_threshold_is_binary() {
    // 4 controls in 79 bytes ⇒ 4*20 = 80 > 79 and meets the four-control floor.
    let mut bytes = vec![b'a'; 79];
    bytes[..4].fill(0x03);
    assert!(looks_binary(&bytes));
}

#[test]
fn looks_binary_four_controls_low_density_is_text() {
    // 4 controls in a 1000-byte file clears the count floor but is under 5%.
    let mut bytes = vec![b'a'; 1000];
    bytes[..4].fill(0x03);
    assert!(!looks_binary(&bytes));
}

#[test]
fn decode_utf16_le_round_trip() {
    let s = "hello, 世界! 🌍";
    let mut bytes = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(decode_utf16(&bytes).as_deref(), Some(s));
}

#[test]
fn decode_utf16_be_round_trip() {
    let s = "hello, 世界! 🌍";
    let mut bytes = vec![0xFE, 0xFF];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_be_bytes());
    }
    assert_eq!(decode_utf16(&bytes).as_deref(), Some(s));
}

#[test]
fn decode_utf16_no_bom_is_none() {
    let s = "hello";
    let mut bytes = Vec::new();
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    assert!(decode_utf16(&bytes).is_none());
}

#[test]
fn decode_utf16_odd_length_payload_is_none() {
    let bytes = [0xFF, 0xFE, 0x68];
    assert!(decode_utf16(&bytes).is_none());
}

#[test]
fn decode_utf16_trailing_orphan_keeps_valid_prefix_lossily() {
    let s = "api_key = \"sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB\"";
    let mut bytes = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes.push(0x68);

    let decoded = decode_utf16(&bytes).expect("valid UTF-16 prefix survives trailing orphan byte");
    assert!(
        decoded.contains("sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB"),
        "valid decoded UTF-16 content must remain scannable after a torn trailing byte"
    );
    assert!(
        decoded.ends_with('\u{FFFD}'),
        "the orphan trailing byte is represented as one lossy replacement"
    );
}

#[test]
fn decode_text_file_utf16_trailing_orphan_is_not_binary_skip() {
    let s = "OPENAI_API_KEY=sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB";
    let mut bytes = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes.push(0x00);

    let decoded = decode_text_file(&bytes).expect("UTF-16 text with a torn tail decodes lossily");
    assert!(
        decoded.contains("sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB"),
        "decode_text_file must not fall through to binary skip for a valid UTF-16 body"
    );
}

#[test]
fn decode_text_file_bom_prefixed_non_utf16_preserves_ascii_secret_via_lossy_append() {
    // A file that STARTS with the UTF-16-LE BOM bytes but is NOT UTF-16: a
    // Latin-1 / adversarial prefix, then an ASCII secret on a clean line. Decoded
    // as UTF-16 the ASCII bytes pair into meaningless CJK scalars (no 0x00 high
    // bytes => no ASCII scalars), so the secret would vanish and the scan would
    // report a false "clean". The non-ASCII-dominant lossy-view append must keep
    // the ASCII secret scannable.
    let secret = "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";
    let mut bytes = vec![0xFF, 0xFE, 0x80, 0x80];
    bytes.extend_from_slice(b" noise ");
    bytes.extend_from_slice(format!("GITHUB_TOKEN={secret}\n").as_bytes());
    bytes.extend_from_slice(&[0x80, 0x81]);

    let decoded = decode_text_file(&bytes)
        .expect("BOM-prefixed non-UTF-16 buffer still decodes (not binary)");
    assert!(
        decoded.contains(secret),
        "a BOM-prefixed non-UTF-16 file must keep its ASCII secret scannable via the \
         appended lossy view; decoded was:\n{decoded:?}"
    );
}

#[test]
fn decode_text_file_genuine_ascii_utf16_is_unchanged_no_lossy_append() {
    // A genuine ASCII UTF-16-LE file is ASCII-dominant, so NO lossy view is
    // appended and the decoded text equals the original exactly (offsets stay
    // exact). Guards the append from firing on the common UTF-16 case.
    let s = "API_KEY=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";
    let mut bytes = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(
        decode_text_file(&bytes).as_deref(),
        Some(s),
        "ASCII-dominant UTF-16 must decode exactly, with no lossy view appended"
    );
}

#[test]
fn decode_utf16_unpaired_surrogate_is_none() {
    // Lone high surrogate followed by ASCII - invalid UTF-16.
    let bytes = [0xFF, 0xFE, 0x00, 0xD8, b'a', 0x00];
    assert!(decode_utf16(&bytes).is_none());
}

#[test]
fn decode_text_file_valid_utf8_takes_fast_path() {
    let s = "let x = 1;\nfn main() {}\n".repeat(500);
    assert_eq!(decode_text_file(s.as_bytes()).as_deref(), Some(s.as_str()));
}

#[test]
fn decode_text_file_short_utf8_with_single_nul_is_kept() {
    let bytes = b"API_KEY=abc\0def\n";
    assert_eq!(
        decode_text_file(bytes).as_deref(),
        Some("API_KEY=abc\0def\n"),
        "a single embedded NUL must not silently turn a text file into a binary skip"
    );
}

#[test]
fn decode_text_file_with_bom_strips_bom() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"hello world");
    assert_eq!(decode_text_file(&bytes).as_deref(), Some("hello world"));
}

#[test]
fn decode_text_file_owned_with_bom_strips_bom() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"hello world");

    let decoded = decode_text_file_owned_or_bytes(bytes).expect("decode");

    assert_eq!(decoded, "hello world");
}

#[test]
fn decode_text_file_owned_with_bom_preserves_original_bytes_on_binary_reject() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"\0\0\0\0binary");

    let rejected = decode_text_file_owned_or_bytes(bytes.clone()).expect_err("binary reject");

    assert_eq!(rejected, bytes);
}

#[test]
fn decode_text_file_owned_with_bom_invalid_utf8_preserves_original_bytes_on_binary_reject() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF, 0xFF];
    bytes.extend_from_slice(b"\0\0\0\0binary");

    let rejected = decode_text_file_owned_or_bytes(bytes.clone()).expect_err("binary reject");

    assert_eq!(rejected, bytes);
}

#[test]
fn decode_text_file_pdf_magic_is_rejected() {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    bytes.extend_from_slice(&vec![b'a'; 4096]);
    assert!(decode_text_file(&bytes).is_none());
}

#[test]
fn decode_text_file_invalid_utf8_falls_back_to_lossy() {
    // Invalid continuation byte mid-stream. Strict from_utf8 rejects;
    // looks_binary verdict is text (low control density); lossy path
    // returns the original with U+FFFD replacements.
    let mut bytes = b"valid prefix ".to_vec();
    bytes.push(0xFF); // lone byte - invalid UTF-8
    bytes.extend_from_slice(b" suffix");
    let decoded = decode_text_file(&bytes).expect("lossy fallback runs");
    assert!(decoded.contains("valid prefix"));
    assert!(decoded.contains("suffix"));
    assert!(decoded.contains('\u{FFFD}'));
}

#[test]
fn decode_text_file_dense_controls_in_header_rejected() {
    // Valid UTF-8 but with >5% C0 controls in the first 4 KiB -
    // should hit the looks_binary_header_check path.
    let mut bytes = vec![b'a'; 4096];
    for b in bytes.iter_mut().take(400) {
        *b = 0x01;
    }
    assert!(decode_text_file(&bytes).is_none());
}

// ----- slice_into_windows: pure-function boundary behavior -----

#[test]
fn slice_into_windows_empty_input_returns_empty() {
    assert!(slice_into_windows(&[], 64, 8).is_empty());
}

#[test]
fn slice_into_windows_smaller_than_window_yields_one_window() {
    let bytes = b"hello, world";
    let ws = slice_into_windows(bytes, 64, 8);
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].offset, 0);
    assert_eq!(ws[0].text, "hello, world");
}

#[test]
fn slice_into_windows_exactly_one_window_size() {
    let bytes = vec![b'a'; 64];
    let ws = slice_into_windows(&bytes, 64, 8);
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].offset, 0);
    assert_eq!(ws[0].text.len(), 64);
}

#[test]
fn slice_into_windows_one_byte_over_window_emits_two_windows() {
    // A 65-byte input with window=64, overlap=8 - stride is 56,
    // so window 1 starts at offset 56 and runs 56..65 = 9 bytes.
    let bytes: Vec<u8> = (0..65u8).collect();
    let ws = slice_into_windows(&bytes, 64, 8);
    assert_eq!(ws.len(), 2);
    assert_eq!(ws[0].offset, 0);
    assert_eq!(ws[0].text.len(), 64);
    assert_eq!(ws[1].offset, 56);
    assert_eq!(ws[1].text.len(), 9);
}

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
    let ws = slice_into_windows(&bytes, 100, 16);
    assert!(ws.len() >= 2);
    for pair in ws.windows(2) {
        let prev = &pair[0];
        let next = &pair[1];
        let prev_tail = &prev.text.as_bytes()[prev.text.len() - 16..];
        let next_head = &next.text.as_bytes()[..16];
        assert_eq!(prev_tail, next_head, "overlap mismatch at {}", next.offset);
        assert_eq!(next.offset - prev.offset, 100 - 16);
    }
}

#[test]
fn slice_into_windows_offsets_cover_the_whole_input() {
    // Coverage check requires that decoded text length equals raw
    // slice length, so use ASCII-only bytes and assert that
    // every byte offset is touched by at least one window.
    let bytes: Vec<u8> = (b'a'..=b'z').cycle().take(10_000).collect();
    let ws = slice_into_windows(&bytes, 256, 32);
    let mut covered = vec![false; bytes.len()];
    for w in &ws {
        assert_eq!(
            w.text.len(),
            (w.offset + w.text.len()).min(bytes.len()) - w.offset,
            "ASCII input → text len equals slice len"
        );
        let end = (w.offset + w.text.len()).min(bytes.len());
        covered[w.offset..end].fill(true);
    }
    assert!(
        covered.iter().all(|&c| c),
        "every byte must be covered by some window"
    );
}

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
    let ws = slice_into_windows(&bytes, 128, 32);
    assert_eq!(
        ws.len(),
        2,
        "expected exactly 2 windows for len=200, ws=128, ov=32"
    );
    let s = std::str::from_utf8(secret).unwrap();
    assert!(
        ws[0].text.contains(s),
        "window 0 must carry the straddling secret"
    );
    assert!(
        ws[1].text.contains(s),
        "window 1 must carry the straddling secret"
    );
}

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
    let ws = slice_into_windows(&bytes, 64, 8);
    assert_eq!(ws.len(), 2, "expected 2 windows for len=120, ws=64, ov=8");
    // Window 0 covers 0..64 → only 0xE2 of the sequence is present.
    // Lossy decode replaces the dangling lead byte with U+FFFD.
    assert!(ws[0].text.ends_with('\u{FFFD}'));
    // Window 1 covers 56..120 → full snowman at relative 7..10.
    assert!(ws[1].text.contains('☃'));
}

#[test]
fn slice_into_windows_large_input_window_count_matches_formula() {
    // len = 4096, window = 1024, overlap = 64 → stride = 960.
    // Windows: starts at 0, 960, 1920, 2880, 3840 - 5 windows
    // (the last one ending exactly at 4096).
    let bytes = vec![b'x'; 4096];
    let ws = slice_into_windows(&bytes, 1024, 64);
    assert_eq!(ws.len(), 5);
    assert_eq!(ws[0].offset, 0);
    assert_eq!(ws[1].offset, 960);
    assert_eq!(ws[2].offset, 1920);
    assert_eq!(ws[3].offset, 2880);
    assert_eq!(ws[4].offset, 3840);
    assert_eq!(ws[4].text.len(), 256);
}

#[test]
#[should_panic(expected = "window must exceed overlap")]
fn slice_into_windows_panics_when_overlap_geq_window() {
    // Same-as-window overlap means stride == 0 → infinite loop.
    // Catch it as a programming error at the API surface.
    slice_into_windows(b"abc", 16, 16);
}

#[test]
fn read_file_windowed_mmap_roundtrip_matches_pure_helper() {
    // The mmap path is just slice_into_windows over the mmap'd
    // bytes. Write a small file, run both, assert identical.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.txt");
    let bytes: Vec<u8> = (0..u8::MAX).cycle().take(8192).collect();
    std::fs::write(&path, &bytes).unwrap();

    let pure = slice_into_windows(&bytes, 1024, 32);
    let mapped = read_file_windowed_mmap(&path, 1024, 32).expect("mmap windows");
    assert_eq!(pure.len(), mapped.len());
    for (a, b) in pure.iter().zip(mapped.iter()) {
        assert_eq!(a.offset, b.offset);
        assert_eq!(a.text, b.text);
    }
}

#[test]
fn for_each_file_windowed_mmap_stops_on_consumer_backpressure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.txt");
    let bytes: Vec<u8> = (0..u8::MAX).cycle().take(8192).collect();
    std::fs::write(&path, &bytes).unwrap();

    let mut seen = Vec::new();
    let mut errors = Vec::new();
    let mapped = for_each_file_windowed_mmap(&path, 1024, 32, |row| match row {
        Ok(window) => {
            seen.push((window.offset, window.text.len()));
            false
        }
        Err(error) => {
            errors.push(error);
            false
        }
    });

    assert!(
        matches!(mapped, super::window::WindowedMmapOutcome::Consumed),
        "mmap path should own this file"
    );
    assert_eq!(seen.len(), 1, "consumer stop must halt window emission");
    assert!(
        errors.is_empty(),
        "normal consumer backpressure must not emit error rows: {errors:?}"
    );
    assert_eq!(seen[0].0, 0, "first streamed window starts at byte zero");
    assert!(seen[0].1 >= 1024, "lossy first window should be non-empty");
}

#[test]
fn windowed_mmap_failure_fallback_is_operator_visible() {
    let window = include_str!("window.rs");
    assert!(
        window.contains("\"cannot windowed-mmap file; falling back to buffered read\""),
        "windowed mmap failure must be operator-visible before buffered fallback"
    );
    assert!(
        window.contains("%error") && window.contains("path = %path.display()"),
        "windowed mmap fallback warning must include the path and mmap error"
    );
    let fallback = window
        .split("\"cannot windowed-mmap file; falling back to buffered read\"")
        .nth(1)
        .expect("windowed mmap fallback warning must be present");
    assert!(
        fallback.contains("return WindowedMmapOutcome::Fallback(file);"),
        "windowed mmap failure should hand the already-open descriptor to the buffered window path after warning"
    );
}

#[test]
fn read_file_for_compressed_input_returns_full_contents_via_mmap() {
    // The mmap-or-bytes wrapper must round-trip an arbitrary
    // non-empty byte sequence - covers the common case where
    // compressed inputs are well within the size cap.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blob.bin");
    // Use a payload with a mix of bytes so any truncation
    // manifests as a mismatch, not coincidentally-equal heads.
    let payload: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
    std::fs::write(&path, &payload).unwrap();

    let fb = read_file_for_compressed_input(&path, 1024 * 1024).expect("read ok");
    assert_eq!(fb.as_slice(), &payload[..]);
    assert_eq!(fb.len(), payload.len());
}

#[test]
fn read_file_for_compressed_input_handles_empty_file() {
    // mmap of zero-byte files is rejected on some platforms; the
    // helper must return Some(Owned(empty)) so callers don't
    // misinterpret None as a hard failure.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.bin");
    std::fs::write(&path, b"").unwrap();

    let fb = read_file_for_compressed_input(&path, 1024).expect("empty ok");
    assert!(fb.as_slice().is_empty());
    assert_eq!(fb.len(), 0);
}

#[test]
fn read_file_for_compressed_input_refuses_oversize_input() {
    // size_cap is the gate that keeps a 100 GiB compressed blob
    // out of memory entirely. The helper returns None and emits
    // a tracing warning - caller treats as "skip this file".
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    std::fs::write(&path, vec![0u8; 4096]).unwrap();

    // cap below file size → refused.
    let fb = read_file_for_compressed_input(&path, 1024);
    assert!(fb.is_none(), "input exceeding size_cap must return None");

    // cap at-or-above file size → accepted.
    let fb = read_file_for_compressed_input(&path, 4096);
    assert!(fb.is_some(), "input at-or-below size_cap must succeed");

    // Source-level max_file_size=0 means unlimited. The compressed helper still
    // uses the hard TOCTOU sanity cap, but must not treat zero as "refuse every
    // non-empty compressed input".
    let fb = read_file_for_compressed_input(&path, 0);
    assert!(
        fb.is_some(),
        "size_cap=0 must mean unlimited up to the hard sanity cap"
    );
}

#[test]
fn read_file_for_compressed_input_returns_none_for_missing_path() {
    // Nonexistent path must NOT panic, and must return None so
    // the caller can move on cleanly. (Earlier implementations
    // did `std::fs::read(path)?` and bubbled the error; the new
    // wrapper folds that into None to match the Option-shaped
    // API the windowed helper uses.)
    let fb =
        read_file_for_compressed_input(std::path::Path::new("/nonexistent/keyhog/test/path"), 1024);
    assert!(fb.is_none());
}

#[test]
fn read_file_windowed_mmap_handles_empty_file() {
    // Zero-byte mmap is a corner case some platforms reject. The
    // helper must return either Some(empty vec) or None - never
    // panic. Either way the caller won't emit chunks.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.txt");
    std::fs::write(&path, b"").unwrap();
    // `None` is also acceptable: mmap of zero-length is refused
    // on some platforms. Either way the caller won't emit chunks.
    if let Some(v) = read_file_windowed_mmap(&path, 1024, 32) {
        assert!(v.is_empty());
    }
}

/// Special-file safety at the single read-open boundary (`open_file_safe`).
///
/// A content scanner that walks untrusted trees must (1) NEVER block opening a
/// FIFO with no writer — a plain `open(O_RDONLY)` hangs forever — and (2) refuse
/// every non-regular file (FIFO, socket, char/block device) rather than read
/// from it. The fix is `O_NONBLOCK` on the open plus an fstat of the OPENED fd
/// that fails closed unless `is_file()`. These tests are Unix-only because they
/// fabricate FIFOs / sockets / devices; the portable `is_file()` refusal they
/// exercise is the same code path on every platform, and the regular-file cases
/// below prove the guard does not regress ordinary reads.
#[cfg(unix)]
mod special_files {
    use crate::filesystem::read::raw::{
        open_file_safe, read_file_mmap, read_file_prefix_safe, read_file_safe,
    };
    use crate::filesystem::special_file_test_support::{
        make_fifo, within_timeout, write_regular as regular,
    };
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // ── FIFO: refused, and never blocks ─────────────────────────────────

    #[test]
    fn open_file_safe_refuses_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let err = within_timeout(move || open_file_safe(&fifo)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn open_file_safe_fifo_error_names_non_regular() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let err = within_timeout(move || open_file_safe(&fifo)).unwrap_err();
        assert!(
            err.to_string().contains("non-regular"),
            "error must name the cause, got: {err}"
        );
    }

    #[test]
    fn read_file_safe_refuses_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let result = within_timeout(move || read_file_safe(&fifo, 0));
        assert!(result.is_err(), "read_file_safe must refuse a FIFO");
    }

    #[test]
    fn read_file_prefix_safe_refuses_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let result = within_timeout(move || {
            let mut buf = [0u8; 64];
            read_file_prefix_safe(&fifo, &mut buf)
        });
        assert!(result.is_err(), "read_file_prefix_safe must refuse a FIFO");
    }

    #[test]
    fn read_file_mmap_returns_none_for_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let result = within_timeout(move || read_file_mmap(&fifo));
        assert!(result.is_none(), "read_file_mmap must skip (None) a FIFO");
    }

    #[test]
    fn fifo_refused_by_type_even_with_writer_present() {
        // A keep-alive O_RDWR fd means a blocking open WOULD succeed, proving the
        // refusal is by file TYPE (is_file == false), not merely the no-writer
        // hang the O_NONBLOCK flag covers.
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: open(2) the FIFO read-write non-blocking; closed below.
        let keepalive = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        assert!(keepalive >= 0, "keep-alive open failed");
        let probe = fifo.clone();
        let err = within_timeout(move || open_file_safe(&probe)).unwrap_err();
        // SAFETY: closing the descriptor opened just above.
        unsafe { libc::close(keepalive) };
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    // ── Devices: refused (no streaming /dev/zero, no /dev/null read) ─────

    #[test]
    fn open_file_safe_refuses_dev_null() {
        let err = open_file_safe(Path::new("/dev/null")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn open_file_safe_refuses_dev_zero_so_it_cannot_stream() {
        // /dev/zero would otherwise stream up to the read cap of zero bytes; the
        // boundary refusal means we never enter the read at all.
        let err = open_file_safe(Path::new("/dev/zero")).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn read_file_safe_refuses_dev_null() {
        assert!(read_file_safe(Path::new("/dev/null"), 0).is_err());
    }

    // ── Unix domain socket: refused ─────────────────────────────────────

    #[test]
    fn open_file_safe_refuses_unix_socket() {
        // A socket is refused at the `open(2)` syscall itself (ENXIO, surfaced as
        // an `Uncategorized` kind) BEFORE the metadata guard runs — a FIFO/device
        // instead opens then trips the `is_file()` guard (`InvalidInput`). Either
        // way the contract is the same: a non-regular file never reaches a read.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(
            open_file_safe(&sock).is_err(),
            "a unix-domain socket must be refused"
        );
    }

    #[test]
    fn read_file_safe_refuses_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(read_file_safe(&sock, 0).is_err());
    }

    // ── Directory: refused by the is_file() guard (never a content read) ─

    #[test]
    fn open_file_safe_refuses_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = open_file_safe(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    // ── Symlinks: O_NOFOLLOW refusal preserved (regular + FIFO targets) ──

    #[test]
    fn open_file_safe_refuses_symlink_to_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = regular(dir.path(), "real.txt", b"secret = abc123def456");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            open_file_safe(&link).is_err(),
            "O_NOFOLLOW must refuse a symlinked regular file"
        );
    }

    #[test]
    fn open_file_safe_refuses_symlink_to_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();
        let result = within_timeout(move || open_file_safe(&link));
        assert!(result.is_err(), "a symlink to a FIFO must be refused");
    }

    // ── Regular files: the guard does NOT regress ordinary reads ─────────

    #[test]
    fn open_file_safe_accepts_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = regular(dir.path(), "ok.txt", b"hello");
        assert!(open_file_safe(&path).is_ok());
    }

    #[test]
    fn open_file_safe_regular_file_reads_back_contents() {
        // Proves O_NONBLOCK did not break a normal regular-file read.
        let dir = tempfile::tempdir().unwrap();
        let path = regular(dir.path(), "ok.txt", b"token = ghp_example");
        let mut file = open_file_safe(&path).unwrap();
        let mut s = String::new();
        file.read_to_string(&mut s).unwrap();
        assert_eq!(s, "token = ghp_example");
    }

    #[test]
    fn read_file_safe_regular_file_returns_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = regular(dir.path(), "ok.txt", b"AKIAIOSFODNN7EXAMPLE");
        let bytes = read_file_safe(&path, 20).unwrap();
        assert_eq!(bytes, b"AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn read_file_prefix_safe_regular_file_returns_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = regular(dir.path(), "ok.txt", b"0123456789abcdef");
        let mut buf = [0u8; 8];
        let n = read_file_prefix_safe(&path, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"01234567");
    }

    #[test]
    fn read_file_mmap_regular_file_returns_some() {
        let dir = tempfile::tempdir().unwrap();
        let path = regular(dir.path(), "ok.txt", b"password = hunter2longvalue");
        assert!(read_file_mmap(&path).is_some());
    }

    #[test]
    fn open_file_safe_accepts_empty_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = regular(dir.path(), "empty.txt", b"");
        assert!(open_file_safe(&path).is_ok());
    }

    #[test]
    fn read_file_safe_empty_regular_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = regular(dir.path(), "empty.txt", b"");
        let bytes = read_file_safe(&path, 0).unwrap();
        assert!(bytes.is_empty());
    }
}

/// Special-file safety for the read entry points ABOVE the `open_file_safe`
/// primitive — the buffered read, the compressed-input read (the path 7z / rar /
/// gz / xz / pdf extraction funnels through), the windowed-mmap read (the scan
/// path for large files), and the capped read. Each routes through
/// `open_file_safe`, so each must refuse a FIFO / symlink / device / directory
/// without hanging; these tests lock that contract for every entry point, not
/// just the primitive. Shared FIFO/symlink fixtures + the no-hang watchdog come
/// from `special_file_test_support` (no-duplication).
#[cfg(unix)]
mod higher_read_path_special_files {
    use crate::filesystem::read::raw::read_file_buffered;
    use crate::filesystem::read::{
        read_file_for_compressed_input_for_test as compressed_input,
        read_file_mmap_for_test as mmap_text, read_file_safe_capped_for_test as safe_capped,
        read_file_windowed_mmap_len_for_test as windowed_len,
    };
    use crate::filesystem::special_file_test_support::{
        make_fifo, symlink_to, within_timeout, write_regular,
    };
    use std::path::Path;

    const CAP: u64 = 1 << 20;

    // ── read_file_buffered ──────────────────────────────────────────────

    #[test]
    fn buffered_refuses_fifo_returns_none_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let result = within_timeout(move || read_file_buffered(&fifo, 0));
        assert!(result.is_none(), "buffered read must skip a FIFO");
    }

    #[test]
    fn buffered_refuses_symlink_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_regular(dir.path(), "real.txt", b"secret = abc123def456");
        let link = symlink_to(dir.path(), "link.txt", &target);
        assert!(
            read_file_buffered(&link, 0).is_none(),
            "buffered read must refuse a symlink"
        );
    }

    #[test]
    fn buffered_refuses_directory_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_file_buffered(dir.path(), 0).is_none());
    }

    #[test]
    fn buffered_refuses_dev_null_returns_none() {
        assert!(read_file_buffered(Path::new("/dev/null"), 0).is_none());
    }

    #[test]
    fn buffered_regular_file_returns_some() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_regular(dir.path(), "ok.txt", b"token = ghp_example");
        assert!(read_file_buffered(&path, 0).is_some());
    }

    // ── read_file_for_compressed_input (7z / rar / gz / xz / pdf path) ───

    #[test]
    fn compressed_input_refuses_fifo_none_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "a.gz");
        let result = within_timeout(move || compressed_input(&fifo, CAP));
        assert!(result.is_none(), "compressed-input read must skip a FIFO");
    }

    #[test]
    fn compressed_input_refuses_symlink_to_fifo_none_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let link = symlink_to(dir.path(), "a.gz", &fifo);
        let result = within_timeout(move || compressed_input(&link, CAP));
        assert!(result.is_none());
    }

    #[test]
    fn compressed_input_refuses_symlink_none() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_regular(dir.path(), "real.gz", b"\x1f\x8b\x08\x00");
        let link = symlink_to(dir.path(), "a.gz", &target);
        assert!(
            compressed_input(&link, CAP).is_none(),
            "must refuse a symlinked archive"
        );
    }

    #[test]
    fn compressed_input_refuses_directory_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(compressed_input(dir.path(), CAP).is_none());
    }

    #[test]
    fn compressed_input_refuses_dev_null_none() {
        assert!(compressed_input(Path::new("/dev/null"), CAP).is_none());
    }

    #[test]
    fn compressed_input_regular_file_returns_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_regular(dir.path(), "a.bin", b"PK\x03\x04payload");
        let bytes = compressed_input(&path, CAP).expect("regular file must read");
        assert_eq!(bytes, b"PK\x03\x04payload");
    }

    // ── read_file_windowed_mmap (windowed scan path) ────────────────────

    // The windowed-mmap path expresses a refusal as `Some(0)` — zero windows
    // scanned — rather than `None`: per its contract that is an already-counted
    // unreadable skip that must NOT invite the caller to reopen and stream the
    // file (a bare `None` means "mmap unavailable, try the non-mmap path"). Either
    // way the special file is opened through `open_file_safe`, refused, and never
    // read; the assertion is that ZERO windows reach the scanner.

    #[test]
    fn windowed_refuses_fifo_zero_windows_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let result = within_timeout(move || windowed_len(&fifo, 1024, 32));
        assert_eq!(
            result,
            Some(0),
            "a FIFO must yield zero windows, never hang"
        );
    }

    #[test]
    fn windowed_refuses_symlink_zero_windows() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_regular(dir.path(), "real.txt", b"x".repeat(4096).as_slice());
        let link = symlink_to(dir.path(), "link.txt", &target);
        assert_eq!(
            windowed_len(&link, 1024, 32),
            Some(0),
            "a symlink must yield zero windows"
        );
    }

    #[test]
    fn windowed_refuses_dev_null_zero_windows() {
        assert_eq!(windowed_len(Path::new("/dev/null"), 1024, 32), Some(0));
    }

    #[test]
    fn windowed_regular_file_returns_windows() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_regular(
            dir.path(),
            "big.txt",
            b"password = hunter2longvalue\n".repeat(64).as_slice(),
        );
        let n = windowed_len(&path, 1024, 32).expect("regular file must mmap");
        assert!(
            n > 0,
            "a non-empty regular file must produce at least one window"
        );
    }

    // ── read_file_mmap_for_test ─────────────────────────────────────────

    #[test]
    fn mmap_refuses_fifo_none_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let result = within_timeout(move || mmap_text(&fifo));
        assert!(result.is_none(), "mmap read must skip a FIFO");
    }

    #[test]
    fn mmap_regular_text_file_returns_some() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_regular(dir.path(), "ok.txt", b"AKIAIOSFODNN7EXAMPLE\n");
        assert!(mmap_text(&path).is_some());
    }

    // ── read_file_safe_capped ───────────────────────────────────────────

    #[test]
    fn safe_capped_refuses_fifo_err_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = make_fifo(dir.path(), "pipe");
        let result = within_timeout(move || safe_capped(&fifo, CAP).is_err());
        assert!(result, "capped read must error on a FIFO");
    }

    #[test]
    fn safe_capped_refuses_symlink_err() {
        let dir = tempfile::tempdir().unwrap();
        let target = write_regular(dir.path(), "real.txt", b"hello");
        let link = symlink_to(dir.path(), "link.txt", &target);
        assert!(
            safe_capped(&link, CAP).is_err(),
            "capped read must refuse a symlink"
        );
    }

    #[test]
    fn safe_capped_refuses_dev_null_err() {
        assert!(safe_capped(Path::new("/dev/null"), CAP).is_err());
    }

    #[test]
    fn safe_capped_regular_file_returns_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_regular(dir.path(), "ok.txt", b"AKIAIOSFODNN7EXAMPLE");
        let bytes = safe_capped(&path, 32).unwrap();
        assert_eq!(bytes, b"AKIAIOSFODNN7EXAMPLE");
    }
}
