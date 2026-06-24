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

    assert!(mapped.is_some(), "mmap path should own this file");
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
        fallback.contains("return None;"),
        "windowed mmap failure should still hand off to the buffered window path after warning"
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
