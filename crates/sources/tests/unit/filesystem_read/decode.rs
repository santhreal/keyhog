//! Decode responsibility tests for filesystem read: binary-vs-text
//! classification, magic-byte heuristics, UTF-16/UTF-8 text decoding, and
//! the owning/non-owning decoder pair.

use keyhog_sources::testing::{zstd_frame_magic_for_test, TestApi};

/// Regression: preserves the externally observable `looks_binary_empty_input_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_empty_input_is_text() {
    assert!(!TestApi.looks_binary(&[]));
}

/// Regression: preserves the externally observable `looks_binary_clean_ascii_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_clean_ascii_is_text() {
    let s = "hello world\nfoo = bar\n".repeat(1024);
    assert!(!TestApi.looks_binary(s.as_bytes()));
}

/// Regression: preserves the externally observable `looks_binary_dense_controls_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_dense_controls_is_binary() {
    let mut bytes = vec![b'a'; 1024];
    for b in bytes.iter_mut().take(200) {
        *b = 0x03; // ETX, well over the 5% threshold
    }
    assert!(TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `looks_binary_sparse_controls_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_sparse_controls_is_text() {
    // Below threshold - exactly 5% would equal `suspicious * 20 == total`,
    // which is `>` test → still text.
    let mut bytes = vec![b'a'; 1000];
    for b in bytes.iter_mut().take(50) {
        *b = 0x03;
    }
    assert!(!TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `looks_binary_single_control_in_short_text_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_single_control_in_short_text_is_text() {
    let bytes = b"KEY\0VALUE\n";
    assert!(
        !TestApi.looks_binary(bytes),
        "one embedded NUL/control byte is not enough evidence to skip a text file"
    );
}

/// Regression: preserves the externally observable `looks_binary_repeated_nul_run_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_repeated_nul_run_is_binary() {
    let bytes = b"prefix\0\0\0\0suffix";
    assert!(TestApi.looks_binary(bytes));
}

/// Regression: preserves the externally observable `decode_text_rejects_dense_control_prefix_even_with_invalid_utf8_tail` behavior after the inline suite split.
#[test]
fn decode_text_rejects_dense_control_prefix_even_with_invalid_utf8_tail() {
    let mut bytes = vec![b'a'; 100_000];
    bytes[..300].fill(0x03);
    bytes.push(0xFF);

    assert!(TestApi.decode_text_file(&bytes).is_none());
    assert!(TestApi.decode_text_file_owned_or_bytes(bytes).is_err());
}

/// Regression: preserves the externally observable `binary_magic_short_ascii_prefixes_require_structure` behavior after the inline suite split.
#[test]
fn binary_magic_short_ascii_prefixes_require_structure() {
    assert!(!TestApi.looks_binary(b"BM_TOKEN=text_prefix_value"));
    assert!(!TestApi.looks_binary_prefix(b"BM_TOKEN=text"));
    assert!(!TestApi.looks_binary(b"MZ_TOKEN=text_prefix_value"));
    assert!(!TestApi.looks_binary_prefix(b"MZ_TOKEN=text"));
    assert!(!TestApi.looks_binary(b"BZh_TOKEN=text_prefix_value"));
    assert!(!TestApi.looks_binary_prefix(b"BZh_TOKEN=text"));
}

/// Regression: preserves the externally observable `binary_magic_structural_bmp_pe_and_bzip2_headers_are_binary` behavior after the inline suite split.
#[test]
fn binary_magic_structural_bmp_pe_and_bzip2_headers_are_binary() {
    let bmp = [b'B', b'M', 70, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, b'd', b'a'];
    assert!(TestApi.looks_binary(&bmp));
    assert!(TestApi.looks_binary_prefix(&bmp));

    let mut pe = vec![0u8; 132];
    pe[0..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&128u32.to_le_bytes());
    pe[128..132].copy_from_slice(b"PE\0\0");
    assert!(TestApi.looks_binary(&pe));
    assert!(TestApi.looks_binary_prefix(&pe));

    assert!(TestApi.looks_binary(b"BZh1compressed"));
    assert!(TestApi.looks_binary_prefix(b"BZh1compressed"));
}

/// Regression: preserves the externally observable `binary_magic_pe_prefix_can_live_beyond_256_bytes` behavior after the inline suite split.
#[test]
fn binary_magic_pe_prefix_can_live_beyond_256_bytes() {
    let mut pe = vec![b'A'; 1024];
    pe[0..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&512u32.to_le_bytes());
    pe[512..516].copy_from_slice(b"PE\0\0");

    assert!(!TestApi.looks_binary_prefix(&pe[..256]));
    assert!(TestApi.looks_binary_prefix(&pe));
    assert!(TestApi.decode_text_file(&pe).is_none());
}

/// Regression: preserves the externally observable `binary_magic_zstd_header_is_binary_in_full_and_prefix_paths` behavior after the inline suite split.
#[test]
fn binary_magic_zstd_header_is_binary_in_full_and_prefix_paths() {
    let mut bytes = zstd_frame_magic_for_test().to_vec();
    bytes.extend_from_slice(&[0x00, b'a', b'b', b'c']);
    bytes.extend_from_slice(&[b'a'; 256]);

    assert!(TestApi.looks_binary(&bytes));
    assert!(TestApi.looks_binary_prefix(&bytes));
    assert!(TestApi.decode_text_file(&bytes).is_none());
}

/// Regression: preserves the externally observable `binary_magic_pickle_header_is_full_file_only` behavior after the inline suite split.
#[test]
fn binary_magic_pickle_header_is_full_file_only() {
    let bytes = [0x80, 0x02, b'}'];

    assert!(TestApi.looks_binary(&bytes));
    assert!(!TestApi.looks_binary_prefix(&bytes));
    assert!(TestApi.decode_text_file(&bytes).is_none());
}

/// Regression: preserves the externally observable `looks_binary_short_circuit_matches_full_scan` behavior after the inline suite split.
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
                TestApi.looks_binary(&bytes),
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

/// Regression: preserves the externally observable `looks_binary_three_consecutive_nuls_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_three_consecutive_nuls_is_text() {
    assert!(!TestApi.looks_binary(b"prefix\0\0\0suffix"));
}

/// Regression: preserves the externally observable `looks_binary_four_consecutive_nuls_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_four_consecutive_nuls_is_binary() {
    assert!(TestApi.looks_binary(b"prefix\0\0\0\0suffix"));
}

/// Regression: preserves the externally observable `looks_binary_five_consecutive_nuls_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_five_consecutive_nuls_is_binary() {
    assert!(TestApi.looks_binary(b"x\0\0\0\0\0y"));
}

/// Regression: preserves the externally observable `looks_binary_four_nuls_at_buffer_end_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_four_nuls_at_buffer_end_is_binary() {
    assert!(TestApi.looks_binary(b"trailing\0\0\0\0"));
}

/// Regression: preserves the externally observable `looks_binary_three_nuls_at_buffer_end_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_three_nuls_at_buffer_end_is_text() {
    // No 4-run, and three controls is below the SUSPICIOUS_CONTROL_BINARY_MIN
    // floor, so a short tail of three NULs stays text.
    assert!(!TestApi.looks_binary(b"trailing\0\0\0"));
}

/// Regression: preserves the externally observable `looks_binary_non_consecutive_nuls_low_density_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_non_consecutive_nuls_low_density_is_text() {
    // Six scattered single NULs, none consecutive, diluted well below 5%.
    assert!(!TestApi.looks_binary(&diluted(b"a\0b\0c\0d\0e\0f\0g", 1000)));
}

/// Regression: preserves the externally observable `looks_binary_separated_nul_pairs_low_density_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_separated_nul_pairs_low_density_is_text() {
    // Two 2-NUL runs (each below the 4-run threshold), diluted below 5%.
    assert!(!TestApi.looks_binary(&diluted(b"ab\0\0cd\0\0ef", 1000)));
}

// ── C0 control-exemption set ───────────────────────────────────────────────
// looks_binary counts a byte as a binary-control signal iff it is < 0x20 and is
// NOT one of the text-layout whitespace bytes \n \r \t and form-feed (0x0C).
// These pin which dense single-byte fills stay text vs flip to binary.

/// Regression: preserves the externally observable `looks_binary_dense_form_feed_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_dense_form_feed_is_text() {
    // 0x0C (form feed) is exempt layout whitespace.
    assert!(!TestApi.looks_binary(&vec![0x0C; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_dense_newline_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_dense_newline_is_text() {
    assert!(!TestApi.looks_binary(&vec![b'\n'; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_dense_carriage_return_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_dense_carriage_return_is_text() {
    assert!(!TestApi.looks_binary(&vec![b'\r'; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_dense_tab_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_dense_tab_is_text() {
    assert!(!TestApi.looks_binary(&vec![b'\t'; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_mixed_layout_whitespace_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_mixed_layout_whitespace_is_text() {
    let bytes: Vec<u8> = b"\n\r\t\x0C".iter().copied().cycle().take(1000).collect();
    assert!(!TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `looks_binary_dense_vertical_tab_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_dense_vertical_tab_is_binary() {
    // 0x0B (vertical tab) is < 0x20 and NOT in the exempt set.
    assert!(TestApi.looks_binary(&vec![0x0B; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_dense_escape_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_dense_escape_is_binary() {
    // 0x1B (ESC) is a binary-control signal.
    assert!(TestApi.looks_binary(&vec![0x1B; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_dense_bell_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_dense_bell_is_binary() {
    // 0x07 (BEL) is a binary-control signal.
    assert!(TestApi.looks_binary(&vec![0x07; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_dense_high_bytes_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_dense_high_bytes_is_text() {
    // 0xFF is not < 0x20, so it is not a C0-control signal; UTF-8 validity is a
    // separate downstream concern, not looks_binary's job.
    assert!(!TestApi.looks_binary(&vec![0xFF; 1000]));
}

/// Regression: preserves the externally observable `looks_binary_dense_del_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_dense_del_is_text() {
    // DEL (0x7F) is not < 0x20, so looks_binary does not count it.
    assert!(!TestApi.looks_binary(&vec![0x7F; 1000]));
}

// ── density gate: exact absolute verdict at the 5% / min-4 edges ────────────

/// Regression: preserves the externally observable `looks_binary_just_over_five_percent_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_just_over_five_percent_is_binary() {
    // 51 controls of 1000 ⇒ 51*20 = 1020 > 1000.
    let mut bytes = vec![b'a'; 1000];
    bytes[..51].fill(0x03);
    assert!(TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `looks_binary_exactly_five_percent_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_exactly_five_percent_is_text() {
    // 50 of 1000 ⇒ 50*20 = 1000, not strictly greater ⇒ text.
    let mut bytes = vec![b'a'; 1000];
    bytes[..50].fill(0x03);
    assert!(!TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `looks_binary_just_under_five_percent_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_just_under_five_percent_is_text() {
    let mut bytes = vec![b'a'; 1000];
    bytes[..49].fill(0x03);
    assert!(!TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `looks_binary_three_controls_high_density_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_three_controls_high_density_is_text() {
    // 3 controls in a 10-byte file is 30% density, but below the four-control
    // minimum, so a short file with a few controls stays text.
    assert!(!TestApi.looks_binary(b"a\x03b\x03c\x03defg"));
}

/// Regression: preserves the externally observable `looks_binary_four_controls_over_threshold_is_binary` behavior after the inline suite split.
#[test]
fn looks_binary_four_controls_over_threshold_is_binary() {
    // 4 controls in 79 bytes ⇒ 4*20 = 80 > 79 and meets the four-control floor.
    let mut bytes = vec![b'a'; 79];
    bytes[..4].fill(0x03);
    assert!(TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `looks_binary_four_controls_low_density_is_text` behavior after the inline suite split.
#[test]
fn looks_binary_four_controls_low_density_is_text() {
    // 4 controls in a 1000-byte file clears the count floor but is under 5%.
    let mut bytes = vec![b'a'; 1000];
    bytes[..4].fill(0x03);
    assert!(!TestApi.looks_binary(&bytes));
}

/// Regression: preserves the externally observable `decode_utf16_le_round_trip` behavior after the inline suite split.
#[test]
fn decode_utf16_le_round_trip() {
    let s = "hello, 世界! 🌍";
    let mut bytes = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    assert_eq!(TestApi.decode_utf16(&bytes).as_deref(), Some(s));
}

/// Regression: preserves the externally observable `decode_utf16_be_round_trip` behavior after the inline suite split.
#[test]
fn decode_utf16_be_round_trip() {
    let s = "hello, 世界! 🌍";
    let mut bytes = vec![0xFE, 0xFF];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_be_bytes());
    }
    assert_eq!(TestApi.decode_utf16(&bytes).as_deref(), Some(s));
}

/// Regression: preserves the externally observable `decode_utf16_no_bom_is_none` behavior after the inline suite split.
#[test]
fn decode_utf16_no_bom_is_none() {
    let s = "hello";
    let mut bytes = Vec::new();
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    assert!(TestApi.decode_utf16(&bytes).is_none());
}

/// Regression: preserves the externally observable `decode_utf16_odd_length_payload_is_none` behavior after the inline suite split.
#[test]
fn decode_utf16_odd_length_payload_is_none() {
    let bytes = [0xFF, 0xFE, 0x68];
    assert!(TestApi.decode_utf16(&bytes).is_none());
}

/// Regression: preserves the externally observable `decode_utf16_trailing_orphan_keeps_valid_prefix_lossily` behavior after the inline suite split.
#[test]
fn decode_utf16_trailing_orphan_keeps_valid_prefix_lossily() {
    let s = "api_key = \"sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB\"";
    let mut bytes = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes.push(0x68);

    let decoded = TestApi
        .decode_utf16(&bytes)
        .expect("valid UTF-16 prefix survives trailing orphan byte");
    assert!(
        decoded.contains("sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB"),
        "valid decoded UTF-16 content must remain scannable after a torn trailing byte"
    );
    assert!(
        decoded.ends_with('\u{FFFD}'),
        "the orphan trailing byte is represented as one lossy replacement"
    );
}

/// Regression: preserves the externally observable `decode_text_file_utf16_trailing_orphan_is_not_binary_skip` behavior after the inline suite split.
#[test]
fn decode_text_file_utf16_trailing_orphan_is_not_binary_skip() {
    let s = "OPENAI_API_KEY=sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB";
    let mut bytes = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes.push(0x00);

    let decoded = TestApi
        .decode_text_file(&bytes)
        .expect("UTF-16 text with a torn tail decodes lossily");
    assert!(
        decoded.contains("sk-ant-svcacct-abcdefghijklmnopqrstuvwxyz1234567890AB"),
        "decode_text_file must not fall through to binary skip for a valid UTF-16 body"
    );
}

/// Regression: preserves the externally observable `decode_text_file_bom_prefixed_non_utf16_preserves_ascii_secret_via_lossy_append` behavior after the inline suite split.
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

    let decoded = TestApi
        .decode_text_file(&bytes)
        .expect("BOM-prefixed non-UTF-16 buffer still decodes (not binary)");
    assert!(
        decoded.contains(secret),
        "a BOM-prefixed non-UTF-16 file must keep its ASCII secret scannable via the \
         appended lossy view; decoded was:\n{decoded:?}"
    );
}

/// Regression: preserves the externally observable `decode_text_file_genuine_ascii_utf16_is_unchanged_no_lossy_append` behavior after the inline suite split.
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
        TestApi.decode_text_file(&bytes).as_deref(),
        Some(s),
        "ASCII-dominant UTF-16 must decode exactly, with no lossy view appended"
    );
}

/// Regression: preserves the externally observable `decode_utf16_unpaired_surrogate_is_none` behavior after the inline suite split.
#[test]
fn decode_utf16_unpaired_surrogate_is_none() {
    // Lone high surrogate followed by ASCII - invalid UTF-16.
    let bytes = [0xFF, 0xFE, 0x00, 0xD8, b'a', 0x00];
    assert!(TestApi.decode_utf16(&bytes).is_none());
}

/// Regression: preserves the externally observable `decode_text_file_valid_utf8_takes_fast_path` behavior after the inline suite split.
#[test]
fn decode_text_file_valid_utf8_takes_fast_path() {
    let s = "let x = 1;\nfn main() {}\n".repeat(500);
    assert_eq!(
        TestApi.decode_text_file(s.as_bytes()).as_deref(),
        Some(s.as_str())
    );
}

/// Regression: preserves the externally observable `decode_text_file_short_utf8_with_single_nul_is_kept` behavior after the inline suite split.
#[test]
fn decode_text_file_short_utf8_with_single_nul_is_kept() {
    let bytes = b"API_KEY=abc\0def\n";
    assert_eq!(
        TestApi.decode_text_file(bytes).as_deref(),
        Some("API_KEY=abc\0def\n"),
        "a single embedded NUL must not silently turn a text file into a binary skip"
    );
}

/// Regression: preserves the externally observable `decode_text_file_with_bom_strips_bom` behavior after the inline suite split.
#[test]
fn decode_text_file_with_bom_strips_bom() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"hello world");
    assert_eq!(
        TestApi.decode_text_file(&bytes).as_deref(),
        Some("hello world")
    );
}

/// Regression: preserves the externally observable `decode_text_file_owned_with_bom_strips_bom` behavior after the inline suite split.
#[test]
fn decode_text_file_owned_with_bom_strips_bom() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"hello world");

    let decoded = TestApi
        .decode_text_file_owned_or_bytes(bytes)
        .expect("decode");

    assert_eq!(decoded, "hello world");
}

/// Regression: preserves the externally observable `decode_text_file_owned_with_bom_preserves_original_bytes_on_binary_reject` behavior after the inline suite split.
#[test]
fn decode_text_file_owned_with_bom_preserves_original_bytes_on_binary_reject() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(b"\0\0\0\0binary");

    let rejected = TestApi
        .decode_text_file_owned_or_bytes(bytes.clone())
        .expect_err("binary reject");

    assert_eq!(rejected, bytes);
}

/// Regression: preserves the externally observable `decode_text_file_owned_with_bom_invalid_utf8_preserves_original_bytes_on_binary_reject` behavior after the inline suite split.
#[test]
fn decode_text_file_owned_with_bom_invalid_utf8_preserves_original_bytes_on_binary_reject() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF, 0xFF];
    bytes.extend_from_slice(b"\0\0\0\0binary");

    let rejected = TestApi
        .decode_text_file_owned_or_bytes(bytes.clone())
        .expect_err("binary reject");

    assert_eq!(rejected, bytes);
}

/// Regression: preserves the externally observable `decode_text_file_pdf_magic_is_rejected` behavior after the inline suite split.
#[test]
fn decode_text_file_pdf_magic_is_rejected() {
    let mut bytes = b"%PDF-1.7\n".to_vec();
    bytes.extend_from_slice(&vec![b'a'; 4096]);
    assert!(TestApi.decode_text_file(&bytes).is_none());
}

/// Regression: preserves the externally observable `decode_text_file_invalid_utf8_falls_back_to_lossy` behavior after the inline suite split.
#[test]
fn decode_text_file_invalid_utf8_falls_back_to_lossy() {
    // Invalid continuation byte mid-stream. Strict from_utf8 rejects;
    // looks_binary verdict is text (low control density); lossy path
    // returns the original with U+FFFD replacements.
    let mut bytes = b"valid prefix ".to_vec();
    bytes.push(0xFF); // lone byte - invalid UTF-8
    bytes.extend_from_slice(b" suffix");
    let decoded = TestApi
        .decode_text_file(&bytes)
        .expect("lossy fallback runs");
    assert!(decoded.contains("valid prefix"));
    assert!(decoded.contains("suffix"));
    assert!(decoded.contains('\u{FFFD}'));
}

/// Regression: preserves the externally observable `decode_text_file_dense_controls_in_header_rejected` behavior after the inline suite split.
#[test]
fn decode_text_file_dense_controls_in_header_rejected() {
    // Valid UTF-8 but with >5% C0 controls in the first 4 KiB -
    // should hit the looks_binary_header_check path.
    let mut bytes = vec![b'a'; 4096];
    for b in bytes.iter_mut().take(400) {
        *b = 0x01;
    }
    assert!(TestApi.decode_text_file(&bytes).is_none());
}
