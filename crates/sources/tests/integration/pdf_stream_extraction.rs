//! Stream-decode + parser-boundary hardening for the hand-rolled PDF text
//! extractor (`crates/sources/src/filesystem/extract/pdf.rs`).
//!
//! The sibling files cover different halves of the surface and this one fills
//! the gaps neither reaches:
//!   * `pdf_documents_are_scanned.rs` — the happy-path stream positives
//!     (one uncompressed literal stream, one FlateDecode stream, one hex string).
//!   * `pdf_metadata_and_strings.rs` — Info-dictionary metadata + the
//!     literal/hex string primitives (`\)`, `\\`, `\101`, balanced parens, odd
//!     hex nibble, mixed case).
//!   * `regression_pdf_coverage_gaps_counted.rs` — the Law-10 gap *counters*
//!     (encrypted / corrupt-flate / missing-endstream / unsupported-filter /
//!     truncation / partial-recovery) via the process-global atomics.
//!
//! What NONE of them reach, and what this file locks:
//!   * `is_pdf_keyword_boundary` — a PDF name or word that merely *contains*
//!     `stream` must not be mistaken for the `stream` keyword (a false match
//!     would fabricate a bogus stream body / missing-endstream gap).
//!   * `stream_body_start` — the CRLF / bare-CR / bare-LF byte(s) after the
//!     `stream` keyword must be consumed exactly, never dropping the first
//!     content byte of the secret.
//!   * `stream_is_image` — an `/Image` XObject stream is skipped, never emitted
//!     as garbage "text", and never masks a co-located real text stream.
//!   * the `/Fl` abbreviated flate filter name.
//!   * a multi-filter `/Filter [ … /FlateDecode]` chain we cannot fully decode
//!     surfaces a LOUD gap, never a silent drop (Law 10).
//!   * an encrypted PDF still extracts its still-readable outside-stream
//!     metadata (recall) WHILE flagging the gap (Law 10).
//!   * `parse_octal_escape` at 1/2-digit, mod-256 overflow, and NUL boundaries.
//!   * hex `<>` empty / invalid-nibble / interior-newline-whitespace forms.
//!   * empty literal `()`, the exact `MIN_PDF_TEXT_LEN` boundary, two-level
//!     nested parens, and `\r`/`\t` control escapes.
//!
//! Law 6: every test asserts the real credential bytes (or the exact gap
//! contract), never `!is_empty`.

use crate::support::pdf::{minimal_pdf, pdf_with_body, pdf_with_info_dict};
use crate::support::split_chunk_results;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use keyhog_core::{Chunk, Source};
use keyhog_sources::FilesystemSource;
use std::io::Write;

/// Scan crafted PDF bytes and return `(pdf/other chunks, error strings)`.
fn scan_rows(bytes: Vec<u8>) -> (Vec<Chunk>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("document.pdf"), bytes).expect("write pdf");
    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);
    (
        chunks.into_iter().cloned().collect(),
        errors.iter().map(|e| e.to_string()).collect(),
    )
}

/// Scan crafted PDF bytes, assert NO coverage-gap error rows, return chunks.
fn scan_clean(bytes: Vec<u8>) -> Vec<Chunk> {
    let (chunks, errors) = scan_rows(bytes);
    assert!(
        errors.is_empty(),
        "well-formed PDF fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks
}

/// True when a `filesystem/pdf` chunk carries `marker`.
fn pdf_has(chunks: &[Chunk], marker: &str) -> bool {
    chunks
        .iter()
        .any(|c| c.metadata.source_type == "filesystem/pdf" && c.data.contains(marker))
}

/// True when ANY emitted chunk carries `marker` (proves a drop is total, not
/// merely off the pdf path).
fn any_has(chunks: &[Chunk], marker: &str) -> bool {
    chunks.iter().any(|c| c.data.contains(marker))
}

/// zlib-compress `plain` for a `/FlateDecode` stream body.
fn flate(plain: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain).expect("flate write");
    encoder.finish().expect("flate finish")
}

/// Build a single unfiltered content stream whose `stream` keyword is followed
/// by exactly `eol` before `body` — the `stream_body_start` EOL contract.
fn pdf_stream_with_eol(eol: &[u8], body: &[u8]) -> Vec<u8> {
    let mut pdf = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n<< /Length ".to_vec();
    pdf.extend_from_slice(body.len().to_string().as_bytes());
    pdf.extend_from_slice(b" >>\nstream");
    pdf.extend_from_slice(eol);
    pdf.extend_from_slice(body);
    pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

/// Build a PDF with N content streams, each `(dict, body)` where `dict` is the
/// extra dictionary text after `/Length` (e.g. ` /Filter /FlateDecode`). Each
/// stream is a well-formed `N 0 obj << … >> stream … endstream endobj` so the
/// per-object boundary the extractor keys on (`endobj`/`endstream`) is present.
fn pdf_streams(streams: &[(&str, &[u8])]) -> Vec<u8> {
    let mut pdf = b"%PDF-1.7\n".to_vec();
    for (idx, (dict, body)) in streams.iter().enumerate() {
        pdf.extend_from_slice(
            format!(
                "{} 0 obj\n<< /Length {}{} >>\nstream\n",
                idx + 1,
                body.len(),
                dict
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(body);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
    }
    pdf.extend_from_slice(b"trailer\n<< /Root 1 0 R >>\n%%EOF\n");
    pdf
}

const IMAGE_DICT: &str = " /Subtype /Image /Filter /FlateDecode";

// ── Stream content positives beyond the 3 happy-path tests ───────────────────

#[test]
fn pdf_uncompressed_stream_multiple_show_ops_all_extracted() {
    let chunks = scan_clean(minimal_pdf(
        "",
        b"BT (KEYHOG_SHOWOP_ONE_1234567890) Tj (KEYHOG_SHOWOP_TWO_0987654321) Tj ET",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_SHOWOP_ONE_1234567890"),
        "first show-text operand must extract; got {chunks:?}"
    );
    assert!(
        pdf_has(&chunks, "KEYHOG_SHOWOP_TWO_0987654321"),
        "second show-text operand must extract; got {chunks:?}"
    );
}

#[test]
fn pdf_fl_abbreviated_filter_is_flate_decoded() {
    // `/Fl` is the abbreviated inline-image name for FlateDecode; the decoder
    // must treat it as flate, not as an unsupported filter.
    let body = flate(b"BT (KEYHOG_FL_ABBREV_SECRET_1234567890) Tj ET");
    let chunks = scan_clean(minimal_pdf(" /Filter /Fl", &body));
    assert!(
        pdf_has(&chunks, "KEYHOG_FL_ABBREV_SECRET_1234567890"),
        "the `/Fl` abbreviated flate filter must be inflated; got {chunks:?}"
    );
}

#[test]
fn pdf_stream_literal_balanced_parens_in_stream_not_truncated() {
    // Balanced-paren depth tracking must hold on the STREAM path too, not only
    // on the metadata path.
    let chunks = scan_clean(minimal_pdf(
        "",
        b"BT (KEYHOG(inner)STRM_SECRET_1234567890) Tj ET",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG(inner)STRM_SECRET_1234567890"),
        "balanced parens inside a stream literal must not truncate; got {chunks:?}"
    );
}

// ── Image XObject streams are skipped, never emitted as garbage ──────────────

#[test]
fn pdf_image_stream_content_not_extracted_as_text() {
    // An `/Image` stream is binary; its bytes must NOT surface as text. The
    // marker sits in the raw stream body and must appear in no chunk at all.
    let chunks = scan_clean(minimal_pdf(
        " /Subtype /Image /Filter /FlateDecode",
        b"KEYHOG_IMAGE_BLOB_MUST_NOT_SURFACE_1234567890",
    ));
    assert!(
        !any_has(&chunks, "KEYHOG_IMAGE_BLOB_MUST_NOT_SURFACE_1234567890"),
        "image XObject stream bytes must not be extracted as text; got {chunks:?}"
    );
}

#[test]
fn pdf_image_stream_and_text_stream_only_text_extracted() {
    // Regression: an earlier image stream's `/Subtype /Image` must not leak into
    // the later text stream's dictionary window (a fixed 8 KiB lookback did, and
    // the text stream was silently skipped as an "image").
    let chunks = scan_clean(pdf_streams(&[
        (IMAGE_DICT, b"KEYHOG_IMG_BLOB_SKIP_0987654321"),
        ("", b"BT (KEYHOG_TEXT_ALONGSIDE_IMAGE_1234567890) Tj ET"),
    ]));
    assert!(
        pdf_has(&chunks, "KEYHOG_TEXT_ALONGSIDE_IMAGE_1234567890"),
        "the text stream beside an image stream must extract; got {chunks:?}"
    );
    assert!(
        !any_has(&chunks, "KEYHOG_IMG_BLOB_SKIP_0987654321"),
        "the image stream bytes must still be skipped; got {chunks:?}"
    );
}

#[test]
fn pdf_text_stream_between_two_image_streams_is_extracted() {
    // The dictionary window of the middle text stream must not inherit the
    // FIRST image's `/Subtype /Image`; both images stay skipped.
    let chunks = scan_clean(pdf_streams(&[
        (IMAGE_DICT, b"KEYHOG_IMG_FIRST_BLOB_1111111111"),
        ("", b"BT (KEYHOG_MIDDLE_TEXT_SECRET_1234567890) Tj ET"),
        (IMAGE_DICT, b"KEYHOG_IMG_LAST_BLOB_2222222222"),
    ]));
    assert!(
        pdf_has(&chunks, "KEYHOG_MIDDLE_TEXT_SECRET_1234567890"),
        "a text stream between two image streams must extract; got {chunks:?}"
    );
    assert!(!any_has(&chunks, "KEYHOG_IMG_FIRST_BLOB_1111111111"));
    assert!(!any_has(&chunks, "KEYHOG_IMG_LAST_BLOB_2222222222"));
}

#[test]
fn pdf_two_adjacent_image_streams_both_skipped() {
    // Negative: the window-bounding fix must not accidentally un-classify a real
    // image whose `/Subtype /Image` lives in its OWN dict — both stay skipped.
    let chunks = scan_clean(pdf_streams(&[
        (IMAGE_DICT, b"KEYHOG_IMG_ADJ_A_BLOB_3333333333"),
        (IMAGE_DICT, b"KEYHOG_IMG_ADJ_B_BLOB_4444444444"),
    ]));
    assert!(!any_has(&chunks, "KEYHOG_IMG_ADJ_A_BLOB_3333333333"));
    assert!(!any_has(&chunks, "KEYHOG_IMG_ADJ_B_BLOB_4444444444"));
}

#[test]
fn pdf_many_alternating_image_text_streams_all_text_extracted() {
    // Scale + boundary: 20 alternating image/text streams. Every text stream
    // must resolve against its OWN dict (not an earlier image's), and the
    // per-stream boundary search stays bounded (no O(n²) on many streams).
    let bodies: Vec<Vec<u8>> = (0..20)
        .map(|i| format!("BT (KEYHOG_ALT_TEXT_SECRET_{i:04}0000) Tj ET").into_bytes())
        .collect();
    let img: Vec<Vec<u8>> = (0..20)
        .map(|i| format!("KEYHOG_ALT_IMG_BLOB_{i:04}9999").into_bytes())
        .collect();
    let mut streams: Vec<(&str, &[u8])> = Vec::new();
    for i in 0..20 {
        streams.push((IMAGE_DICT, img[i].as_slice()));
        streams.push(("", bodies[i].as_slice()));
    }
    let chunks = scan_clean(pdf_streams(&streams));
    for i in 0..20 {
        assert!(
            pdf_has(&chunks, &format!("KEYHOG_ALT_TEXT_SECRET_{i:04}0000")),
            "text stream #{i} must extract past every preceding image; got {chunks:?}"
        );
        assert!(
            !any_has(&chunks, &format!("KEYHOG_ALT_IMG_BLOB_{i:04}9999")),
            "image stream #{i} must still be skipped"
        );
    }
}

#[test]
fn pdf_text_stream_before_image_stream_is_extracted() {
    // Control for ordering: a text stream that PRECEDES an image stream was
    // never at risk, and must keep extracting.
    let chunks = scan_clean(pdf_streams(&[
        ("", b"BT (KEYHOG_TEXT_BEFORE_IMAGE_1234567890) Tj ET"),
        (IMAGE_DICT, b"KEYHOG_IMG_TRAILING_BLOB_5555555555"),
    ]));
    assert!(pdf_has(&chunks, "KEYHOG_TEXT_BEFORE_IMAGE_1234567890"));
    assert!(!any_has(&chunks, "KEYHOG_IMG_TRAILING_BLOB_5555555555"));
}

#[test]
fn pdf_two_text_streams_both_secrets_extracted() {
    let chunks = scan_clean(pdf_streams(&[
        ("", b"BT (KEYHOG_STREAM_A_SECRET_1234567890) Tj ET"),
        ("", b"BT (KEYHOG_STREAM_B_SECRET_0987654321) Tj ET"),
    ]));
    assert!(pdf_has(&chunks, "KEYHOG_STREAM_A_SECRET_1234567890"));
    assert!(pdf_has(&chunks, "KEYHOG_STREAM_B_SECRET_0987654321"));
}

// ── Keyword-boundary: "stream" as a substring is not the keyword ─────────────

#[test]
fn pdf_name_with_stream_substring_not_parsed_as_stream() {
    // `/Substream` contains "stream" preceded by a name byte, so it must NOT be
    // treated as a content-stream keyword — no bogus missing-endstream gap, and
    // the co-located metadata secret still extracts cleanly.
    let chunks = scan_clean(pdf_with_body(
        "3 0 obj\n<< /Producer (KEYHOG_KWB_SUBSTREAM_SECRET_1234567890) /Kind /Substream >>\nendobj\n",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_KWB_SUBSTREAM_SECRET_1234567890"),
        "a name containing 'stream' must not derail metadata extraction; got {chunks:?}"
    );
}

#[test]
fn pdf_literal_with_stream_word_inside_not_parsed_as_stream() {
    // The word "stream" inside a literal string is data, not the keyword.
    let chunks = scan_clean(pdf_with_info_dict(
        "/Title (mainstream config KEYHOG_KWB_WORD_SECRET_1234567890)",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_KWB_WORD_SECRET_1234567890"),
        "the word 'stream' inside a literal must not be a keyword; got {chunks:?}"
    );
}

// ── stream_body_start: the EOL after `stream` is consumed exactly ────────────

#[test]
fn pdf_stream_body_start_crlf_keeps_first_byte() {
    let chunks = scan_clean(pdf_stream_with_eol(
        b"\r\n",
        b"BT (KEYHOG_CRLF_FIRSTBYTE_SECRET_1234567890) Tj ET",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_CRLF_FIRSTBYTE_SECRET_1234567890"),
        "CRLF after `stream` must not drop the first body byte; got {chunks:?}"
    );
}

#[test]
fn pdf_stream_body_start_lf_keeps_first_byte() {
    let chunks = scan_clean(pdf_stream_with_eol(
        b"\n",
        b"BT (KEYHOG_LF_FIRSTBYTE_SECRET_1234567890) Tj ET",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_LF_FIRSTBYTE_SECRET_1234567890"));
}

#[test]
fn pdf_stream_body_start_cr_only_keeps_first_byte() {
    // A bare CR (no LF) after `stream` is a single-byte EOL.
    let chunks = scan_clean(pdf_stream_with_eol(
        b"\r",
        b"BT (KEYHOG_CR_ONLY_FIRSTBYTE_SECRET_1234567890) Tj ET",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_CR_ONLY_FIRSTBYTE_SECRET_1234567890"),
        "bare CR after `stream` must consume exactly one byte; got {chunks:?}"
    );
}

// ── Law 10: undecodable filter chains + encryption are LOUD, not silent ──────

#[test]
fn pdf_multi_filter_array_flate_plus_other_surfaces_loud_gap() {
    // `/Filter [/ASCII85Decode /FlateDecode]` on bytes that are not raw zlib:
    // we cannot run the ASCII85 stage, so inflate fails. That MUST surface as a
    // gap, never be silently dropped.
    let (_chunks, errors) = scan_rows(minimal_pdf(
        " /Filter [/ASCII85Decode /FlateDecode]",
        b"<~9jqo^Znot-actually-a-flate-stream~>",
    ));
    assert_eq!(
        errors.len(),
        1,
        "an undecodable multi-filter chain must surface exactly one gap, got {errors:?}"
    );
    assert!(
        errors[0].contains("stream decode failed before producing text")
            && errors[0].contains("affected PDF bytes were not scanned"),
        "the multi-filter gap must name the unscanned coverage, got {}",
        errors[0]
    );
}

#[test]
fn pdf_encrypted_still_extracts_outside_stream_metadata_and_flags_gap() {
    // Encryption flags a coverage gap, but the still-readable outside-stream
    // metadata literal must ALSO be extracted (recall is not suppressed by the
    // flag), and the gap must still be surfaced.
    let (chunks, errors) = scan_rows(pdf_with_body(
        "3 0 obj\n<< /Author (KEYHOG_ENC_META_STILL_READ_1234567890) /Encrypt 5 0 R >>\nendobj\n",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_ENC_META_STILL_READ_1234567890"),
        "readable metadata in an encrypted PDF must still extract; got {chunks:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("encrypted PDF")),
        "the encryption coverage gap must still be surfaced, got {errors:?}"
    );
}

// ── parse_octal_escape boundaries (via metadata literal strings) ─────────────

#[test]
fn pdf_octal_escape_single_digit_decodes() {
    // `\7` is a one-digit octal escape (0x07 BEL); it must consume exactly one
    // digit, leaving the following text intact.
    let chunks = scan_clean(pdf_with_info_dict("/Author (KEYHOG_OCT1\\7END_TAIL1234)"));
    assert!(
        pdf_has(&chunks, "KEYHOG_OCT1") && pdf_has(&chunks, "END_TAIL1234"),
        "one-digit octal must consume only '7' and keep the tail; got {chunks:?}"
    );
}

#[test]
fn pdf_octal_escape_two_digit_decodes() {
    // `\52` is octal 42 = 0x2A = '*'.
    let chunks = scan_clean(pdf_with_info_dict("/Author (KEYHOG_OCT2\\52X_TAIL1234)"));
    assert!(
        pdf_has(&chunks, "KEYHOG_OCT2*X_TAIL1234"),
        "two-digit octal \\52 must decode to '*'; got {chunks:?}"
    );
}

#[test]
fn pdf_octal_escape_overflow_wraps_mod_256() {
    // `\777` = 0o777 = 511; the high bits are dropped (& 0xff = 0xFF). The
    // surrounding ASCII must survive the (lossy) byte.
    let chunks = scan_clean(pdf_with_info_dict("/Author (KEYHOG_OVF\\777TAIL1234)"));
    assert!(
        pdf_has(&chunks, "KEYHOG_OVF") && pdf_has(&chunks, "TAIL1234"),
        "octal overflow must wrap mod 256 without eating neighbours; got {chunks:?}"
    );
}

#[test]
fn pdf_octal_escape_null_byte_preserves_surrounding_text() {
    // `\000` is a NUL; both halves of the value must remain scannable.
    let chunks = scan_clean(pdf_with_info_dict("/Author (KEYHOG_NUL\\000TAIL1234)"));
    assert!(
        pdf_has(&chunks, "KEYHOG_NUL") && pdf_has(&chunks, "TAIL1234"),
        "a NUL octal escape must not truncate the value; got {chunks:?}"
    );
}

// ── parse_hex_string boundaries ──────────────────────────────────────────────

#[test]
fn pdf_hex_string_empty_angles_dropped_keeps_valid() {
    let chunks = scan_clean(pdf_with_info_dict(
        "/Title <> /Author (KEYHOG_HEXEMPTY_VALID_1234567890)",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_HEXEMPTY_VALID_1234567890"),
        "an empty <> hex string must be a no-op, not derail the valid one; got {chunks:?}"
    );
}

#[test]
fn pdf_hex_string_invalid_nibble_skipped_keeps_valid() {
    // `<ZZZZ>` has no valid hex nibble; it is skipped and the valid metadata
    // after it still extracts.
    let chunks = scan_clean(pdf_with_info_dict(
        "/Title <ZZZZ> /Author (KEYHOG_HEXBAD_VALID_1234567890)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_HEXBAD_VALID_1234567890"));
    assert!(
        !any_has(&chunks, "ZZZZ"),
        "invalid hex nibbles must not leak the raw <ZZZZ>; got {chunks:?}"
    );
}

#[test]
fn pdf_hex_string_newline_between_nibbles_decodes() {
    // Interior newline (not just space) is hex whitespace and must be ignored.
    // `4b45594841434b` = "KEYHACK".
    let chunks = scan_clean(pdf_with_info_dict("/Author <4b4559\n4841434b>"));
    assert!(
        pdf_has(&chunks, "KEYHACK"),
        "a newline between hex nibbles must be ignored; got {chunks:?}"
    );
}

// ── Literal-string + min-length boundaries ───────────────────────────────────

#[test]
fn pdf_empty_literal_string_dropped_keeps_valid() {
    let chunks = scan_clean(pdf_with_info_dict(
        "/Title () /Author (KEYHOG_EMPTYLIT_VALID_1234567890)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_EMPTYLIT_VALID_1234567890"));
}

#[test]
fn pdf_exactly_min_len_four_char_string_extracted() {
    // MIN_PDF_TEXT_LEN is 4: a 4-char alphanumeric value is exactly at the
    // boundary and must be kept (the `< 4` guard is strict).
    let chunks = scan_clean(pdf_with_info_dict("/Author (Ab12)"));
    assert!(
        any_has(&chunks, "Ab12"),
        "a value of exactly MIN_PDF_TEXT_LEN must be extracted; got {chunks:?}"
    );
}

#[test]
fn pdf_literal_string_nested_two_levels_not_truncated() {
    // Two levels of balanced parens must round-trip whole.
    let chunks = scan_clean(pdf_with_info_dict(
        "/Author (a(b(c)d)e_KEYHOG_NEST2_1234567890)",
    ));
    assert!(
        pdf_has(&chunks, "a(b(c)d)e_KEYHOG_NEST2_1234567890"),
        "two-level nested parens must not truncate; got {chunks:?}"
    );
}

#[test]
fn pdf_literal_string_backslash_r_and_t_control_escapes() {
    // `\r` -> CR and `\t` -> TAB; both halves around each control survive.
    let cr = scan_clean(pdf_with_info_dict("/Author (KEYHOG_CR\\rTAIL1234)"));
    assert!(
        pdf_has(&cr, "KEYHOG_CR") && pdf_has(&cr, "TAIL1234"),
        "\\r escape must not truncate; got {cr:?}"
    );
    let tab = scan_clean(pdf_with_info_dict("/Author (KEYHOG_TAB\\tTAIL5678)"));
    assert!(
        pdf_has(&tab, "KEYHOG_TAB") && pdf_has(&tab, "TAIL5678"),
        "\\t escape must not truncate; got {tab:?}"
    );
}
