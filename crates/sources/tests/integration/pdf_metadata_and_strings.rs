//! Recall + coherence: a PDF carries secrets in TWO places the content-stream
//! fixtures never reach
//!   1. **Document metadata** (the Info dictionary: `/Author`, `/Title`,
//!      `/Keywords`, `/Producer`, `/Subject`) rendered as literal `(...)` or hex
//!      `<...>` strings OUTSIDE any stream. A credential pasted into a
//!      document's properties is a real leak, and #119 claims "embedded text +
//!      metadata" (these tests prove the metadata half).
//!   2. The literal/hex **string parser** primitives that back that extraction
//!      (`parse_literal_string`, `parse_octal_escape`, `parse_hex_string`).
//!      PDF strings are a classic parsing-hazard surface: balanced UNescaped
//!      parens, `\(`/`\)`/`\\` escapes, `\ddd` octal escapes, line
//!      continuations, hex whitespace and odd-nibble padding. A naive
//!      "find the first `)`" scan truncates a secret at the first inner paren.
//!
//! Every test asserts the real credential bytes surface in a `filesystem/pdf`
//! chunk (Law 6: assert the credential, never `!is_empty`).

use crate::support::pdf::{pdf_with_body, pdf_with_info_dict};
use crate::support::split_chunk_results;
use keyhog_core::{Chunk, Source};
use keyhog_sources::FilesystemSource;

fn scan_pdf(bytes: Vec<u8>) -> Vec<Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("document.pdf");
    std::fs::write(&path, bytes).expect("write pdf");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid PDF fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks.into_iter().cloned().collect()
}

/// True when a `filesystem/pdf` chunk carries `marker`.
fn pdf_has(chunks: &[Chunk], marker: &str) -> bool {
    chunks
        .iter()
        .any(|c| c.metadata.source_type.as_ref() == "filesystem/pdf" && c.data.contains(marker))
}

/// True when ANY emitted chunk (pdf or fallback) carries `marker`: used to
/// prove a dropped string is dropped everywhere, not merely off the pdf path.
fn any_chunk_has(chunks: &[Chunk], marker: &str) -> bool {
    chunks.iter().any(|c| c.data.contains(marker))
}

// ── Info-dictionary metadata fields (literal strings outside streams) ────────

#[test]
fn pdf_author_metadata_is_extracted() {
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author (KEYHOG_PDF_AUTHOR_SECRET_1234567890)",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_PDF_AUTHOR_SECRET_1234567890"),
        "a secret in the /Author metadata field must be extracted; got {chunks:?}"
    );
}

#[test]
fn pdf_title_metadata_is_extracted() {
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Title (KEYHOG_PDF_TITLE_SECRET_1234567890)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_PDF_TITLE_SECRET_1234567890"));
}

#[test]
fn pdf_keywords_metadata_is_extracted() {
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Keywords (KEYHOG_PDF_KEYWORDS_SECRET_1234567890)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_PDF_KEYWORDS_SECRET_1234567890"));
}

#[test]
fn pdf_producer_metadata_is_extracted() {
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Producer (KEYHOG_PDF_PRODUCER_SECRET_1234567890)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_PDF_PRODUCER_SECRET_1234567890"));
}

#[test]
fn pdf_subject_metadata_is_extracted() {
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Subject (KEYHOG_PDF_SUBJECT_SECRET_1234567890)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_PDF_SUBJECT_SECRET_1234567890"));
}

#[test]
fn pdf_multiple_metadata_fields_all_extracted() {
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author (KEYHOG_MULTI_AUTHOR_1234) /Title (KEYHOG_MULTI_TITLE_1234) /Keywords (KEYHOG_MULTI_KEYS_1234)",
    ));
    for marker in [
        "KEYHOG_MULTI_AUTHOR_1234",
        "KEYHOG_MULTI_TITLE_1234",
        "KEYHOG_MULTI_KEYS_1234",
    ] {
        assert!(
            pdf_has(&chunks, marker),
            "metadata field {marker} must be extracted"
        );
    }
}

#[test]
fn pdf_hex_string_metadata_is_decoded() {
    // /Author <hex>: "KEYHOG_HEX_META" as a hex-encoded metadata string.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author <4b4559484f475f4845585f4d455441>",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_HEX_META"),
        "a hex-encoded metadata string must be decoded and extracted; got {chunks:?}"
    );
}

// ── Literal-string parser edge cases (the parsing-hazard surface) ────────────

#[test]
fn pdf_literal_string_balanced_parens_not_truncated() {
    // A naive "first `)`" scan truncates at `KEYHOG(inner`. Depth tracking must
    // return the WHOLE value including the text after the inner close paren.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author (KEYHOG(inner)SECRET_1234567890)",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG(inner)SECRET_1234567890"),
        "balanced unescaped parens must not truncate the string; got {chunks:?}"
    );
}

#[test]
fn pdf_literal_string_escaped_close_paren_is_literal() {
    // `\)` is a literal `)`, not a string terminator.
    let chunks = scan_pdf(pdf_with_info_dict("/Author (KEYHOG\\)SECRET_1234567890)"));
    assert!(pdf_has(&chunks, "KEYHOG)SECRET_1234567890"));
}

#[test]
fn pdf_literal_string_escaped_open_paren_is_literal() {
    let chunks = scan_pdf(pdf_with_info_dict("/Author (KEYHOG\\(SECRET_1234567890)"));
    assert!(pdf_has(&chunks, "KEYHOG(SECRET_1234567890"));
}

#[test]
fn pdf_literal_string_escaped_backslash_is_literal() {
    let chunks = scan_pdf(pdf_with_info_dict("/Author (KEYHOG\\\\SECRET_1234567890)"));
    assert!(pdf_has(&chunks, "KEYHOG\\SECRET_1234567890"));
}

#[test]
fn pdf_literal_string_octal_escape_decodes_byte() {
    // `\101` is octal for 0x41 = 'A' -> "KEYHOGASECRET_1234".
    let chunks = scan_pdf(pdf_with_info_dict("/Author (KEYHOG\\101SECRET_1234)"));
    assert!(
        pdf_has(&chunks, "KEYHOGASECRET_1234"),
        "octal escape \\101 must decode to 'A'; got {chunks:?}"
    );
}

#[test]
fn pdf_literal_string_backslash_n_splits_but_keeps_both_halves() {
    // `\n` -> newline; both halves of the value remain in the extracted text.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author (KEYHOG_HALF_ONE_1234\\nKEYHOG_HALF_TWO_5678)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_HALF_ONE_1234"));
    assert!(pdf_has(&chunks, "KEYHOG_HALF_TWO_5678"));
}

#[test]
fn pdf_literal_string_line_continuation_joins_halves() {
    // A backslash immediately before a real newline is a line continuation:
    // the two source lines join with NOTHING between them.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author (KEYHOG_LONG_\\\nSECRET_VALUE_1234)",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_LONG_SECRET_VALUE_1234"),
        "line continuation must join the halves without a gap; got {chunks:?}"
    );
}

// ── Hex-string parser edge cases ─────────────────────────────────────────────

#[test]
fn pdf_hex_string_with_embedded_whitespace_decodes() {
    // Whitespace between hex nibbles is ignored per the PDF spec.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author <4b 45 59 48 4f 47 5f 48 45 58 5f 4d 45 54 41>",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_HEX_META"),
        "hex string with embedded whitespace must decode; got {chunks:?}"
    );
}

#[test]
fn pdf_hex_string_odd_nibble_is_zero_padded() {
    // 21 nibbles: the final lone nibble is zero-padded. The stable prefix
    // "KEYHOG_ODD" must survive unchanged.
    let chunks = scan_pdf(pdf_with_info_dict("/Author <4b4559484f475f4f44443>"));
    assert!(
        pdf_has(&chunks, "KEYHOG_ODD"),
        "odd-nibble hex must zero-pad the tail and keep the prefix; got {chunks:?}"
    );
}

#[test]
fn pdf_hex_string_mixed_case_nibbles_decode() {
    let chunks = scan_pdf(pdf_with_info_dict("/Author <4B4559484F475F4d4958>"));
    assert!(pdf_has(&chunks, "KEYHOG_MIX"));
}

// ── Negatives: strings that must be dropped ──────────────────────────────────

#[test]
fn pdf_short_string_below_min_len_is_dropped() {
    // "Zqx" (3 bytes) is below MIN_PDF_TEXT_LEN; the long value proves the scan
    // still ran and the short one was specifically dropped.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Title (Zqx) /Author (KEYHOG_LONG_VALID_1234)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_LONG_VALID_1234"));
    assert!(
        !any_chunk_has(&chunks, "Zqx"),
        "a sub-minimum-length string must not be extracted"
    );
}

#[test]
fn pdf_string_without_alphanumeric_is_dropped() {
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Title (--------) /Author (KEYHOG_ALNUM_VALID_1234)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_ALNUM_VALID_1234"));
    assert!(
        !any_chunk_has(&chunks, "--------"),
        "a string with no alphanumeric byte must not be extracted"
    );
}

// ── Robustness ───────────────────────────────────────────────────────────────

#[test]
fn pdf_dict_open_double_angle_not_treated_as_hex_string() {
    // `<<` opens a dictionary, not a hex string, it must be skipped, and a
    // co-located hex-string secret still extracted, with no error row.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Type /Metadata /Author <4b4559484f475f4845585f4d455441>",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_HEX_META"));
}

#[test]
fn pdf_trailing_unterminated_string_keeps_prior_valid() {
    // A trailing unterminated `(` with no closing `)` anywhere must not panic
    // or discard the valid metadata extracted before it.
    let chunks = scan_pdf(pdf_with_body(
        "3 0 obj\n<< /Title (KEYHOG_VALID_BEFORE_1234) /Author (KEYHOG_UNTERMINATED_NO_CLOSE\nendobj\n",
    ));
    assert!(
        pdf_has(&chunks, "KEYHOG_VALID_BEFORE_1234"),
        "a valid metadata string before an unterminated one must still be extracted; got {chunks:?}"
    );
}

#[test]
fn pdf_metadata_chunk_is_tagged_filesystem_pdf() {
    // Provenance: a metadata-only PDF still emits the dedicated `filesystem/pdf`
    // source type, never the plain-text `filesystem` decoder.
    let chunks = scan_pdf(pdf_with_info_dict(
        "/Author (KEYHOG_PROVENANCE_SECRET_1234)",
    ));
    assert!(pdf_has(&chunks, "KEYHOG_PROVENANCE_SECRET_1234"));
    assert!(
        chunks
            .iter()
            .all(|c| c.metadata.source_type.as_ref() != "filesystem"),
        "PDF metadata bytes must not be decoded as a plain filesystem text file"
    );
}
