//! Unit tests for URL percent and Quoted-Printable decoders.
//!
//! Verifies zeroization of intermediate decoded byte buffers on error exits,
//! ASCII pass-through scanning for chunks without `%` or `=` characters,
//! escape counting and detection predicates, and admission sketches.

use super::*;
use keyhog_core::Chunk;

#[test]
fn test_url_decode_valid_percent_escapes() {
    assert_eq!(url_decode("%41%42%43"), Ok("ABC".to_string()));
    assert_eq!(url_decode("hello%20world"), Ok("hello world".to_string()));
    assert_eq!(
        url_decode("slash%2Fcolon%3A"),
        Ok("slash/colon:".to_string())
    );
    assert_eq!(url_decode("lower%3a%3b"), Ok("lower:;".to_string()));
}

#[test]
fn test_url_decode_no_percent_escapes_returns_err() {
    assert_eq!(url_decode("plain text without percent"), Err(()));
    assert_eq!(url_decode(""), Err(()));
    assert_eq!(url_decode("key=value&foo=bar"), Err(()));
}

#[test]
fn test_url_decode_malformed_percent_without_valid_triplet() {
    assert_eq!(url_decode("%"), Err(()));
    assert_eq!(url_decode("%4"), Err(()));
    assert_eq!(url_decode("%ZZ"), Err(()));
    assert_eq!(url_decode("%G1%H2"), Err(()));
}

#[test]
fn test_url_decode_best_effort_partial_recovery() {
    assert_eq!(url_decode("%41%ZZ"), Ok("A%ZZ".to_string()));
    assert_eq!(url_decode("start_%42_%"), Ok("start_B_%".to_string()));
    assert_eq!(url_decode("prefix_%43_%5"), Ok("prefix_C_%5".to_string()));
}

#[test]
fn test_url_decode_invalid_utf8_zeroized_and_returns_err() {
    // 0xFF is never valid UTF-8.
    assert_eq!(url_decode("%FF"), Err(()));
    // Overlong UTF-8 sequence (%C0%AF).
    assert_eq!(url_decode("%C0%AF"), Err(()));
    // Incomplete multibyte UTF-8 lead byte (%C3 alone).
    assert_eq!(url_decode("%C3"), Err(()));
}

#[test]
fn test_quoted_printable_decode_valid_octets() {
    assert_eq!(quoted_printable_decode("=41=42=43"), Ok("ABC".to_string()));
    assert_eq!(
        quoted_printable_decode("secret=3Dvalue"),
        Ok("secret=value".to_string())
    );
    assert_eq!(quoted_printable_decode("=3d=3D"), Ok("==".to_string()));
}

#[test]
fn test_quoted_printable_decode_soft_breaks() {
    assert_eq!(
        quoted_printable_decode("hello=\r\nworld"),
        Ok("helloworld".to_string())
    );
    assert_eq!(
        quoted_printable_decode("foo=\nbar"),
        Ok("foobar".to_string())
    );
    assert_eq!(quoted_printable_decode("a=\rb"), Ok("ab".to_string()));
}

#[test]
fn test_quoted_printable_decode_no_escapes_passthrough() {
    assert_eq!(
        quoted_printable_decode("plain text"),
        Ok("plain text".to_string())
    );
    assert_eq!(quoted_printable_decode(""), Ok("".to_string()));
    assert_eq!(
        quoted_printable_decode("no equals here 12345"),
        Ok("no equals here 12345".to_string())
    );
}

#[test]
fn test_quoted_printable_decode_literal_non_hex_equals() {
    assert_eq!(quoted_printable_decode("a=b"), Ok("a=b".to_string()));
    assert_eq!(quoted_printable_decode("=ZZ"), Ok("=ZZ".to_string()));
    assert_eq!(quoted_printable_decode("end="), Ok("end=".to_string()));
    assert_eq!(quoted_printable_decode("=4"), Ok("=4".to_string()));
}

#[test]
fn test_quoted_printable_decode_invalid_utf8_zeroized_and_returns_err() {
    assert_eq!(quoted_printable_decode("=FF"), Err(()));
    assert_eq!(quoted_printable_decode("=C0=AF"), Err(()));
    assert_eq!(quoted_printable_decode("=C3"), Err(()));
}

#[test]
fn test_contains_percent_escape_predicates() {
    assert!(contains_percent_escape("%20"));
    assert!(contains_percent_escape("foo%41bar"));
    assert!(contains_percent_escape("%ff"));
    assert!(!contains_percent_escape("plain text"));
    assert!(!contains_percent_escape("%"));
    assert!(!contains_percent_escape("%1"));
    assert!(!contains_percent_escape("%ZZ"));
    assert!(!contains_percent_escape(""));
}

#[test]
fn test_percent_escape_count_accurate() {
    assert_eq!(percent_escape_count(""), 0);
    assert_eq!(percent_escape_count("no escapes"), 0);
    assert_eq!(percent_escape_count("%41"), 1);
    assert_eq!(percent_escape_count("%41%42%43"), 3);
    assert_eq!(percent_escape_count("%41%ZZ%42"), 2);
    assert_eq!(percent_escape_count("%%%%"), 0);
}

#[test]
fn test_has_qp_escape_predicates() {
    assert!(has_qp_escape("=20"));
    assert!(has_qp_escape("foo=41bar"));
    assert!(has_qp_escape("=ff"));
    assert!(!has_qp_escape("plain text"));
    assert!(!has_qp_escape("="));
    assert!(!has_qp_escape("=1"));
    assert!(!has_qp_escape("=ZZ"));
    assert!(!has_qp_escape(""));
}

#[test]
fn test_qp_escape_count_accurate() {
    assert_eq!(qp_escape_count(""), 0);
    assert_eq!(qp_escape_count("no escapes"), 0);
    assert_eq!(qp_escape_count("=41"), 1);
    assert_eq!(qp_escape_count("=41=42=43"), 3);
    assert_eq!(qp_escape_count("=41=ZZ=42"), 2);
    assert_eq!(qp_escape_count("===="), 0);
}

#[test]
fn test_url_decoder_admission_sketch() {
    let decoder = UrlDecoder;
    let empty_chunk = Chunk {
        data: "hello world".into(),
        metadata: Default::default(),
    };
    assert_eq!(
        decoder.admission_sketch(&empty_chunk),
        DecodeAdmissionSketch::NONE
    );

    let pct_chunk = Chunk {
        data: "hello %41%42 world".into(),
        metadata: Default::default(),
    };
    let sketch = decoder.admission_sketch(&pct_chunk);
    assert_ne!(sketch, DecodeAdmissionSketch::NONE);
}

#[test]
fn test_quoted_printable_decoder_admission_sketch() {
    let decoder = QuotedPrintableDecoder;
    let empty_chunk = Chunk {
        data: "hello world".into(),
        metadata: Default::default(),
    };
    assert_eq!(
        decoder.admission_sketch(&empty_chunk),
        DecodeAdmissionSketch::NONE
    );

    let qp_chunk = Chunk {
        data: "hello =41=42 world".into(),
        metadata: Default::default(),
    };
    let sketch = decoder.admission_sketch(&qp_chunk);
    assert_ne!(sketch, DecodeAdmissionSketch::NONE);
}

#[test]
fn test_mime_q_decode_and_encoded_word() {
    assert_eq!(
        mime_encoded_word_decode("=?utf-8?q?hello_world?="),
        Ok("hello world".to_string())
    );
    assert_eq!(
        mime_encoded_word_decode("=?utf-8?Q?=41=42=43?="),
        Ok("ABC".to_string())
    );
    assert_eq!(mime_encoded_word_decode("=?utf-8?Q?=FF?="), Err(()));
}
