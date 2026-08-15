//! Unit tests for backend chunk preparation and SIMD compile plans.

use crate::engine::backend::prepared::*;
#[cfg(feature = "simd")]
use crate::engine::build_simd_compile_plan;
#[cfg(feature = "simd")]
use crate::types::{CompiledPattern, LazyRegex};
use keyhog_core::Chunk;
use std::sync::{Arc, OnceLock};

/// WHY: line context must use the rewritten preprocessed bytes whose offsets
/// locate matches, never the differently shaped raw chunk.
#[test]
fn line_index_follows_preprocessed_text_not_raw_chunk_when_bytes_differ() {
    let raw = "AAAAAA\nBBBBBB\nCCCCCC";
    let preprocessed_text = "xxx\nyyy\nzzz";
    let chunk: Chunk = raw.to_string().into();
    let prepared = PreparedChunk {
        chunk: &chunk,
        preprocessed: crate::types::ScannerPreprocessedText::passthrough(preprocessed_text),
        line_index: OnceLock::<Arc<_>>::new(),
        #[cfg(debug_assertions)]
        line_index_scanned_bytes: None,
    };

    let lines: Vec<_> = prepared
        .line_index()
        .lines(&prepared.preprocessed.text)
        .collect();
    assert_eq!(lines, ["xxx", "yyy", "zzz"]);
    assert!(!lines.iter().any(|line| line.starts_with('A')));
    assert_eq!(prepared.line_index().line_number_for_offset(5), 2);
}

#[test]
fn passthrough_lines_are_sliced_on_demand() {
    let text = "key = one\nother = two\nlast = three";
    let chunk: Chunk = text.to_string().into();
    let prepared = PreparedChunk {
        chunk: &chunk,
        preprocessed: crate::types::ScannerPreprocessedText::passthrough(text),
        line_index: OnceLock::<Arc<_>>::new(),
        #[cfg(debug_assertions)]
        line_index_scanned_bytes: None,
    };
    assert_eq!(
        prepared
            .line_index()
            .lines(&prepared.preprocessed.text)
            .collect::<Vec<_>>(),
        ["key = one", "other = two", "last = three"]
    );
}

#[cfg(feature = "simd")]
fn pattern(regex: &str) -> CompiledPattern {
    CompiledPattern {
        detector_index: 0,
        pattern_index: 0,
        regex: LazyRegex::detector(regex),
        group: None,
        client_safe: false,
        weak_anchor: false,
        structural_password_slot: false,
        match_proves_keyword_nearby: false,
        allows_repeated_keyword_separator: false,
        homoglyph_variant: false,
    }
}

/// WHY: copying every canonical literal into the lazy SIMD plan doubled the complete literal table until first backend use.
#[cfg(feature = "simd")]
#[test]
fn simd_compile_plan_shares_the_canonical_literal_table() {
    let literals: std::sync::Arc<[String]> = vec!["STATIC_SECRET_".to_owned()].into();
    let plan = build_simd_compile_plan(
        &[pattern(r"STATIC_SECRET_[A-Z0-9]{16}")],
        std::sync::Arc::clone(&literals),
        &crate::scanner_config::ScannerTuningConfig::default(),
    )
    .expect("fixture produces a SIMD plan");

    assert!(
        std::sync::Arc::ptr_eq(&plan.ac_literals, &literals),
        "SIMD plan must share the canonical literal allocation"
    );
}
