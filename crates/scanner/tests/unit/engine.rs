use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::engine::{
    build_rule_pipeline, floor_char_boundary, line_number_for_offset, next_window_offset,
    window_chunk, window_end_offset, CompiledScanner,
};
use keyhog_scanner::hw_probe::ScanBackend;

fn demo_detector() -> DetectorSpec {
    DetectorSpec {
        id: "demo-token".into(),
        name: "Demo Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abc".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        companions: vec![],
        verify: None,
        keywords: vec!["abc".into()],
        ..Default::default()
    }
}

fn chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata::default(),
    }
}

// ── engine/windowed.rs ──────────────────────────────────────────────

#[test]
fn window_end_offset_stays_on_char_boundary() {
    let text = "αβγ";
    let end = window_end_offset(text, 0, 1);
    assert!(text.is_char_boundary(end));
    assert!(end <= text.len());
}

#[test]
fn window_end_offset_rejects_invalid_start() {
    let text = "hello";
    assert_eq!(window_end_offset(text, text.len(), 10), text.len());
}

#[test]
fn next_window_offset_applies_overlap_without_splitting_chars() {
    let text = "αβγδεζηθικλ";
    let end = window_end_offset(text, 0, 6);
    let next = next_window_offset(text, end, 2);
    assert!(text.is_char_boundary(next));
    assert!(next <= end);
}

#[test]
fn window_chunk_slices_data_and_preserves_metadata() {
    let mut meta = ChunkMetadata::default();
    meta.path = Some("src/main.rs".into());
    let parent = Chunk {
        data: "0123456789".into(),
        metadata: meta.clone(),
    };
    let slice = window_chunk(&parent, 2, 6);
    assert_eq!(slice.data.as_ref(), "2345");
    assert_eq!(slice.metadata.path.as_deref(), Some("src/main.rs"));
}

#[test]
fn floor_char_boundary_never_splits_multibyte_char() {
    let text = "aαb";
    let idx = floor_char_boundary(text, 2);
    assert!(text.is_char_boundary(idx));
    assert_eq!(idx, 1);
}

#[test]
fn line_number_for_offset_counts_newlines() {
    let text = "line1\nline2\nline3";
    assert_eq!(line_number_for_offset(text, 0), 1);
    assert_eq!(line_number_for_offset(text, 6), 2);
    assert_eq!(line_number_for_offset(text, text.len()), 3);
}

// ── engine/mod.rs - compile + rule pipeline ─────────────────────────

#[test]
fn compiled_scanner_compile_happy_path() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let matches = scanner.scan(&chunk("prefix abc suffix"));
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].credential.as_ref(), "abc");
}

#[test]
fn compiled_scanner_compile_rejects_invalid_regex() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = "(unclosed".into();
    assert!(CompiledScanner::compile(vec![detector]).is_err());
}

#[test]
fn build_rule_pipeline_compiles_simple_pattern() {
    let _pipeline = build_rule_pipeline(&["abc"], 1024).unwrap();
}

#[test]
fn build_rule_pipeline_rejects_unsupported_regex_features() {
    // Lookahead is outside the byte-NFA frontend.
    let err = build_rule_pipeline(&["(?=abc)"], 1024).unwrap_err();
    let _ = err.to_string();
}

// ── engine/scan.rs + fallback paths (via scan) ──────────────────────

#[test]
fn scan_empty_chunk_returns_no_matches() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    assert!(scanner.scan(&chunk("")).is_empty());
}

#[test]
fn scan_rejects_cross_chunk_pattern_via_chunks_api() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let chunks = vec![chunk("ab"), chunk("c")];
    let per_chunk = scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback);
    assert!(per_chunk.iter().all(Vec::is_empty));
}

// ── engine/backend.rs ───────────────────────────────────────────────

#[test]
fn backend_scan_with_backend_cpu_fallback_finds_match() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let matches = scanner.scan_with_backend(&chunk("abc token"), ScanBackend::CpuFallback);
    assert_eq!(matches.len(), 1);
}

#[test]
fn backend_scan_with_backend_empty_chunk_returns_empty() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    assert!(scanner
        .scan_with_backend(&chunk(""), ScanBackend::CpuFallback)
        .is_empty());
}

// ── engine/fallback.rs + fallback_entropy.rs + fallback_generic.rs ─

#[test]
fn fallback_pattern_fires_on_keyword_chunk() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"ghp_[A-Za-z0-9]{20,}".into();
    detector.keywords = vec!["ghp_".into()];
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let matches = scanner.scan(&chunk(&format!("export TOKEN={token}")));
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}

#[test]
fn fallback_pattern_skips_plaintext_without_keyword() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"ghp_[A-Za-z0-9]{20,}".into();
    detector.keywords = vec!["ghp_".into()];
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    assert!(scanner.scan(&chunk("the quick brown fox")).is_empty());
}

// ── engine/scan_gpu.rs + hot_patterns.rs (via warm_backend) ─────────

#[test]
fn scan_gpu_warm_backend_cpu_paths_always_succeed() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    assert!(scanner.warm_backend(ScanBackend::CpuFallback));
    assert!(scanner.warm_backend(ScanBackend::SimdCpu));
}

#[test]
fn scan_gpu_megascan_warm_degrades_gracefully_without_gpu() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    // Returns false when no GPU adapter, but must not panic.
    let _ = scanner.warm_backend(ScanBackend::MegaScan);
}

// ── engine/scan_filters.rs (keyword gating via generic assignment) ──

#[test]
fn scan_filters_generic_assignment_requires_secret_keyword() {
    let scanner = CompiledScanner::compile(vec![demo_detector()]).unwrap();
    let matches = scanner.scan(&chunk("username = randomuser1234567890"));
    assert!(matches.is_empty());
}

#[test]
fn scan_filters_generic_assignment_fires_with_secret_keyword() {
    let mut detector = demo_detector();
    detector.patterns[0].regex = r"ghp_[A-Za-z0-9]{20,}".into();
    detector.keywords = vec!["ghp_".into()];
    let scanner = CompiledScanner::compile(vec![detector]).unwrap();
    let token = concat!("gh", "p_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17");
    let matches = scanner.scan(&chunk(&format!("api_key = \"{token}\"")));
    assert!(matches.iter().any(|m| m.credential.as_ref() == token));
}

// ── engine/segment_attribution.rs ───────────────────────────────────
// Covered in segment_attribution.rs unit module.

// ── engine/boundary.rs ──────────────────────────────────────────────
// Covered by inline #[cfg(test)] in boundary.rs (lib tests).
