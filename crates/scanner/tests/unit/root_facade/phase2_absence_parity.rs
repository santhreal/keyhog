use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

const SECRET: &str = "UNSCOPED_ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEF";

fn detector() -> DetectorSpec {
    DetectorSpec {
        id: "dense-prefixless".into(),
        name: "Dense prefixless".into(),
        service: "test".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: r"UNSCOPED_[A-Z]{32}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        keywords: Vec::new(),
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn ordered_detector() -> DetectorSpec {
    let mut detector = detector();
    detector.id = "ordered-prefixless".into();
    detector.name = "Ordered prefixless".into();
    detector.patterns[0].regex = r"PREFIX\nUNSCOPED_[A-Z]{32}".into();
    detector
}

fn repeated_detector() -> DetectorSpec {
    let mut detector = detector();
    detector.id = "repeated-prefixless".into();
    detector.name = "Repeated prefixless".into();
    detector.patterns[0].regex = r"PREFIX\nPREFIX\nUNSCOPED_[A-Z]{32}".into();
    detector
}

fn chunk(text: String) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem/windowed".into(),
            path: Some("dense.txt".into()),
            ..Default::default()
        },
    }
}

#[test]
fn dense_markerless_input_preserves_prefixless_findings() {
    let mut text = "a".repeat(64 * 1024);
    text.push_str(SECRET);
    let scanner = CompiledScanner::compile(vec![detector()]).expect("compile detector");

    let matches = scanner
        .scan_chunks_with_backend(&[chunk(text)], ScanBackend::CpuFallback)
        .expect("scan dense markerless input");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].len(), 1);
    assert_eq!(matches[0][0].detector_id.as_ref(), "dense-prefixless");
    assert_eq!(matches[0][0].credential.as_ref(), SECRET);
}

#[cfg(feature = "decode")]
#[test]
fn dense_markerless_input_preserves_decoded_findings() {
    use base64::Engine as _;

    let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(SECRET);
    assert!(!encoded
        .bytes()
        .any(|byte| matches!(byte, b'+' | b'/' | b'=')));
    let text = format!("{} {encoded} {}", "a".repeat(64 * 1024), "b".repeat(64));
    let scanner = CompiledScanner::compile(vec![detector()]).expect("compile detector");

    let matches = scanner
        .scan_chunks_with_backend(&[chunk(text)], ScanBackend::CpuFallback)
        .expect("scan dense markerless encoded input");

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].len(), 1);
    assert_eq!(matches[0][0].detector_id.as_ref(), "dense-prefixless");
    assert_eq!(matches[0][0].credential.as_ref(), SECRET);
}

#[test]
fn absence_cache_preserves_line_order() {
    let scanner = CompiledScanner::compile(vec![ordered_detector()]).expect("compile detector");
    let clean = format!("{SECRET}\nPREFIX");
    let matching = format!("PREFIX\n{SECRET}");

    let first = scanner
        .scan_chunks_with_backend(&[chunk(clean)], ScanBackend::CpuFallback)
        .expect("scan clean window");
    assert!(first[0].is_empty());

    let second = scanner
        .scan_chunks_with_backend(&[chunk(matching)], ScanBackend::CpuFallback)
        .expect("scan reordered window");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].len(), 1);
    assert_eq!(second[0][0].detector_id.as_ref(), "ordered-prefixless");
}

#[test]
fn absence_cache_preserves_line_multiplicity() {
    let scanner = CompiledScanner::compile(vec![repeated_detector()]).expect("compile detector");
    let clean = format!("PREFIX\n{SECRET}");
    let matching = format!("PREFIX\nPREFIX\n{SECRET}");

    let first = scanner
        .scan_chunks_with_backend(&[chunk(clean)], ScanBackend::CpuFallback)
        .expect("scan clean window");
    assert!(first[0].is_empty());

    let second = scanner
        .scan_chunks_with_backend(&[chunk(matching)], ScanBackend::CpuFallback)
        .expect("scan repeated-line window");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].len(), 1);
    assert_eq!(second[0][0].detector_id.as_ref(), "repeated-prefixless");
}
