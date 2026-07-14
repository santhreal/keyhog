use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};

fn source_chunk(value: &str) -> Chunk {
    Chunk {
        data: format!("const TABLE_VALUE: &str = \"{value}\";\n").into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("recovery_fixture.rs".into()),
            ..Default::default()
        },
    }
}

fn scanner(config: ScannerConfig) -> CompiledScanner {
    let detectors =
        keyhog_core::load_embedded_detectors_or_fail().expect("load the embedded detector corpus");
    CompiledScanner::compile(detectors)
        .expect("compile the embedded detector corpus")
        .with_config(config)
}

#[test]
fn deep_recovers_unanchored_source_entropy_that_default_excludes() {
    let value = "q4S3#lg7pKEmNkfQOjoUHcd%yzTF^56*iLt-$RAw0xhX_8Pu2s@YeZ+.GM1Vvarn";
    let input = source_chunk(value);

    let default_matches = scanner(ScannerConfig::default()).scan(&input);
    assert!(
        default_matches
            .iter()
            .all(|finding| finding.credential.as_ref() != value),
        "the routine preset must keep unanchored source entropy outside its recovery surface; got {default_matches:?}"
    );

    let deep_config = ScannerConfig::thorough();
    assert_eq!(
        deep_config.max_decode_bytes,
        ScannerConfig::DEEP_MAX_DECODE_BYTES
    );
    assert!(deep_config.entropy_in_source_files);
    assert!(deep_config.scan_comments);

    let deep_matches = scanner(deep_config).scan(&input);
    assert!(
        deep_matches.iter().any(|finding| {
            finding.credential.as_ref() == value
                && finding.detector_id.as_ref().starts_with("entropy-")
        }),
        "deep must recover a high-entropy source value without a keyword anchor; got {deep_matches:?}"
    );
}

#[test]
fn deep_rejects_javascript_xor_index_expression_as_entropy() {
    let input = Chunk {
        data: "const recovered = (() => { const data = [1, 2, 3]; const _a8fe8b046732 = [4, 5, 6]; return String.fromCharCode(...data.map((b, i) => b ^ _a8fe8b046732[i % _a8fe8b046732.length])); })();\n".into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("recovery_fixture.js".into()),
            ..Default::default()
        },
    };

    let matches = scanner(ScannerConfig::thorough()).scan(&input);
    assert!(
        matches
            .iter()
            .all(|finding| finding.credential.as_ref() != "_a8fe8b046732.length]))"),
        "JavaScript array-index syntax must not become an entropy finding: {matches:?}"
    );
}

#[test]
fn deep_rejects_digit_only_javascript_identifier_tail_as_entropy() {
    let input = Chunk {
        data:
            "const recovered = data.map((b, i) => b ^ _715561396085[i % _715561396085.length]));\n"
                .into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("numeric_identifier_recovery.js".into()),
            ..Default::default()
        },
    };

    let matches = scanner(ScannerConfig::thorough()).scan(&input);
    assert!(
        matches
            .iter()
            .all(|finding| finding.credential.as_ref() != "_715561396085.length]))"),
        "a valid underscore-led JavaScript identifier must not become an entropy finding: {matches:?}"
    );
}
