use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, SensitiveString, Severity};
use keyhog_scanner::decode::Decoder;
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::testing::register_thread_decoder;
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::sync::Arc;

const REVERSED_EXAMPLE_CREDENTIAL: &str = "321_TERCES_ELPMAXE_terceSedoceD";

struct ReversePlaceholderDecoder;

impl Decoder for ReversePlaceholderDecoder {
    fn name(&self) -> &'static str {
        "postprocess_reverse_placeholder"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        if chunk.metadata.source_type.contains("postprocess-reverse") {
            return Vec::new();
        }

        vec![Chunk {
            data: SensitiveString::from(format!("decoded = \"{REVERSED_EXAMPLE_CREDENTIAL}\"")),
            metadata: ChunkMetadata {
                source_type: format!("{}/postprocess-reverse/reverse", chunk.metadata.source_type)
                    .into(),
                path: chunk.metadata.path.clone(),
                ..Default::default()
            },
        }]
    }
}

fn detector() -> DetectorSpec {
    DetectorSpec {
        id: "postprocess-reverse-placeholder".into(),
        name: "Postprocess Reverse Placeholder".into(),
        service: "unit".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: format!("({})", regex::escape(REVERSED_EXAMPLE_CREDENTIAL)),
            description: Some("reverse placeholder fixture".into()),
            group: Some(1),
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
        }],
        keywords: vec!["ELPMAXE".into()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn root_chunk() -> Chunk {
    Chunk {
        data: SensitiveString::from("ordinary text that only the custom decoder can expand"),
        metadata: ChunkMetadata {
            path: Some("reverse-placeholder.txt".into()),
            ..Default::default()
        },
    }
}

#[test]
fn decoded_reverse_placeholder_drop_records_adjudicator_example_suppression() {
    let _telemetry_guard = super::super::telemetry_serial::lock();
    telemetry::testing::reset();
    let _decoder_guard = register_thread_decoder(Box::new(ReversePlaceholderDecoder));

    let mut config = ScannerConfig::default();
    config.max_decode_depth = 1;
    config.min_confidence = 0.0;
    let scanner = CompiledScanner::compile(vec![detector()])
        .expect("fixture detector compiles")
        .with_config(config);

    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let matches = telemetry::with_scan_telemetry(&trace, || scanner.scan(&root_chunk()));
    assert!(
        matches.is_empty(),
        "reverse-decoded documentation placeholder must be suppressed, got {matches:?}"
    );

    let events = trace.drain().dogfood_events;
    assert!(
        events.iter().any(|event| matches!(
            event,
            DogfoodEvent::ExampleSuppressed {
                detector,
                path: Some(path),
                reason,
                ..
            } if detector == "postprocess-reverse-placeholder"
                && path == "reverse-placeholder.txt"
                && reason.as_ref() == "decoded_reverse_placeholder"
        )),
        "decoded reverse placeholder drop must be visible through adjudicator example telemetry, got {events:?}"
    );
}
