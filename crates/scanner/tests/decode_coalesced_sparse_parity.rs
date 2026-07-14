//! Sparse decoder admission must have the same recall on scalar CPU and the
//! production coalesced SIMD path.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::{register_decoder, Decoder};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::collections::BTreeSet;
use std::sync::{Once, OnceLock};
use support::paths::detector_dir;

const AWS_ACCESS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
        let mut config = ScannerConfig::default();
        config.penalize_test_paths = false;
        CompiledScanner::compile(detectors)
            .expect("scanner compile")
            .with_config(config)
    })
}

fn chunk(value: &str) -> Chunk {
    Chunk {
        data: format!("token = \"{value}\"").into(),
        metadata: ChunkMetadata {
            source_type: "decode-coalesced-parity".into(),
            path: Some("credentials.env".into()),
            ..Default::default()
        },
    }
}

fn aws_findings(results: &[Vec<keyhog_core::RawMatch>]) -> BTreeSet<(String, String)> {
    results
        .iter()
        .flatten()
        .filter(|finding| finding.detector_id.as_ref() == "aws-access-key")
        .map(|finding| {
            (
                finding.detector_id.as_ref().to_string(),
                finding.credential.as_ref().to_string(),
            )
        })
        .collect()
}

fn assert_scalar_coalesced_parity(label: &str, fixture: Chunk) {
    let scanner = scanner();
    scanner.clear_fragment_cache();
    let scalar =
        scanner.scan_chunks_with_backend(std::slice::from_ref(&fixture), ScanBackend::CpuFallback);
    scanner.clear_fragment_cache();
    let coalesced =
        scanner.scan_coalesced_with_backend(std::slice::from_ref(&fixture), ScanBackend::SimdCpu);

    let scalar = aws_findings(&scalar);
    let coalesced = aws_findings(&coalesced);
    assert!(
        scalar.contains(&("aws-access-key".to_string(), AWS_ACCESS_KEY.to_string())),
        "scalar reference did not recover {label}: {scalar:?}"
    );
    assert_eq!(
        coalesced, scalar,
        "coalesced SIMD decode admission diverged for {label}"
    );

    #[cfg(feature = "gpu")]
    if keyhog_scanner::gpu::gpu_available() {
        scanner.clear_fragment_cache();
        let gpu =
            scanner.scan_chunks_with_backend(std::slice::from_ref(&fixture), ScanBackend::GpuWgpu);
        assert_eq!(
            aws_findings(&gpu),
            scalar,
            "coalesced GPU decode admission diverged for {label}"
        );
    }
}

#[test]
fn sparse_reverse_matches_scalar_recall() {
    assert_scalar_coalesced_parity("reverse", chunk("AYX7RQIFH5NMPLYQAIKA"));
}

#[test]
fn punctuated_z85_matches_scalar_recall() {
    assert_scalar_coalesced_parity("z85", chunk("k$:^nqcuN?o?)MpmOcDPh=%iG"));
}

#[test]
fn single_percent_escape_matches_scalar_recall() {
    assert_scalar_coalesced_parity("single percent escape", chunk("AK%49AQYLPMN5HFIQR7XYA"));
}

#[test]
fn short_octal_escape_matches_scalar_recall() {
    assert_scalar_coalesced_parity("short octal escape", chunk(r"AKIAQYLPMN\65HFIQR7XYA"));
}

#[test]
fn single_unicode_escape_matches_scalar_recall() {
    assert_scalar_coalesced_parity("single unicode escape", chunk(r"AK\u0049AQYLPMN5HFIQR7XYA"));
}

#[test]
fn single_quoted_printable_escape_matches_scalar_recall() {
    assert_scalar_coalesced_parity(
        "single quoted-printable escape",
        chunk("AK=49AQYLPMN5HFIQR7XYA"),
    );
}

#[test]
fn single_html_numeric_entity_matches_scalar_recall() {
    assert_scalar_coalesced_parity(
        "single HTML numeric entity",
        chunk("AK&#73;AQYLPMN5HFIQR7XYA"),
    );
}

#[test]
fn single_mime_encoded_word_matches_scalar_recall() {
    assert_scalar_coalesced_parity(
        "single MIME encoded word",
        chunk("=?utf-8?B?QUtJQVFZTFBNTjVIRklRUjdYWUE=?="),
    );
}

#[test]
fn caesar_rotation_matches_scalar_recall() {
    assert_scalar_coalesced_parity("Caesar rotation", chunk("NXVNDLYCZA5USVDE7KLN"));
}

struct UnknownAdmissionDecoder;

impl Decoder for UnknownAdmissionDecoder {
    fn name(&self) -> &'static str {
        "unknown-admission-parity-probe"
    }

    fn decode_chunk(&self, source: &Chunk) -> Vec<Chunk> {
        if source
            .metadata
            .source_type
            .contains("/unknown-admission-probe")
            || !source.data.contains("c.u.s.t.o.m")
        {
            return Vec::new();
        }
        let mut decoded = source.clone();
        decoded.data = AWS_ACCESS_KEY.into();
        decoded.metadata.source_type =
            format!("{}/unknown-admission-probe", source.metadata.source_type).into();
        vec![decoded]
    }
}

#[test]
fn custom_decoder_without_admission_predicate_fails_open() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| register_decoder(Box::new(UnknownAdmissionDecoder)));
    assert_scalar_coalesced_parity("custom unknown admission", chunk("c.u.s.t.o.m"));
}
