//! Sparse decoder admission must have the same recall on scalar CPU and the
//! production coalesced SIMD path.

mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::{register_decoder, DecodeOutputSink, Decoder};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::collections::BTreeSet;
use std::sync::{Once, OnceLock};
use support::paths::detector_dir;

const AWS_ACCESS_KEY: &str = "AKIAQYLPMN5HFIQR7XYA";

fn scanner(backend: ScanBackend) -> &'static CompiledScanner {
    static CPU: OnceLock<CompiledScanner> = OnceLock::new();
    static SIMD: OnceLock<CompiledScanner> = OnceLock::new();
    #[cfg(feature = "gpu")]
    static GPU: OnceLock<CompiledScanner> = OnceLock::new();
    let slot = match backend {
        ScanBackend::CpuFallback => &CPU,
        ScanBackend::SimdCpu => &SIMD,
        #[cfg(feature = "gpu")]
        ScanBackend::GpuWgpu => &GPU,
        #[allow(unreachable_patterns)]
        other => panic!("unsupported parity backend {other:?}"),
    };
    slot.get_or_init(|| compile_scanner(backend))
}

fn compile_scanner(backend: ScanBackend) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
    let mut config = ScannerConfig::default();
    config.penalize_test_paths = false;
    CompiledScanner::compile_for_backend(detectors, backend)
        .expect("scanner compile")
        .with_config(config)
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
    assert_scalar_coalesced_parity_with(
        label,
        fixture,
        scanner(ScanBackend::CpuFallback),
        scanner(ScanBackend::SimdCpu),
        true,
    );
}

fn assert_scalar_coalesced_parity_with(
    label: &str,
    fixture: Chunk,
    cpu: &CompiledScanner,
    simd: &CompiledScanner,
    _check_gpu: bool,
) {
    let scalar = cpu
        .scan_chunks_with_backend(std::slice::from_ref(&fixture), ScanBackend::CpuFallback)
        .expect("selected backend scan succeeds");
    let coalesced = simd
        .scan_coalesced_with_backend(std::slice::from_ref(&fixture), ScanBackend::SimdCpu)
        .expect("coalesced SIMD decode scan should succeed");

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
    if _check_gpu && keyhog_scanner::gpu::gpu_available() {
        let gpu = scanner(ScanBackend::GpuWgpu)
            .scan_chunks_with_backend(std::slice::from_ref(&fixture), ScanBackend::GpuWgpu)
            .expect("selected backend scan succeeds");
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

    fn decode_chunk_into(&self, source: &Chunk, sink: &mut dyn DecodeOutputSink) {
        if source
            .metadata
            .source_type
            .contains("/unknown-admission-probe")
            || !source.data.contains("c.u.s.t.o.m")
        {
            return;
        }
        let mut decoded = source.clone();
        decoded.data = AWS_ACCESS_KEY.into();
        decoded.metadata.source_type =
            format!("{}/unknown-admission-probe", source.metadata.source_type).into();
        sink.push(decoded);
    }
}

#[test]
fn custom_decoder_without_admission_predicate_fails_open() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| register_decoder(Box::new(UnknownAdmissionDecoder)));
    let cpu = compile_scanner(ScanBackend::CpuFallback);
    let simd = compile_scanner(ScanBackend::SimdCpu);
    assert_scalar_coalesced_parity_with(
        "custom unknown admission",
        chunk("c.u.s.t.o.m"),
        &cpu,
        &simd,
        false,
    );
}
