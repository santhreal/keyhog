//! Native binary sources keep structurally validated credentials while rejecting
//! weak prefix and generic-assignment noise from printable data sections.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

const AWS_ACCESS_KEY: &str = "AKIAQ9W7E6R5T4Y3U2I1";
const OPENAI_PREFIX_FRAGMENT: &str = "sk-proj-Xy9kLm2Qw";
const GENERIC_PASSWORD: &str = "aapqhgn-qhuuc-trnmf";

fn findings(source_type: &str, text: &str) -> Vec<(String, String)> {
    let scanner = CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("embedded scanner compiles");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some("fixture.bin".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .expect("binary-source scan succeeds")
        .iter()
        .flat_map(|per_chunk| per_chunk.iter())
        .map(|finding| {
            (
                finding.detector_id.as_ref().to_owned(),
                finding.credential.as_ref().to_owned(),
            )
        })
        .collect()
}

fn assert_aws_finding(source_type: &str) {
    let actual = findings(source_type, &format!("\0{AWS_ACCESS_KEY}\0"));
    assert!(
        actual
            .iter()
            .any(|(detector, credential)| detector == "aws-access-key"
                && credential == AWS_ACCESS_KEY),
        "validated AWS key must survive {source_type:?} suppression; findings: {actual:#?}"
    );
}

/// Locks out the production bug where `filesystem:binary-strings` discarded an
/// exact 20-byte AWS access key even after its detector shape had validated it.
#[test]
fn extracted_native_strings_keep_shape_validated_aws_keys() {
    assert_aws_finding("filesystem:binary-strings");
}

/// Proves the recall exemption covers each native executable section analyzer,
/// preventing ELF, PE, and Mach-O scans from silently losing exact credentials.
#[test]
fn native_executable_sections_keep_shape_validated_aws_keys() {
    for source_type in [
        "binary:strings",
        "binary:elf:.data",
        "binary:pe:.rdata",
        "binary:macho:__cstring",
    ] {
        assert_aws_finding(source_type);
    }
}

/// Proves archived compiled objects retain the same validated-credential recall
/// contract as directly scanned binaries instead of taking a stricter path.
#[test]
fn archived_binary_strings_keep_shape_validated_aws_keys() {
    assert_aws_finding("filesystem/archive-binary");
}

/// Guards the precision twin: a short OpenAI prefix fragment has no complete
/// credential-shape proof and must remain suppressed in raw executable data.
#[test]
fn weak_prefix_fragments_remain_suppressed_in_native_sections() {
    let actual = findings(
        "binary:elf:.rodata",
        &format!("\0{OPENAI_PREFIX_FRAGMENT}\0"),
    );
    assert!(
        actual
            .iter()
            .all(|(_, credential)| credential != OPENAI_PREFIX_FRAGMENT),
        "unvalidated prefix fragment must stay suppressed; findings: {actual:#?}"
    );
}

/// Guards the generic-detector twin: assignment syntax embedded in printable
/// binary data is not proof of a source credential and must remain suppressed.
#[test]
fn generic_assignments_remain_suppressed_in_native_sections() {
    let ordinary = findings("filesystem", &format!("GRAPHITE_PASS={GENERIC_PASSWORD}"));
    assert!(
        ordinary.iter().any(
            |(detector, credential)| detector == "generic-keyword-secret"
                && credential == GENERIC_PASSWORD
        ),
        "fixture must exercise the generic assignment detector; findings: {ordinary:#?}"
    );

    let binary = findings(
        "binary:elf:.rodata",
        &format!("GRAPHITE_PASS={GENERIC_PASSWORD}"),
    );
    assert!(
        binary
            .iter()
            .all(|(_, credential)| credential != GENERIC_PASSWORD),
        "generic binary assignment must stay suppressed; findings: {binary:#?}"
    );
}
