//! Generic assignment candidate lengths are detector policy, including the
//! inclusive upper boundary. A longer token must never be reported as a
//! truncated prefix at the shared extractor ceiling.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner_with_api_key_bounds(min_len: usize, max_len: usize) -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let detector = detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-api-key")
        .expect("generic-api-key detector");
    detector.min_len = Some(min_len);
    detector.max_len = Some(max_len);
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn generic_api_key_credentials_with_backend(
    scanner: &CompiledScanner,
    key: &str,
    value: &str,
    backend: ScanBackend,
) -> Vec<String> {
    scanner.clear_fragment_cache();
    let chunk = Chunk {
        data: format!("{key}={value}").into(),
        metadata: ChunkMetadata::default(),
    };
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), backend)
        .into_iter()
        .flatten()
        .filter(|finding| finding.detector_id.as_ref() == "generic-api-key")
        .map(|finding| finding.credential.to_string())
        .collect()
}

fn generic_api_key_credentials(scanner: &CompiledScanner, value: &str) -> Vec<String> {
    generic_api_key_credentials_with_backend(scanner, "api_key", value, ScanBackend::CpuFallback)
}

#[test]
fn owning_detector_max_len_is_inclusive_and_rejects_the_next_byte() {
    let scanner = scanner_with_api_key_bounds(8, 16);
    let at_ceiling = "aB3dE5gH7jK9mN2p";
    assert_eq!(at_ceiling.len(), 16);
    assert_eq!(
        generic_api_key_credentials(&scanner, at_ceiling),
        vec![at_ceiling.to_string()]
    );

    let over_ceiling = "aB3dE5gH7jK9mN2pQ";
    assert_eq!(over_ceiling.len(), 17);
    assert!(generic_api_key_credentials(&scanner, over_ceiling).is_empty());
}

#[test]
fn shared_128_byte_ceiling_never_emits_a_truncated_prefix() {
    let scanner = scanner_with_api_key_bounds(8, 128);
    let over_ceiling = "aB3dE5gH7jK9mN2p".repeat(9);
    assert!(over_ceiling.len() > 128);
    let findings = generic_api_key_credentials(&scanner, &over_ceiling);
    assert!(
        findings.is_empty(),
        "overlength value produced truncated generic finding(s): {findings:?}"
    );
}

#[test]
fn custom_detector_keyword_drives_cpu_simd_and_gpu_admission() {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let detector = detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-api-key")
        .expect("generic-api-key detector");
    detector.keywords.push("bespoke_credential".to_string());
    let scanner = CompiledScanner::compile(detectors).expect("compile custom corpus");
    let value = "aB3dE5gH7jK9mN2pQ4rS6tV8";

    let cpu = generic_api_key_credentials_with_backend(
        &scanner,
        "bespoke_credential",
        value,
        ScanBackend::CpuFallback,
    );
    let simd = generic_api_key_credentials_with_backend(
        &scanner,
        "bespoke_credential",
        value,
        ScanBackend::SimdCpu,
    );
    let gpu = generic_api_key_credentials_with_backend(
        &scanner,
        "bespoke_credential",
        value,
        ScanBackend::Gpu,
    );
    assert_eq!(cpu, vec![value.to_string()]);
    assert_eq!(
        simd, cpu,
        "custom detector policy must retain CPU/SIMD parity"
    );
    assert_eq!(
        gpu, cpu,
        "custom detector policy must retain CPU/GPU parity"
    );
}
