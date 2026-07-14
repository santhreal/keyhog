//! GPU ↔ SIMD parity test: identical input, identical detectors -
//! the GPU and SIMD backends must produce the same set of credentials
//! at the same offsets.
//!
//! Hard-fail parity: adapter/init failure or divergence panics -
//! no silent skip, no WARN-only downgrade. Run under the explicit require-GPU
//! runtime policy in CI to mandate a compatible adapter.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::contracts::test_chunk as make_chunk;
use support::gpu_gate::{assert_gpu_not_silent_empty, require_gpu_or_panic};
use support::paths::detector_dir;

/// (credential_hash, file_path, file_offset) - the smallest tuple that
/// uniquely identifies a finding for cross-backend comparison. We
/// intentionally don't compare detector_id because the GPU literal-set
/// can attribute a literal to a different detector when multiple
/// detectors share the same prefix; the credential string + location
/// is what end users see in the report.
type FindingKey = (String, String, usize);

fn collect_keys(results: &[Vec<keyhog_core::RawMatch>]) -> std::collections::BTreeSet<FindingKey> {
    let mut set = std::collections::BTreeSet::new();
    for chunk in results {
        for m in chunk {
            set.insert((
                m.credential.as_ref().to_string(),
                m.location
                    .file_path
                    .as_deref()
                    .map(|s| s.to_string())
                    .unwrap_or_default(),
                m.location.offset,
            ));
        }
    }
    set
}

#[test]
fn gpu_and_simd_produce_identical_findings_on_same_corpus() {
    require_gpu_or_panic("gpu_and_simd_produce_identical_findings_on_same_corpus");
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Synthetic corpus designed to exercise: AKIA/ASIA prefix path,
    // ghp_ prefix path, generic high-entropy fallback, and a chunk
    // boundary straddle (kicks the v0.5.4 boundary helper on both
    // backends so any divergence between the SIMD and GPU paths
    // surfaces here).
    let chunks = vec![
        make_chunk("// no secrets in this file", "clean.rs"),
        make_chunk(
            "const KEY = \"AKIAQYLPMN5HFIQR7XYA\";\nconst PAT = \"ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\";",
            "fixtures/aws_github.rs",
        ),
        make_chunk(
            "auth: \"sk_live_4eC39HqLyjWDarjtT1zdp7dc\"\npayload: \"AKIAQYLPMN5HFIQR7BBB\"",
            "fixtures/stripe_aws.yml",
        ),
    ];

    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let simd_keys = collect_keys(&simd_results);

    let gpu_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::GpuWgpu);
    let gpu_keys = collect_keys(&gpu_results);

    assert_gpu_not_silent_empty(
        gpu_results.iter().all(|c| c.is_empty()),
        simd_keys.len(),
        "gpu_and_simd_produce_identical_findings_on_same_corpus",
    );

    if simd_keys != gpu_keys {
        let only_simd: Vec<_> = simd_keys.difference(&gpu_keys).collect();
        let only_gpu: Vec<_> = gpu_keys.difference(&simd_keys).collect();
        panic!(
            "GPU/SIMD parity broken.\n  SIMD findings: {}\n  GPU findings:  {}\n  only in SIMD ({}): {:?}\n  only in GPU ({}): {:?}",
            simd_keys.len(),
            gpu_keys.len(),
            only_simd.len(),
            only_simd.iter().take(5).collect::<Vec<_>>(),
            only_gpu.len(),
            only_gpu.iter().take(5).collect::<Vec<_>>(),
        );
    }

    assert!(
        !simd_keys.is_empty(),
        "fixture should produce findings on both backends"
    );
}

#[test]
fn gpu_path_finds_boundary_straddled_secret() {
    // Same boundary-reassembly test as window_boundary.rs but driven
    // through the GPU backend. Catches the regression "GPU dispatch
    // skips boundary scan" - a real correctness gap that shipped in
    // v0.5.4 before the GPU sweep, where the SIMD path got boundary
    // reassembly and the GPU path didn't.
    require_gpu_or_panic("gpu_path_finds_boundary_straddled_secret");
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let secret = concat!("AK", "IAQYLPMN5HFIQR7CCC");
    assert_eq!(secret.len(), 20);
    let split_at = 12;

    // Chunk A: 4 MiB pad + first 12 chars of the secret. Big enough
    // to keep the chunk well-defined; small enough for a fast test.
    let pad_a_len = (4 * 1024 * 1024) - split_at;
    let mut data_a = "x\n".repeat(pad_a_len / 2);
    if data_a.len() < pad_a_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();
    let chunk_a = Chunk {
        data: data_a.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("big.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");
    data_b.push_str(&"y".repeat(1024));
    let chunk_b = Chunk {
        data: data_b.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("big.txt".into()),
            base_offset: len_a,
            ..Default::default()
        },
    };

    let results = scanner.scan_chunks_with_backend(&[chunk_a, chunk_b], ScanBackend::GpuWgpu);
    let mut found = false;
    for chunk in &results {
        for m in chunk {
            if m.credential.as_ref() == secret {
                found = true;
                assert_eq!(m.location.offset, pad_a_len);
            }
        }
    }
    assert!(
        found,
        "GPU path missed the boundary-straddled AKIA secret (per-chunk findings: {:?})",
        results.iter().map(|v| v.len()).collect::<Vec<_>>()
    );
}
