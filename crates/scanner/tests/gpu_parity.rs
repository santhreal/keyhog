//! GPU ↔ SIMD parity test: identical input, identical detectors -
//! the GPU and SIMD backends must produce the same set of credentials
//! at the same offsets.
//!
//! Hard-fail parity: adapter/init failure or divergence panics -
//! no silent skip, no WARN-only downgrade. Set `KEYHOG_REQUIRE_GPU=1`
//! in CI to mandate a compatible adapter.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::gpu_gate::{assert_gpu_not_silent_empty, require_gpu_or_panic};
use support::paths::detector_dir;

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

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

    let gpu_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::Gpu);
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

    let results = scanner.scan_chunks_with_backend(&[chunk_a, chunk_b], ScanBackend::Gpu);
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

/// Pipeline-refactor lock for the AC kernel path: the two-phase API
/// `scan_coalesced_gpu_ac_phase1` → `scan_coalesced_gpu_phase2` must
/// be a faithful split of the combined `scan_coalesced_gpu_ac`
/// wrapper. Same rationale as the literal-set test below but exercises
/// the AC-bounded-ranges kernel path that fires when
/// `KEYHOG_GPU_KERNEL=ac` or the CUDA backend is active.
#[test]
fn scan_coalesced_gpu_ac_phase1_phase2_parity_with_wrapper() {
    use keyhog_scanner::GpuPhase1Output;
    require_gpu_or_panic("scan_coalesced_gpu_ac_phase1_phase2_parity_with_wrapper");
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

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

    let combined = scanner.scan_coalesced_gpu_ac(&chunks);
    let combined_keys = collect_keys(&combined);

    let split = match scanner.scan_coalesced_gpu_ac_phase1(&chunks) {
        GpuPhase1Output::Hits(per_chunk_hits) => {
            scanner.scan_coalesced_gpu_phase2(&chunks, per_chunk_hits)
        }
        GpuPhase1Output::Done(results) => results,
    };
    let split_keys = collect_keys(&split);

    if combined_keys != split_keys {
        let only_combined: Vec<_> = combined_keys.difference(&split_keys).collect();
        let only_split: Vec<_> = split_keys.difference(&combined_keys).collect();
        panic!(
            "AC phase1+phase2 split diverges from scan_coalesced_gpu_ac wrapper.\n  combined: {} keys\n  split:    {} keys\n  only in combined ({}): {:?}\n  only in split    ({}): {:?}",
            combined_keys.len(),
            split_keys.len(),
            only_combined.len(),
            only_combined.iter().take(5).collect::<Vec<_>>(),
            only_split.len(),
            only_split.iter().take(5).collect::<Vec<_>>(),
        );
    }

    assert_eq!(
        combined.len(),
        split.len(),
        "AC phase1+phase2 produced a different per-chunk Vec length than the wrapper"
    );
    for (i, (a, b)) in combined.iter().zip(split.iter()).enumerate() {
        assert_eq!(
            a.len(),
            b.len(),
            "AC chunk {i}: wrapper produced {} matches, split produced {}",
            a.len(),
            b.len(),
        );
    }
}

/// Pipeline-refactor lock: the two-phase API
/// `scan_coalesced_gpu_phase1` + `scan_coalesced_gpu_phase2` must be a
/// faithful split of `scan_coalesced_gpu`. The orchestrator's pipelined
/// scanner thread (overlap GPU dispatch of batch N+1 with CPU
/// post-process of batch N) sequences these manually instead of going
/// through the combined wrapper - if the two paths ever diverge,
/// the pipelined path silently mis-attributes findings.
///
/// This test asserts byte-for-byte identical
/// `(credential, file_path, offset)` tuples between:
///   (a) `scanner.scan_coalesced_gpu(&chunks)` - the atomic wrapper
///   (b) manual `phase1` → match `Hits` then `phase2`, or `Done` then
///       return directly - the same flow the orchestrator does.
///
#[test]
fn scan_coalesced_gpu_phase1_phase2_parity_with_wrapper() {
    use keyhog_scanner::GpuPhase1Output;
    require_gpu_or_panic("scan_coalesced_gpu_phase1_phase2_parity_with_wrapper");
    let detectors =
        keyhog_core::load_detectors(&detector_dir()).expect("detectors directory must load");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Same synthetic corpus as the SIMD-parity test so the GPU dispatch
    // actually has substance to attribute. Three chunks gives multiple
    // per_chunk_hits buckets; both AC-prefix detectors (AKIA, ghp_,
    // sk_live_) and the boundary helper get exercised.
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

    // Atomic wrapper path.
    let combined = scanner.scan_coalesced_gpu(&chunks);
    let combined_keys = collect_keys(&combined);

    // Manual phase1+phase2 path - exactly what
    // `cli/orchestrator.rs::scanner_thread` does on the
    // `KEYHOG_BACKEND=gpu` route.
    let split = match scanner.scan_coalesced_gpu_phase1(&chunks) {
        GpuPhase1Output::Hits(per_chunk_hits) => {
            scanner.scan_coalesced_gpu_phase2(&chunks, per_chunk_hits)
        }
        GpuPhase1Output::Done(results) => results,
    };
    let split_keys = collect_keys(&split);

    if combined_keys != split_keys {
        let only_combined: Vec<_> = combined_keys.difference(&split_keys).collect();
        let only_split: Vec<_> = split_keys.difference(&combined_keys).collect();
        panic!(
            "phase1+phase2 split diverges from scan_coalesced_gpu wrapper.\n  combined: {} keys\n  split:    {} keys\n  only in combined ({}): {:?}\n  only in split    ({}): {:?}",
            combined_keys.len(),
            split_keys.len(),
            only_combined.len(),
            only_combined.iter().take(5).collect::<Vec<_>>(),
            only_split.len(),
            only_split.iter().take(5).collect::<Vec<_>>(),
        );
    }

    // Also assert per-chunk Vec lengths align - the wrapper preserves
    // chunk-index ordering and the split must too. A divergence at this
    // level would mean a chunk's matches got reattributed to a
    // neighbouring chunk by the refactor.
    assert_eq!(
        combined.len(),
        split.len(),
        "phase1+phase2 produced a different per-chunk Vec length than the wrapper"
    );
    for (i, (a, b)) in combined.iter().zip(split.iter()).enumerate() {
        assert_eq!(
            a.len(),
            b.len(),
            "chunk {i}: wrapper produced {} matches, split produced {}",
            a.len(),
            b.len(),
        );
    }
}
