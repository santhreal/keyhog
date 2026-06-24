mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::sync::OnceLock;

const GHP_VALID: &str = "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";
const DETECTOR_IDS: &[&str] = &["github-classic-pat"];

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let mut detectors =
            keyhog_core::load_detectors(&support::paths::detector_dir()).expect("detectors");
        detectors.retain(|detector| DETECTOR_IDS.contains(&detector.id.as_str()));
        CompiledScanner::compile(detectors).expect("compile")
    })
}

fn chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "github-pat-boundary".into(),
            path: Some("fixtures/overlong_pat.rs".into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
fn overlong_github_pat_run_is_not_reported_by_any_cpu_backend() {
    let scanner = scanner();
    let input = chunk(&format!("const PAT = \"{GHP_VALID}X\";\n"));

    for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
        scanner.clear_fragment_cache();
        let matches = scanner.scan_with_backend(&input, backend);
        assert!(
            matches.is_empty(),
            "overlong contiguous ghp_ payload must fail closed on {backend:?}; got {matches:?}"
        );
    }
}

#[test]
fn exact_github_pat_boundary_still_reports() {
    let scanner = scanner();
    let input = chunk(&format!("const PAT = \"{GHP_VALID}\";\n"));

    for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
        scanner.clear_fragment_cache();
        let matches = scanner.scan_with_backend(&input, backend);
        assert!(
            matches.iter().any(|m| {
                m.detector_id.as_ref() == "github-classic-pat" && m.credential.as_ref() == GHP_VALID
            }),
            "exact valid ghp_ payload must still report on {backend:?}; got {matches:?}"
        );
    }
}
