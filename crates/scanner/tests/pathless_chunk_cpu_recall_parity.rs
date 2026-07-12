//! Coverage: a path-less chunk (stdin: `source_type="stdin"`, `path=None`)
//! must detect a canonical AWS access key on the scalar `CpuFallback` backend,
//! exactly like an identical filesystem chunk.
//!
//! Gap this closes: `backend_parity_matrix` and the existing stdin e2e only
//! exercise chunks that carry a file path (and the e2e only runs `--backend
//! simd`, which dispatches through `scan_coalesced_with_backend`). The scalar
//! `CpuFallback` per-chunk path (`scan_chunks_with_backend`) on a `path=None`
//! chunk had no direct assertion, so a future change that keyed detection (not
//! just suppression/confidence) on `ChunkMetadata.path`/`source_type` would
//! slip through. Each cell below varies (source_type) × (path present?) so the
//! load-bearing field is pinned: detection must be identical across all four.

mod support;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

const LINE: &str = "AWS_ACCESS_KEY_ID=\"AKIAQYLPMN5HFIQR7XYA\"\n";

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

fn chunk(source_type: &str, path: Option<&str>) -> Chunk {
    Chunk {
        data: LINE.into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: path.map(Into::into),
            ..Default::default()
        },
    }
}

fn aws_hits(results: &[Vec<RawMatch>]) -> usize {
    results
        .iter()
        .flatten()
        .filter(|m| m.detector_id.as_ref() == "aws-access-key")
        .count()
}

#[test]
fn pathless_stdin_chunk_detects_aws_key_on_cpu_fallback() {
    let sc = scanner();
    let be = ScanBackend::CpuFallback;

    // Four cells isolate (source_type) × (path present?). The filesystem+path
    // cell is the known-good control; the others must match it.
    let fs_path = aws_hits(&sc.scan_chunks_with_backend(&[chunk("filesystem", Some("k.txt"))], be));
    let fs_nopath = aws_hits(&sc.scan_chunks_with_backend(&[chunk("filesystem", None)], be));
    let stdin_path = aws_hits(&sc.scan_chunks_with_backend(&[chunk("stdin", Some("k.txt"))], be));
    let stdin_nopath = aws_hits(&sc.scan_chunks_with_backend(&[chunk("stdin", None)], be));

    assert_eq!(
        fs_path, 1,
        "control: filesystem chunk with a path must detect"
    );
    assert_eq!(
        fs_nopath, 1,
        "filesystem chunk WITHOUT a path must still detect (path is metadata, not a gate)"
    );
    assert_eq!(stdin_path, 1, "stdin-typed chunk with a path must detect");
    assert_eq!(
        stdin_nopath, 1,
        "stdin chunk (no path) must detect the same AWS key as the file scan — a path-less \
         chunk is not a license to false-clean"
    );
}
