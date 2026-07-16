//! Backend-robustness sweep - adversarial inputs and stress shapes
//! that must NEVER panic / OOM / silently drop matches on any backend.
//!
//! Each test runs on the three production backends. A required GPU that is
//! unavailable fails visibly. The point is to catch crashes that ONLY surface on
//! one backend - e.g. a NUL byte that crashes the GPU shader's
//! C-string buffer handling but not the CPU path.
//!
//! Coverage axes:
//!   * Embedded NUL bytes (GPU shader buffer hazard).
//!   * Long single-line input (no newlines - the line-offset table
//!     degenerates to one entry).
//!   * Empty input (1-byte chunks, zero-byte chunks).
//!   * Deeply-nested unicode (combining marks, RTL, ZWJ sequences).
//!   * Many tiny chunks (rayon worker pressure).
//!   * One huge chunk (large enough to cross MAX_SCAN_CHUNK_BYTES).
//!   * Concurrent scans from multiple threads (Send/Sync invariant).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, GpuInitPolicy, ScanBackend};
use std::sync::{Arc, Barrier, OnceLock};

fn scanner() -> &'static Arc<CompiledScanner> {
    static SCANNER: OnceLock<Arc<CompiledScanner>> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors =
            keyhog_core::load_detectors(&detector_dir()).expect("detectors dir loadable");
        Arc::new(CompiledScanner::compile(detectors).expect("scanner compile"))
    })
}

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "robustness".into(),
            path: Some(path.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn canonical_scan(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    backend: ScanBackend,
) -> Vec<Vec<keyhog_core::RawMatch>> {
    let mut rows = scanner.scan_chunks_with_backend(chunks, backend);
    for row in &mut rows {
        row.sort();
    }
    rows
}

fn assert_backend_parity(scanner: &CompiledScanner, chunks: &[Chunk]) {
    let reference = canonical_scan(scanner, chunks, ScanBackend::CpuFallback);
    for backend in [ScanBackend::SimdCpu, ScanBackend::GpuWgpu] {
        assert_eq!(
            canonical_scan(scanner, chunks, backend),
            reference,
            "{backend:?} full findings diverged from the scalar reference"
        );
    }
}

#[test]
fn r1_embedded_nul_bytes_backend_parity() {
    let scanner = scanner();
    let chunks = vec![make_chunk(
        "header\0AKIAQYLPMN5HFIQR7XYA\0sk_live_4eC39HqLyjWDarjtT1zdp7dc\0footer",
        "nul.bin",
    )];
    assert_backend_parity(scanner, &chunks);
}

#[test]
fn r2_single_line_no_newline_backend_parity() {
    let scanner = scanner();
    // 1 MiB on a single line with no `\n`. Stresses line-offset
    // calculation degenerate case (one giant line).
    let mut text = String::with_capacity(1024 * 1024);
    while text.len() < 1024 * 1024 {
        text.push_str("noise ");
    }
    text.push_str(concat!("AK", "IAQYLPMN5HFIQR7XYA"));
    let chunks = vec![make_chunk(&text, "longline.txt")];
    assert_backend_parity(scanner, &chunks);
}

#[test]
fn r3_zero_byte_input_backend_parity() {
    let scanner = scanner();
    let chunks = vec![
        make_chunk("", "empty-a.txt"),
        make_chunk("", "empty-b.txt"),
        make_chunk("", "empty-c.txt"),
    ];
    assert_eq!(
        canonical_scan(scanner, &chunks, ScanBackend::CpuFallback),
        vec![Vec::new(), Vec::new(), Vec::new()]
    );
    assert_backend_parity(scanner, &chunks);
}

#[test]
fn r4_one_byte_input_backend_parity() {
    let scanner = scanner();
    let chunks = vec![make_chunk("A", "one.txt")];
    assert_backend_parity(scanner, &chunks);
}

#[test]
fn r5_unicode_storm_backend_parity() {
    let scanner = scanner();
    // ZWJ sequences, RTL overrides, combining marks - UTF-8
    // boundary hazards that have historically crashed naive byte-
    // indexing in the GPU shader.
    let storm = "\u{202E}AKIAQYLPMN5HFIQR7XYA\u{202C}é\u{0301}é\u{0301}é\u{0301}🦀🚀\u{200D}🌈\
                 ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\u{202E}";
    let chunks = vec![make_chunk(storm, "unicode.txt")];
    assert_backend_parity(scanner, &chunks);
}

#[test]
fn r6_many_tiny_chunks_backend_parity() {
    let scanner = scanner();
    // 1000 4-byte chunks. Per-chunk dispatch overhead × 1000;
    // catches "GPU batch limit was set to 1" bugs or
    // mpsc-channel deadlocks.
    let chunks: Vec<Chunk> = (0..1000)
        .map(|i| make_chunk("noi\n", &format!("c{i:04}.txt")))
        .collect();
    assert_backend_parity(scanner, &chunks);
}

#[test]
fn r7_concurrent_scans_from_multiple_threads_no_data_race() {
    // The resident GPU session owns mutable device buffers, so distinct requests
    // must remain exact when many callers reach it together.
    let scanner = scanner().clone();
    let barrier = Arc::new(Barrier::new(16));
    let suffixes = *b"BCDEFGHJKLMNPQRS";

    let handles: Vec<_> = (0..16)
        .map(|thread_index| {
            let scanner = scanner.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let suffix = suffixes[thread_index] as char;
                let key = format!("AKIAQYLPMN5HFIQR7XY{suffix}");
                let path = format!("concurrent-{thread_index:02}.rs");
                let chunks = vec![make_chunk(
                    &format!("const AWS_ACCESS_KEY_ID = \"{key}\";\n"),
                    &path,
                )];

                let canonicalize = |mut rows: Vec<Vec<keyhog_core::RawMatch>>| {
                    for row in &mut rows {
                        row.sort();
                    }
                    rows
                };
                let reference = canonicalize(
                    scanner.scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback),
                );
                let aws: Vec<_> = reference[0]
                    .iter()
                    .filter(|finding| finding.detector_id.as_ref() == "aws-access-key")
                    .collect();
                assert_eq!(aws.len(), 1, "thread {thread_index}: {reference:?}");
                assert_eq!(aws[0].credential.as_ref(), key);
                assert_eq!(aws[0].location.file_path.as_deref(), Some(path.as_str()));

                barrier.wait();
                let gpu_first =
                    canonicalize(scanner.scan_chunks_with_backend(&chunks, ScanBackend::GpuWgpu));
                barrier.wait();
                let gpu_second =
                    canonicalize(scanner.scan_chunks_with_backend(&chunks, ScanBackend::GpuWgpu));
                let simd =
                    canonicalize(scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu));
                for (backend, actual) in [
                    ("gpu-first", gpu_first),
                    ("gpu-second", gpu_second),
                    ("hyperscan", simd),
                ] {
                    assert_eq!(
                        actual, reference,
                        "thread {thread_index} {backend} result diverged from scalar reference"
                    );
                }
                reference
            })
        })
        .collect();

    for handle in handles {
        let reference = handle.join().expect("concurrent scanner worker panicked");
        assert_eq!(reference.len(), 1);
    }
}

#[test]
fn r8_empty_regions_around_nonempty_chunks_backend_parity() {
    let scanner = scanner();
    let chunks = vec![
        make_chunk("", "empty-before.txt"),
        make_chunk(
            "const AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\";\n",
            "credential.rs",
        ),
        make_chunk("", "empty-middle.txt"),
        make_chunk("ordinary text\n", "plain.txt"),
        make_chunk("", "empty-after.txt"),
    ];
    let reference = canonical_scan(scanner, &chunks, ScanBackend::CpuFallback);
    assert_eq!(reference.len(), chunks.len());
    assert!(reference[0].is_empty());
    assert!(reference[2].is_empty());
    assert!(reference[4].is_empty());
    let aws: Vec<_> = reference[1]
        .iter()
        .filter(|finding| finding.detector_id.as_ref() == "aws-access-key")
        .collect();
    assert_eq!(aws.len(), 1, "mixed-region scalar oracle: {reference:?}");
    assert_eq!(aws[0].location.file_path.as_deref(), Some("credential.rs"));
    assert_backend_parity(scanner, &chunks);
}

#[test]
fn r9_fallible_gpu_boundary_preserves_stable_bytes_for_cpu_recovery() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors dir loadable");
    let scanner = CompiledScanner::compile_with_gpu_policy(detectors, GpuInitPolicy::ForceDisabled)
        .expect("GPU-disabled scanner compiles");
    let chunks = vec![make_chunk(
        "const AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\";\n",
        "recover.env",
    )];

    let error = scanner
        .try_scan_coalesced_with_backend_and_admission(&chunks, ScanBackend::GpuWgpu, None)
        .expect_err("a disabled GPU peer must return an in-band dispatch error");
    assert!(
        error.to_string().contains("GPU"),
        "dispatch error must identify the failed accelerator: {error}"
    );

    let recovered = canonical_scan(&scanner, &chunks, ScanBackend::CpuFallback);
    let aws: Vec<_> = recovered[0]
        .iter()
        .filter(|finding| finding.detector_id.as_ref() == "aws-access-key")
        .collect();
    assert_eq!(aws.len(), 1, "stable-byte CPU recovery lost the finding");
    assert_eq!(aws[0].credential.as_ref(), "AKIAQYLPMN5HFIQR7XYA");
    assert_eq!(aws[0].location.file_path.as_deref(), Some("recover.env"));
}
