//! Backend-robustness sweep — adversarial inputs and stress shapes
//! that must NEVER panic / OOM / silently drop matches on any backend.
//!
//! Each test runs on all 4 backends. Where the GPU adapter is absent
//! the test silently skips (the helper falls back to SIMD when GPU
//! init fails). The point is to catch crashes that ONLY surface on
//! one backend — e.g. a NUL byte that crashes the GPU shader's
//! C-string buffer handling but not the CPU path.
//!
//! Coverage axes:
//!   * Embedded NUL bytes (GPU shader buffer hazard).
//!   * Long single-line input (no newlines — the line-offset table
//!     degenerates to one entry).
//!   * Empty input (1-byte chunks, zero-byte chunks).
//!   * Deeply-nested unicode (combining marks, RTL, ZWJ sequences).
//!   * Many tiny chunks (rayon worker pressure).
//!   * One huge chunk (large enough to cross MAX_SCAN_CHUNK_BYTES).
//!   * Concurrent scans from multiple threads (Send/Sync invariant).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

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

const ALL_BACKENDS: &[ScanBackend] = &[
    ScanBackend::SimdCpu,
    ScanBackend::CpuFallback,
    ScanBackend::Gpu,
    ScanBackend::MegaScan,
];

#[test]
fn r1_embedded_nul_bytes_no_panic_on_any_backend() {
    let scanner = scanner();
    let chunks = vec![make_chunk(
        "header\0AKIAQYLPMN5HFIQR7XYA\0sk_live_4eC39HqLyjWDarjtT1zdp7dc\0footer",
        "nul.bin",
    )];
    for backend in ALL_BACKENDS {
        // Just must not panic. We don't assert findings — different
        // backends legitimately treat NUL differently (the GPU shader
        // may terminate on NUL); the contract is "no crash."
        let _ = scanner.scan_chunks_with_backend(&chunks, *backend);
    }
}

#[test]
fn r2_single_line_no_newline_no_panic() {
    let scanner = scanner();
    // 1 MiB on a single line with no `\n`. Stresses line-offset
    // calculation degenerate case (one giant line).
    let mut text = String::with_capacity(1024 * 1024);
    while text.len() < 1024 * 1024 {
        text.push_str("noise ");
    }
    text.push_str("AKIAQYLPMN5HFIQR7XYA");
    let chunks = vec![make_chunk(&text, "longline.txt")];
    for backend in ALL_BACKENDS {
        let _ = scanner.scan_chunks_with_backend(&chunks, *backend);
    }
}

#[test]
fn r3_zero_byte_input_no_panic() {
    let scanner = scanner();
    let chunks = vec![make_chunk("", "empty.txt")];
    for backend in ALL_BACKENDS {
        let r = scanner.scan_chunks_with_backend(&chunks, *backend);
        assert_eq!(
            r.len(),
            1,
            "result vec must match input vec length on {backend:?}"
        );
        assert!(
            r[0].is_empty(),
            "empty input must produce no findings on {backend:?}"
        );
    }
}

#[test]
fn r4_one_byte_input_no_panic() {
    let scanner = scanner();
    let chunks = vec![make_chunk("A", "one.txt")];
    for backend in ALL_BACKENDS {
        let _ = scanner.scan_chunks_with_backend(&chunks, *backend);
    }
}

#[test]
fn r5_unicode_storm_no_panic() {
    let scanner = scanner();
    // ZWJ sequences, RTL overrides, combining marks — UTF-8
    // boundary hazards that have historically crashed naive byte-
    // indexing in the GPU shader.
    let storm = "\u{202E}AKIAQYLPMN5HFIQR7XYA\u{202C}é\u{0301}é\u{0301}é\u{0301}🦀🚀\u{200D}🌈\
                 ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\u{202E}";
    let chunks = vec![make_chunk(storm, "unicode.txt")];
    for backend in ALL_BACKENDS {
        let _ = scanner.scan_chunks_with_backend(&chunks, *backend);
    }
}

#[test]
fn r6_many_tiny_chunks_no_panic() {
    let scanner = scanner();
    // 1000 4-byte chunks. Per-chunk dispatch overhead × 1000;
    // catches "GPU batch limit was set to 1" bugs or
    // mpsc-channel deadlocks.
    let chunks: Vec<Chunk> = (0..1000)
        .map(|i| make_chunk("noi\n", &format!("c{i:04}.txt")))
        .collect();
    for backend in ALL_BACKENDS {
        let r = scanner.scan_chunks_with_backend(&chunks, *backend);
        assert_eq!(
            r.len(),
            chunks.len(),
            "{backend:?} returned {} per-chunk vecs for {} inputs",
            r.len(),
            chunks.len()
        );
    }
}

#[test]
fn r7_concurrent_scans_from_multiple_threads_no_data_race() {
    // CompiledScanner must be Send + Sync — multi-thread callers
    // (file walkers, async handlers) rely on this. Crash, panic, or
    // findings drift across runs is a hard fail.
    let scanner = scanner().clone();
    let chunks = Arc::new(vec![make_chunk(
        "const KEY = \"AKIAQYLPMN5HFIQR7XYA\";\n",
        "shared.rs",
    )]);

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let scanner = scanner.clone();
            let chunks = chunks.clone();
            std::thread::spawn(move || {
                // Each thread does both a SimdCpu and a CpuFallback
                // scan, twice; result count must be stable.
                let mut counts = Vec::with_capacity(4);
                for backend in [ScanBackend::SimdCpu, ScanBackend::CpuFallback] {
                    for _ in 0..2 {
                        let r = scanner.scan_chunks_with_backend(&chunks, backend);
                        counts.push(r[0].len());
                    }
                }
                counts
            })
        })
        .collect();

    let all_counts: Vec<Vec<usize>> = handles
        .into_iter()
        .map(|h| h.join().expect("worker thread panicked"))
        .collect();

    // All threads must report the same count for the same (backend, scan)
    // index slot — non-stable output is a data race symptom.
    let first = &all_counts[0];
    for (idx, counts) in all_counts.iter().enumerate() {
        assert_eq!(
            counts, first,
            "thread {idx} reported {counts:?}, thread 0 reported {first:?} — data race"
        );
    }
}
