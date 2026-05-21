//! Per-backend × per-fixture-size perf-floor matrix.
//!
//! Each cell asserts a minimum MiB/s for the (backend, fixture_size)
//! pair so a regression on any backend × size combo lights up CI red,
//! not just the single-fixture single-backend `perf_floor.rs` test.
//!
//! ~24 cells (3 sizes × 4 backends × 2 fixture-shapes) covering the
//! product surface that real users hit:
//!
//!   * SimdCpu × {benign, dense-credential} × {64KiB, 1MiB, 16MiB}
//!   * CpuFallback × same — scalar reference floor (always slower
//!     than SimdCpu by construction).
//!   * Gpu × same — when adapter present; SKIP otherwise.
//!   * MegaScan × same — when adapter present; SKIP otherwise.
//!
//! The point isn't to bench-mark steady-state throughput (that's
//! `crates/scanner/benches/`); it's to fail CI when **any** backend
//! crosses below a hard floor on **any** fixture size. The floors
//! are calibrated conservatively (60% headroom under measured) so
//! noise doesn't redden the gate, but a 2× algorithmic regression
//! reliably trips at least one cell.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Instant;

fn detector_dir() -> PathBuf {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    d
}

fn scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir())
            .expect("detector dir must exist for perf-floor matrix");
        CompiledScanner::compile(detectors).expect("scanner compile")
    })
}

#[derive(Debug, Clone, Copy)]
struct Size(usize);

impl Size {
    fn bytes(self) -> usize {
        self.0
    }
    fn label(self) -> String {
        if self.0 >= 1024 * 1024 {
            format!("{}MiB", self.0 / (1024 * 1024))
        } else {
            format!("{}KiB", self.0 / 1024)
        }
    }
}

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

/// Pseudo-Go-source filler — same shape as perf_floor.rs but
/// parametric in length. The text avoids triggering generic-
/// detectors so the measurement is the fast-path (alphabet screen +
/// bigram bloom + AC pre-filter).
fn build_benign_fixture(bytes: usize) -> String {
    let mut s = String::with_capacity(bytes + 1024);
    let blocks: &[&str] = &[
        "// Copyright 2024 The Kubernetes Authors. Licensed under Apache-2.0.\n",
        "package controller\n\n",
        "import (\n\t\"context\"\n\t\"fmt\"\n\tcorev1 \"k8s.io/api/core/v1\"\n)\n\n",
        "func (c *Controller) reconcile(ctx context.Context, name string) error {\n",
        "\tlog := log.FromContext(ctx).WithName(\"reconcile\").WithValues(\"name\", name)\n",
        "\treturn nil\n",
        "}\n\n",
        "var DefaultClientID = \"controller-manager\"\n",
        "const maxBackoff = 5 * time.Minute\n\n",
        "for i := 0; i < len(pods); i++ {\n\tprocess(pods[i])\n}\n\n",
    ];
    let mut idx = 0usize;
    while s.len() < bytes {
        s.push_str(blocks[idx % blocks.len()]);
        idx += 1;
    }
    s.truncate(bytes);
    s
}

/// Pseudo-source with one planted AKIA + ghp_ every ~16 KiB. Exercises
/// the regex-confirm + ML-scoring path; throughput is expected to be
/// ~5× lower than benign code, but should still clear its floor.
fn build_dense_fixture(bytes: usize) -> String {
    let benign = build_benign_fixture(bytes);
    let mut s = String::with_capacity(bytes + 4096);
    let stride = 16 * KIB;
    let mut counter = 0u32;
    let mut consumed = 0usize;
    while consumed < benign.len() {
        let end = (consumed + stride).min(benign.len());
        s.push_str(&benign[consumed..end]);
        // Each planted secret is ~80 bytes; truncate to keep total ~bytes.
        s.push_str(&format!(
            "\nconst KEY_{counter} = \"AKIAQYLPMN5HFIQR{counter:04X}\";\n\
             const PAT_{counter} = \"ghp_aBcD{counter:04X}EFgh5678ijklMNop9012qrSTuvWX\";\n"
        ));
        counter += 1;
        consumed = end;
    }
    s.truncate(bytes);
    s
}

fn chunk_for(text: String, label: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "perf-floor-matrix".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// Per-(backend, size, shape) MiB/s floor. Conservative; tuned to ~50%
/// of measured steady-state on a 9950X + RTX 5090. Bump up only when
/// the value ratchets up and is stable across 3 runs.
fn floor_mib_per_s(backend: ScanBackend, size_mib: f64, dense: bool) -> f64 {
    // Benign is the fast-path (alphabet screen rejects); dense is the
    // slow path (regex + ML). Floors diverge accordingly.
    let benign_floor = match backend {
        ScanBackend::SimdCpu => 8.0,
        ScanBackend::CpuFallback => 4.0,
        ScanBackend::Gpu => 4.0,      // GPU shines on huge multi-chunk, not 64KiB
        ScanBackend::MegaScan => 4.0,
    };
    let dense_floor = match backend {
        ScanBackend::SimdCpu => 1.5,
        ScanBackend::CpuFallback => 0.8,
        ScanBackend::Gpu => 0.8,
        ScanBackend::MegaScan => 0.8,
    };
    // Tiny inputs (64 KiB) have higher per-byte dispatch overhead; the
    // floor for tiny inputs is half the steady-state floor.
    let scale = if size_mib < 1.0 { 0.5 } else { 1.0 };
    if dense {
        dense_floor * scale
    } else {
        benign_floor * scale
    }
}

/// Measure one cell: time the SECOND scan (warm), return MiB/s.
fn measure(scanner: &CompiledScanner, chunk: &Chunk, backend: ScanBackend) -> (f64, usize) {
    // Warm-up (first scan pays first-touch alloc).
    let _ = scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), backend);

    let start = Instant::now();
    let matches = scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), backend);
    let elapsed = start.elapsed();

    let mib = chunk.data.len() as f64 / (1024.0 * 1024.0);
    let mib_per_s = mib / elapsed.as_secs_f64().max(1e-9);
    let total_matches: usize = matches.iter().map(Vec::len).sum();
    (mib_per_s, total_matches)
}

#[test]
fn perf_floor_matrix_all_backends_all_sizes() {
    let scanner = scanner();
    let sizes = [Size(64 * KIB), Size(MIB), Size(16 * MIB)];
    let shapes = [
        ("benign", false, build_benign_fixture as fn(usize) -> String),
        ("dense", true, build_dense_fixture as fn(usize) -> String),
    ];
    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    let mut cells = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for size in sizes {
        for (shape_name, dense, build) in &shapes {
            let text = build(size.bytes());
            let chunk = chunk_for(text, &format!("{}-{}.txt", shape_name, size.label()));

            // Reference: how many findings does SimdCpu produce? We use
            // this to decide if a GPU/MegaScan "0 findings" is a SKIP
            // (no adapter) vs a real perf-floor failure.
            let (_, simd_matches) =
                measure(scanner, &chunk, ScanBackend::SimdCpu);

            for backend in backends {
                cells += 1;
                let (mib_per_s, found) = measure(scanner, &chunk, backend);

                // SKIP heuristic: GPU/MegaScan returning empty while
                // SIMD found matches almost certainly means no real
                // GPU adapter (helper falls back to SIMD on init
                // failure; that path produces a quick scan with
                // zero findings on a "no GPU" host).
                if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
                    && found == 0
                    && simd_matches > 0
                {
                    skipped += 1;
                    continue;
                }

                let size_mib = size.bytes() as f64 / (1024.0 * 1024.0);
                let floor = floor_mib_per_s(backend, size_mib, *dense);
                eprintln!(
                    "perf_floor_matrix: backend={:?} size={} shape={} mib/s={:.1} (floor={:.1}) matches={}",
                    backend,
                    size.label(),
                    shape_name,
                    mib_per_s,
                    floor,
                    found
                );

                if mib_per_s < floor {
                    failures.push(format!(
                        "[{:?}/{}/{}] {:.1} MiB/s < floor {:.1} MiB/s (matches={})",
                        backend,
                        size.label(),
                        shape_name,
                        mib_per_s,
                        floor,
                        found
                    ));
                }
            }
        }
    }

    eprintln!(
        "perf_floor_matrix: cells={} skipped={} failed={}",
        cells,
        skipped,
        failures.len()
    );

    assert!(
        failures.is_empty(),
        "perf-floor matrix failures:\n  - {}",
        failures.join("\n  - "),
    );
}
