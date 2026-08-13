//! Allocation contract for CPU phase-one trigger evidence.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{hw_probe::ScanBackend, CompiledScanner};

struct CountingAlloc;
static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
static PROBE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) && new_size > layout.size() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn scanner() -> CompiledScanner {
    let patterns = (0..128)
        .map(|index| {
            let prefix = format!("TRIGGER_{index:03}_");
            PatternSpec {
                regex: format!(r"{prefix}[A-Z0-9]{{16}}"),
                required_literals: vec![prefix],
                ..Default::default()
            }
        })
        .collect();
    let detector = DetectorSpec {
        id: "trigger-scratch-fixture".into(),
        name: "trigger-scratch-fixture".into(),
        service: "test".into(),
        severity: Severity::High,
        patterns,
        keywords: vec!["TRIGGER_".into()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    CompiledScanner::compile(vec![detector]).expect("scanner compiles")
}

fn clean_chunks() -> Vec<Chunk> {
    (0..16)
        .map(|index| Chunk {
            data: format!("T{index:02}").into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(format!("src/component_{index:02}.rs").into()),
                ..Default::default()
            },
        })
        .collect()
}

fn trigger_chunks() -> Vec<Chunk> {
    vec![
        Chunk {
            data: "TRIGGER_000_A1B2C3D4E5F6G7H8".into(),
            metadata: ChunkMetadata::default(),
        },
        Chunk {
            data: "plain admitted text without a detector prefix".into(),
            metadata: ChunkMetadata::default(),
        },
    ]
}

fn finding_keys(findings: &[Vec<keyhog_core::RawMatch>]) -> Vec<(usize, String, usize)> {
    let mut keys = findings
        .iter()
        .enumerate()
        .flat_map(|(chunk_index, matches)| {
            matches.iter().map(move |finding| {
                (
                    chunk_index,
                    finding.detector_id.to_string(),
                    finding.location.offset,
                )
            })
        })
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

fn plan_allocations(scanner: &CompiledScanner, chunks: &[Chunk], backend: ScanBackend) -> usize {
    ALLOCATIONS.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let plan = scanner.phase1_admission_plan_for_backend(chunks, backend);
    COUNTING.store(false, Ordering::Relaxed);

    if backend == ScanBackend::CpuFallback {
        for index in 0..chunks.len() {
            let hints = plan
                .cpu_trigger_hints_for_diagnostics(index)
                .expect("clean admitted chunks must retain exact CPU trigger evidence");
            assert!(
                hints.is_empty(),
                "clean fixture unexpectedly triggered a detector"
            );
        }
    }
    std::hint::black_box(plan);
    ALLOCATIONS.load(Ordering::Relaxed)
}

/// WHY: no-hit CPU admission rows must reuse one temporary bitmap instead of
/// allocating one zeroed bitmap per unique chunk. This covers clean rows only;
/// hit rows intentionally retain their exact bitmap for downstream extraction.
#[test]
fn clean_cpu_trigger_rows_add_no_per_chunk_allocations() {
    let _guard = PROBE_LOCK.lock().expect("allocation probe lock");
    let scanner = scanner();
    let chunks = clean_chunks();

    // Warm scanner lazies and the worker-local trigger scratch before measuring.
    let _ = scanner.phase1_admission_plan_for_backend(&chunks, ScanBackend::SimdCpu);
    let _ = scanner.phase1_admission_plan_for_backend(&chunks, ScanBackend::CpuFallback);

    let without_cpu_hints = plan_allocations(&scanner, &chunks, ScanBackend::SimdCpu);
    let with_cpu_hints = plan_allocations(&scanner, &chunks, ScanBackend::CpuFallback);
    eprintln!("trigger evidence allocations: cpu={with_cpu_hints} non_cpu={without_cpu_hints}");
    assert!(
        with_cpu_hints <= without_cpu_hints + 1,
        "clean CPU hints allocated per row: cpu={with_cpu_hints}, non_cpu={without_cpu_hints}"
    );
}

/// WHY: worker-local scratch must be cleared before every payload. A hit
/// followed by a clean row catches stale bits, while scanning with and without
/// the compact admission plan pins finding parity. The allocation test above
/// separately owns the no-hit allocation bound.
#[test]
fn trigger_scratch_clears_between_rows_and_preserves_findings() {
    let _guard = PROBE_LOCK.lock().expect("allocation probe lock");
    let scanner = scanner();
    let chunks = trigger_chunks();
    let plan = scanner.phase1_admission_plan_for_backend(&chunks, ScanBackend::CpuFallback);

    let hit_hints = plan
        .cpu_trigger_hints_for_diagnostics(0)
        .expect("triggered row must retain exact CPU evidence");
    assert!(
        hit_hints.iter().any(|&word| word != 0),
        "hit row unexpectedly lost its trigger bit"
    );
    assert_eq!(
        plan.cpu_trigger_hints_for_diagnostics(1),
        Some([].as_slice()),
        "clean row retained a stale trigger from the prior payload"
    );

    let planned = scanner
        .scan_coalesced_with_backend_and_admission(
            &chunks,
            ScanBackend::CpuFallback,
            Some(&plan),
        )
        .expect("planned CPU scan succeeds");
    let recomputed = scanner
        .scan_coalesced_with_backend(&chunks, ScanBackend::CpuFallback)
        .expect("unplanned CPU scan succeeds");
    assert_eq!(finding_keys(&planned), finding_keys(&recomputed));
    assert_eq!(
        finding_keys(&planned),
        vec![(0, "trigger-scratch-fixture".to_string(), 0)]
    );
}
