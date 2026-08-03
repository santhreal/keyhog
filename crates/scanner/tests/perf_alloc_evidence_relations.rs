//! Allocation bound for compiled cross-detector evidence resolution.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use keyhog_core::{
    Chunk, DetectorRelationKind, DetectorRelationSpec, DetectorSpec, EvidenceDirection,
    PatternSpec, Severity,
};
use keyhog_scanner::CompiledScanner;

struct CountingAlloc;
static COUNTING: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) && new_size > layout.size() {
            BYTES.fetch_add(new_size - layout.size(), Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn detector(id: &str, prefix: &str, relations: Vec<DetectorRelationSpec>) -> DetectorSpec {
    DetectorSpec {
        id: id.into(),
        name: id.into(),
        service: "test".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: format!(r"{prefix}[A-Z0-9]{{20}}"),
            required_literals: vec![prefix.into()],
            ..Default::default()
        }],
        keywords: vec![prefix.into()],
        detector_relations: relations,
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("github-classic-pat")
            .and_then(|spec| spec.match_confidence),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

fn scanner(with_relation: bool) -> CompiledScanner {
    let relations = with_relation
        .then(|| DetectorRelationSpec {
            detector_id: "target".into(),
            kind: DetectorRelationKind::Requires,
            within_lines: 0,
            within_bytes: Some(128),
            direction: EvidenceDirection::Either,
        })
        .into_iter()
        .collect();
    CompiledScanner::compile(vec![
        detector("owner", "OWN_", relations),
        detector("target", "TGT_", Vec::new()),
    ])
    .expect("allocation fixture compiles")
}

fn fixture() -> Chunk {
    let mut text = String::new();
    for _ in 0..128 {
        text.push_str("TGT_4Qm8Za2Lc7Nv5Xk9Bp3R OWN_7Gk2Nq9Vm4Xs8Wp3Dz6H\n");
    }
    Chunk::from(text)
}

fn resolution_bytes(scanner: &CompiledScanner, chunk: &Chunk) -> (usize, usize) {
    let matches = scanner.scan(chunk).expect("allocation fixture scans");
    let count = matches.len();
    BYTES.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let resolved = scanner
        .try_resolve_matches(matches)
        .expect("allocation fixture resolves");
    COUNTING.store(false, Ordering::Relaxed);
    assert_eq!(resolved.len(), count);
    (BYTES.load(Ordering::Relaxed), count)
}

/// Relation indexing may allocate per finding, but its incremental cost must stay bounded and linear.
#[test]
fn compiled_relation_resolution_allocation_overhead_is_bounded() {
    let chunk = fixture();
    let (baseline_bytes, count) = resolution_bytes(&scanner(false), &chunk);
    let (relation_bytes, relation_count) = resolution_bytes(&scanner(true), &chunk);
    assert_eq!(relation_count, count);
    let overhead = relation_bytes.saturating_sub(baseline_bytes);
    eprintln!(
        "evidence relation allocation: baseline={baseline_bytes} relation={relation_bytes} overhead={overhead} findings={count}"
    );
    assert!(
        overhead <= count * 512 + 16_384,
        "relation resolution allocated {overhead} incremental bytes for {count} findings"
    );
}
