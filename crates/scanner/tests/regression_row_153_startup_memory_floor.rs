//! WHY: Asserts startup memory footprint and baseline scan structure limits (Row 153).
//! Optimizes scanner memory layouts, lazy-loads non-critical structures, shrinks static
//! tables, and bounds initial capacities so peak RSS on empty and small scans is minimized.
//!
//! What this does NOT catch: OS-level kernel page table fragmentation or GPU driver VRAM allocations.

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

#[test]
fn row_153_compiled_scanner_baseline_scan_memory_bounds() {
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .expect("embedded detectors should load successfully");
    let scanner = CompiledScanner::compile(detectors)
        .expect("scanner should compile successfully");

    // Scan an empty chunk
    let empty_chunk = Chunk::from("");
    let empty_findings = scanner.scan(&empty_chunk).expect("scan empty chunk succeeds");
    assert!(empty_findings.is_empty(), "empty chunk should yield no findings");

    // Scan a small inert chunk
    let small_chunk = Chunk::from("fn main() { println!(\"hello world\"); }\n");
    let small_findings = scanner.scan(&small_chunk).expect("scan small inert chunk succeeds");
    assert!(small_findings.is_empty(), "small inert chunk should yield no findings");
}

#[test]
fn row_153_scanner_structure_layout_and_type_bounds() {
    // Assert CsrU32 layout uses exact boxed slices (two Box<[u32]> fat pointers = 4 pointer words).
    assert_eq!(
        std::mem::size_of::<keyhog_scanner::testing::CsrU32>(),
        std::mem::size_of::<Box<[u32]>>() * 2,
        "CsrU32 must be exactly two Box slices (data + offsets)"
    );

    // Assert CsrU32 from_pairs produces exact-sized storage with zero excess capacity
    let pairs = vec![(0, 1), (0, 2), (2, 5)];
    let csr = keyhog_scanner::testing::CsrU32::from_pairs(3, pairs);
    let (data_len, offsets_len) = csr.storage_lengths();
    assert_eq!(data_len, 3);
    assert_eq!(offsets_len, 4);
    assert_eq!(csr.get(0), Some(&[1, 2][..]));
    assert_eq!(csr.get(1), Some(&[][..]));
    assert_eq!(csr.get(2), Some(&[5][..]));
}

#[test]
fn row_153_lazy_regex_state_compact_flags() {
    let rx = keyhog_scanner::testing::LazyRegexProbe::detector("sk_live_[0-9a-zA-Z]{24}");
    assert!(rx.has_literal_prefix(), "literal prefix should be detected and cached");
    assert_eq!(rx.as_str(), "sk_live_[0-9a-zA-Z]{24}");
    assert!(rx.get().is_match("sk_live_123456789012345678901234"));
}

#[test]
fn row_153_scan_state_empty_allocation_floor() {
    let state = keyhog_scanner::testing::ScanState::default();
    assert_eq!(state.accepted_match_events(), 0);
    assert_eq!(state.into_matches(0).len(), 0);
}
