//! WHY: Scan path counting instrument and low-memory footprint contract (Rows 23, 35, 38, 93):
//! Scan performance and footprint claims must be backed by exact counting instruments
//! (allocation count, allocated bytes, peak footprint) rather than wall-clock timings alone,
//! and the scanner must enforce memory bounds with deterministic failure/rejection rather than
//! unhandled aborts or OOM crashes.
//!
//! WHAT IT DOES NOT CATCH:
//! OS-level kernel page table allocations outside the Rust global allocator.

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

static MEASURE_LOCK: Mutex<()> = Mutex::new(());

struct ScanCountingAllocator;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static TOTAL_BYTES: AtomicUsize = AtomicUsize::new(0);
static CURRENT_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for ScanCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() && COUNTING.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            TOTAL_BYTES.fetch_add(size, Ordering::Relaxed);
            let prev = CURRENT_BYTES.fetch_add(size, Ordering::Relaxed);
            let cur = prev.saturating_add(size);
            let mut peak = PEAK_BYTES.load(Ordering::Relaxed);
            while cur > peak {
                match PEAK_BYTES.compare_exchange_weak(
                    peak,
                    cur,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(actual) => peak = actual,
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size();
        unsafe { System.dealloc(ptr, layout) };
        if COUNTING.load(Ordering::Relaxed) {
            let _ = CURRENT_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(cur.saturating_sub(size))
            });
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old_size = layout.size();
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() && COUNTING.load(Ordering::Relaxed) {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            if new_size > old_size {
                let diff = new_size - old_size;
                TOTAL_BYTES.fetch_add(diff, Ordering::Relaxed);
                let prev = CURRENT_BYTES.fetch_add(diff, Ordering::Relaxed);
                let cur = prev.saturating_add(diff);
                let mut peak = PEAK_BYTES.load(Ordering::Relaxed);
                while cur > peak {
                    match PEAK_BYTES.compare_exchange_weak(
                        peak,
                        cur,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => peak = actual,
                    }
                }
            } else if old_size > new_size {
                let diff = old_size - new_size;
                let _ = CURRENT_BYTES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                    Some(cur.saturating_sub(diff))
                });
            }
        }
        new_ptr
    }
}
#[global_allocator]
static ALLOCATOR: ScanCountingAllocator = ScanCountingAllocator;

fn reset_instrument() {
    ALLOC_COUNT.store(0, Ordering::SeqCst);
    TOTAL_BYTES.store(0, Ordering::SeqCst);
    CURRENT_BYTES.store(0, Ordering::SeqCst);
    PEAK_BYTES.store(0, Ordering::SeqCst);
}

fn measure_scan<T>(f: impl FnOnce() -> T) -> (T, usize, usize, usize) {
    let _guard = MEASURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_instrument();
    COUNTING.store(true, Ordering::SeqCst);
    let res = f();
    COUNTING.store(false, Ordering::SeqCst);
    let count = ALLOC_COUNT.load(Ordering::SeqCst);
    let total = TOTAL_BYTES.load(Ordering::SeqCst);
    let peak = PEAK_BYTES.load(Ordering::SeqCst);
    (res, count, total, peak)
}
fn make_test_scanner() -> CompiledScanner {
    let specs =
        keyhog_core::load_embedded_detectors_or_fail().expect("embedded detectors must load");
    CompiledScanner::compile(specs).expect("compile scanner")
}

#[test]
fn scan_path_counting_instrument_measures_allocations_and_finding_parity() {
    let scanner = make_test_scanner();

    // Planted secrets corpus: AWS Access Key ID + Slack token
    let sample = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nexport SLACK_BOT_TOKEN=xoxb-123456789012-1234567890123-abcdefghijklmnopqrstuvwx\n";
    let chunk = Chunk {
        data: sample.into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };

    // Warm-up run
    let base_findings = scanner.scan(&chunk).expect("base scan");
    assert!(!base_findings.is_empty(), "must find planted secrets");

    // Measured trial 1
    let (findings1, allocs1, total_bytes1, peak1) =
        measure_scan(|| scanner.scan(&chunk).expect("trial 1 scan"));

    // Measured trial 2
    let (findings2, allocs2, total_bytes2, peak2) =
        measure_scan(|| scanner.scan(&chunk).expect("trial 2 scan"));
    // Parity assertion
    assert_eq!(findings1.len(), base_findings.len(), "finding count parity");
    assert_eq!(
        findings2.len(),
        base_findings.len(),
        "finding count parity across trials"
    );
    for (f1, f2) in findings1.iter().zip(findings2.iter()) {
        assert_eq!(f1.detector_id, f2.detector_id, "detector id parity");
        assert_eq!(f1.credential_hash, f2.credential_hash, "hash parity");
    }

    // Allocation stability (Row 38)
    assert_eq!(
        allocs1, allocs2,
        "allocation count must be deterministic across identical scans"
    );
    assert_eq!(
        total_bytes1, total_bytes2,
        "total allocated bytes must be deterministic"
    );
    assert_eq!(peak1, peak2, "peak footprint must be deterministic");
    assert!(
        peak1 <= 10 * 1024 * 1024,
        "peak memory during scan must be well within 10MB limit (got {} bytes)",
        peak1
    );
}

#[test]
fn scan_scaling_ratio_is_bounded_with_chunk_size() {
    let scanner = make_test_scanner();

    let text_small = "const MSG = 'hello world';\n".repeat(100);
    let text_large = "const MSG = 'hello world';\n".repeat(1000);

    let chunk_small = Chunk {
        data: text_small.into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };
    let chunk_large = Chunk {
        data: text_large.into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };

    let (_, _allocs_small, bytes_small, _peak_small) =
        measure_scan(|| scanner.scan(&chunk_small).expect("scan small"));

    let (_, _allocs_large, bytes_large, _peak_large) =
        measure_scan(|| scanner.scan(&chunk_large).expect("scan large"));
    // Ratio validation (Row 35): scan path passthrough must not allocate O(N^2) memory
    let growth = bytes_large.saturating_sub(bytes_small);
    assert!(
        growth < 1024 * 1024,
        "memory growth across 10x input size must remain strictly bounded (growth = {} bytes)",
        growth
    );
}
