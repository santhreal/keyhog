//! PERF-alloc_perchunk — allocation churn on the per-chunk hot path.
//!
//! KEY: alloc_perchunk
//! VECTOR: SPEED / OPTIMIZATION (Law 7 — extra copies are production bugs at scale).
//!
//! ## The defect
//!
//! Every chunk scanned routes through `CompiledScanner::prepare_chunk`
//! (crates/scanner/src/engine/backend_dispatch.rs:69), which builds a
//! `ScannerPreprocessedText`. On the overwhelmingly common path — a chunk
//! with no structured-config shape and no multiline concatenation indicators
//! (plain source, .env lines, config without continuation) — it takes the
//! passthrough branch:
//!
//!   crates/scanner/src/engine/backend_dispatch.rs:116
//!     `ScannerPreprocessedText::passthrough(data_ref)`
//!
//! which lands at:
//!
//!   crates/scanner/src/multiline/config.rs:63-84  (multiline feature on)
//!     ```
//!     pub fn passthrough(text: &str) -> Self {
//!         ...
//!         Self { text: text.to_string(), original_end, mappings }   // <-- FULL COPY
//!     }
//!     ```
//!   (and the identical `text: text.to_string()` at
//!    crates/scanner/src/multiline/preprocessor.rs:168 and
//!    crates/scanner/src/types.rs:147 for the non-multiline build).
//!
//! `text.to_string()` heap-allocates and memcpy's the ENTIRE chunk body into a
//! fresh `String` on every single chunk, even though `prepare_chunk` already
//! holds a borrow of `chunk.data` for the whole call and the downstream
//! scan reads `preprocessed.text` immutably. The preprocessed text for a
//! passthrough chunk is byte-identical to the input — the copy buys nothing.
//! At fleet scale (hundreds of thousands of files, one chunk each) this is one
//! whole-file-sized allocation + memcpy per file, hammering the global
//! allocator on the hot path the engine spends most of its time in.
//!
//! ## What this tripwire measures (hardware-independent)
//!
//! A `#[global_allocator]` counts total bytes requested during a scan. We scan
//! a passthrough chunk of `N` bytes and again of `2N` bytes (identical shape,
//! no detector hits, prefilters passed) and look at how the per-scan allocation
//! volume GROWS with chunk size:
//!
//!   growth = bytes_alloc(2N) - bytes_alloc(N)
//!
//! Because `passthrough` copies the whole body, `growth >= N` (the extra N
//! bytes of body copied into the second scan's `String`). Once the path
//! borrows the chunk text instead of copying it, the preprocessed `String`
//! disappears and `growth` collapses to the size-independent bookkeeping
//! (line mappings etc.), far below `N`.
//!
//! This is a RATIO/asymptotic assertion on a deterministic allocation COUNTER,
//! not a wall-clock timing, so it does not flake on slow CI hosts — the byte
//! counts are identical on every machine for a given build.
//!
//! Profile: built/run under the workspace `release-fast` characteristics
//! (the prebuilt black-box binary lives at
//! `/mnt/FlareTraining/santh-archive/cargo-target/release-fast/keyhog`); the
//! assertion is profile-independent because it counts bytes, not nanoseconds.
//!
//! ## Measured on the current tree (dev box)
//!
//! With N = 256 KiB the passthrough copy makes `growth` track the body size:
//! growth ~= N (>= 262_144 bytes). The FLOOR is set at N/2 (131_072 bytes) —
//! the real defect overshoots it by ~2x while leaving generous headroom so
//! incidental per-scan allocations never trip it. After the borrow fix,
//! `growth` is a few KiB of line-mapping bookkeeping (well under N/2), so the
//! test passes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use keyhog_core::{Chunk, ChunkMetadata, DetectorFile};
use keyhog_scanner::CompiledScanner;

/// Counts total bytes requested via `alloc` while `COUNTING` is enabled.
struct CountingAlloc;

static BYTES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static COUNTING: AtomicBool = AtomicBool::new(false);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            BYTES_ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            // A growing realloc copies `new_size` fresh bytes — count the
            // delta so buffer GROWTH (e.g. a Vec doubling) is captured too.
            if new_size > layout.size() {
                BYTES_ALLOCATED.fetch_add(new_size - layout.size(), Ordering::Relaxed);
            }
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

fn load_embedded_detectors() -> Vec<keyhog_core::DetectorSpec> {
    let embedded = keyhog_core::embedded_detector_tomls();
    assert!(
        !embedded.is_empty(),
        "no embedded detectors - rebuild keyhog-core with detectors directory"
    );
    embedded
        .iter()
        .filter_map(|(_, toml)| toml::from_str::<DetectorFile>(toml).ok())
        .map(|f| f.detector)
        .collect()
}

/// A passthrough-shaped chunk: realistic source bytes so the alphabet/bigram
/// prefilters in `scan_with_deadline_and_backend` let it reach
/// `prepare_chunk`, but no concatenation indicators (so it takes the
/// `passthrough` branch, NOT the multiline preprocessor) and no real
/// credential (so detector extraction does no body-proportional work that
/// would muddy the size-delta signal).
fn passthrough_chunk(target_bytes: usize) -> Chunk {
    // Each line is benign code-shaped text: letters, an assignment, a quote.
    // It carries enough distinct bytes/bigrams to pass the prefilters but
    // contains no detector literal prefix and no `\` / template-literal /
    // implicit-concatenation indicator that would divert into the multiline
    // path.
    const LINE: &str = "let value_name = compute_label(index_position, lookup_table);\n";
    let mut s = String::with_capacity(target_bytes + LINE.len());
    while s.len() < target_bytes {
        s.push_str(LINE);
    }
    Chunk {
        data: s.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "filesystem".into(),
            // A neutral .rs path: not a sensitive/config name, not `.keyhog`,
            // not under a `detectors/` dir, so nothing short-circuits the scan.
            path: Some("src/module/component_helper.rs".into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
        },
    }
}

/// Run `scan` once and return the bytes the allocator handed out during it.
fn scan_alloc_bytes(scanner: &CompiledScanner, chunk: &Chunk) -> usize {
    BYTES_ALLOCATED.store(0, Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    let matches = scanner.scan(chunk);
    COUNTING.store(false, Ordering::Relaxed);
    // Keep the result observably alive so the scan can't be optimized away,
    // and assert the fixture really is a no-match passthrough so the alloc
    // signal is the preprocessing copy, not match post-processing.
    assert!(
        matches.is_empty(),
        "fixture chunk should produce no matches (got {}); a matching chunk \
         would add body-proportional post-processing allocations and pollute \
         the per-chunk-copy signal",
        matches.len()
    );
    BYTES_ALLOCATED.load(Ordering::Relaxed)
}

#[test]
fn passthrough_prepare_does_not_copy_whole_chunk_body() {
    const N: usize = 256 * 1024; // 256 KiB base chunk
                                 // FLOOR: the per-scan allocation growth from N -> 2N must stay BELOW N/2.
                                 // The full-body `text.to_string()` copy makes growth >= N (one extra copy
                                 // of the extra N bytes), so it trips this floor by ~2x. A borrow-based
                                 // passthrough grows only by size-independent bookkeeping (a few KiB of
                                 // line mappings), far under N/2.
    const FLOOR_BYTES: usize = N / 2;

    let detectors = load_embedded_detectors();
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let chunk_n = passthrough_chunk(N);
    let chunk_2n = passthrough_chunk(2 * N);

    // Warm: first scans lazily allocate HS scratch, regex DFA caches, intern
    // tables, etc. Those are one-time and must NOT be attributed to per-chunk
    // copy cost. Run each size twice up front so the measured pass below sees
    // only steady-state per-chunk allocation.
    for _ in 0..2 {
        let _ = scanner.scan(&chunk_n);
        let _ = scanner.scan(&chunk_2n);
    }

    // Best-of-K on the COUNTER: take the minimum allocation reading across K
    // runs at each size, so any incidental lazy first-touch that slipped past
    // warmup is excluded (the min run has none).
    const K: usize = 3;
    let mut min_n = usize::MAX;
    let mut min_2n = usize::MAX;
    for _ in 0..K {
        min_n = min_n.min(scan_alloc_bytes(&scanner, &chunk_n));
        min_2n = min_2n.min(scan_alloc_bytes(&scanner, &chunk_2n));
    }

    // Growth in per-scan allocation volume as the chunk body doubles.
    let growth = min_2n.saturating_sub(min_n);

    assert!(
        growth < FLOOR_BYTES,
        "PERF-alloc_perchunk-1: per-chunk allocation grows with chunk body \
         size — the passthrough path copies the whole chunk into a fresh \
         String.\n  scan({N}B) allocated {min_n} B; scan({}B) allocated {min_2n} B\n  \
         growth (2N - N) = {growth} B  (must be < {FLOOR_BYTES} B = N/2)\n  \
         Defect: ScannerPreprocessedText::passthrough does `text.to_string()` \
         (crates/scanner/src/multiline/config.rs:80, \
         preprocessor.rs:168, types.rs:147), reached from \
         prepare_chunk (engine/backend_dispatch.rs:116) on every non-multiline \
         chunk. growth >= N here means one full-body copy per chunk.\n  \
         Fix: make the passthrough preprocessed text BORROW chunk.data \
         (Cow<'a, str> / &str) instead of owning a copy, so per-chunk \
         allocation is size-independent and `growth` drops to the line-mapping \
         bookkeeping (a few KiB).",
        2 * N
    );
}
