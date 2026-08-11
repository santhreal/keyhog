//! Allocation contract for production coalesced batch topology construction.

use keyhog_core::{Chunk, ChunkMetadata};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

struct ThreadCountingAlloc;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for ThreadCountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get() + 1);
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get() + layout.size());
            }
        });
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() && new_size > layout.size() {
                ALLOCATIONS.set(ALLOCATIONS.get() + 1);
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get() + new_size - layout.size());
            }
        });
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: ThreadCountingAlloc = ThreadCountingAlloc;

fn measure_allocations<T>(run: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCATIONS.set(0);
    ALLOCATED_BYTES.set(0);
    COUNTING.set(true);
    let result = run();
    COUNTING.set(false);
    (result, ALLOCATIONS.get(), ALLOCATED_BYTES.get())
}

/// WHY: every small work lane previously owned a separate `Vec<usize>`, so the
/// production 1,024-chunk/32-worker topology made 34 allocations. One flat
/// membership buffer plus the lane descriptor buffer closes that allocation
/// class. This test does not measure allocator-internal byte rounding.
#[test]
fn production_small_lane_topology_uses_two_allocations() {
    const CHUNKS: usize = 1024;
    const WORKERS: usize = 32;
    const THRESHOLD: usize = 64 * 1024;
    let chunks: Vec<Chunk> = (0..CHUNKS)
        .map(|_| Chunk {
            data: "x".into(),
            metadata: ChunkMetadata::default(),
        })
        .collect();

    let (shape, allocations, allocated_bytes) = measure_allocations(|| {
        black_box(
            keyhog_scanner::testing::chunk_lane_storage_shape_for_chunks_for_test(
                black_box(&chunks),
                THRESHOLD,
                WORKERS,
            ),
        )
    });

    assert_eq!(shape, (WORKERS, CHUNKS, 1));
    assert_eq!(
        allocations, 2,
        "topology allocated {allocations} blocks ({allocated_bytes} bytes); expected one flat index buffer and one lane descriptor buffer"
    );
}
