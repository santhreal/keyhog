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

fn legacy_small_lane_topology(
    chunks: &[Chunk],
    threshold: usize,
    workers: usize,
) -> Vec<Vec<usize>> {
    let small_indices: Vec<usize> = chunks
        .iter()
        .enumerate()
        .filter_map(|(index, chunk)| (chunk.data.len() <= threshold).then_some(index))
        .collect();
    let worker_lane_width = small_indices.len().div_ceil(workers).max(1);
    let max_small_chunk_bytes = small_indices
        .iter()
        .map(|&index| chunks[index].data.len())
        .max()
        .unwrap_or(0);
    let byte_bounded_width = if max_small_chunk_bytes == 0 {
        worker_lane_width
    } else {
        ((512 * 1024) / max_small_chunk_bytes).max(1)
    };
    let lane_width = worker_lane_width.min(byte_bounded_width).max(1);
    small_indices
        .chunks(lane_width)
        .map(<[usize]>::to_vec)
        .collect()
}

/// WHY: every small work lane previously owned a separate `Vec<usize>`. One
/// flat membership buffer plus the lane descriptor buffer closes that
/// allocation class. This test does not measure allocator-internal byte
/// rounding.
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

    let (legacy_lanes, legacy_allocations, legacy_allocated_bytes) = measure_allocations(|| {
        black_box(legacy_small_lane_topology(
            black_box(&chunks),
            THRESHOLD,
            WORKERS,
        ))
    });
    assert_eq!(legacy_lanes.iter().map(Vec::len).sum::<usize>(), CHUNKS);

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
    assert!(
        legacy_allocations >= allocations * 10,
        "legacy={legacy_allocations} allocations/{legacy_allocated_bytes} bytes candidate={allocations} allocations/{allocated_bytes} bytes"
    );
    eprintln!(
        "batch topology allocations: legacy={legacy_allocations} ({legacy_allocated_bytes} bytes) candidate={allocations} ({allocated_bytes} bytes)"
    );
}
