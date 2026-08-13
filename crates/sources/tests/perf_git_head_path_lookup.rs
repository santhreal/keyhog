#![cfg(feature = "git")]

use keyhog_sources::testing::GitHeadBlobPaths;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

struct ThreadCountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for ThreadCountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|counting| {
            if counting.get() {
                ALLOCATIONS.set(ALLOCATIONS.get().saturating_add(1));
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get().saturating_add(layout.size()));
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
                ALLOCATIONS.set(ALLOCATIONS.get().saturating_add(1));
                ALLOCATED_BYTES.set(
                    ALLOCATED_BYTES
                        .get()
                        .saturating_add(new_size - layout.size()),
                );
            }
        });
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: ThreadCountingAllocator = ThreadCountingAllocator;

fn oid(hex: &[u8]) -> gix::ObjectId {
    gix::ObjectId::from_hex(hex).expect("valid test object id")
}

fn measure_allocations<T>(run: impl FnOnce() -> T) -> (T, usize, usize) {
    ALLOCATIONS.set(0);
    ALLOCATED_BYTES.set(0);
    COUNTING.set(true);
    let result = run();
    COUNTING.set(false);
    (result, ALLOCATIONS.get(), ALLOCATED_BYTES.get())
}

/// WHY: HEAD classification must borrow each decoded raw path. Constructing an
/// owned `(oid, Vec<u8>)` probe allocated once per emitted Git blob.
#[test]
fn repeated_head_blob_membership_probes_allocate_zero_bytes_after_setup() {
    let live_oid = oid(b"1111111111111111111111111111111111111111");
    let historical_oid = oid(b"2222222222222222222222222222222222222222");
    let live_path = b"nested/live.env".to_vec();
    let historical_path = b"nested/historical.env".to_vec();
    let paths = GitHeadBlobPaths::new([
        (live_oid, live_path.clone()),
        (historical_oid, historical_path.clone()),
    ]);

    assert!(paths.contains(&live_oid, &live_path));
    assert!(!paths.contains(&live_oid, &historical_path));
    assert!(!paths.contains(&historical_oid, &live_path));

    let (matched, allocations, allocated_bytes) = measure_allocations(|| {
        let mut matched = 0usize;
        for _ in 0..10_000 {
            matched += usize::from(black_box(paths.contains(
                black_box(&live_oid),
                black_box(live_path.as_slice()),
            )));
            matched += usize::from(black_box(paths.contains(
                black_box(&historical_oid),
                black_box(live_path.as_slice()),
            )));
        }
        matched
    });

    assert_eq!(matched, 10_000);
    assert_eq!(
        allocations, 0,
        "borrowed HEAD blob membership probes must not allocate"
    );
    assert_eq!(
        allocated_bytes, 0,
        "borrowed HEAD blob membership probes must allocate zero bytes"
    );
}
