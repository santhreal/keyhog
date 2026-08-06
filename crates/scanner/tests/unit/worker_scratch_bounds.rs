use super::{release_candidate_scratch, MAX_RETAINED_WORKER_SCRATCH_BYTES};

/// WHY: one anchor-dense chunk may need a large transient candidate vector, but a Rayon worker reused by a later CPU or SIMD route must not retain that outlier allocation indefinitely.
#[test]
fn host_anchor_candidate_outlier_is_released_between_routes() {
    let element_bytes = std::mem::size_of::<(u32, u32)>();
    let retained_elements = MAX_RETAINED_WORKER_SCRATCH_BYTES / element_bytes;
    let mut candidates = Vec::with_capacity(retained_elements + 1);
    candidates.push((7, 11));

    release_candidate_scratch(&mut candidates);

    assert!(candidates.is_empty());
    assert_eq!(candidates.capacity(), 0);
}

/// WHY: single-chunk VYRE dispatch scratch belongs only to the selected GPU route; an outlier must be zeroed, emptied, and released before that worker can serve a host route.
#[test]
fn gpu_literal_outlier_is_zeroed_and_released() {
    let mut scratch = vyre_libs::scan::dispatch_io::ScanDispatchScratch::default();
    scratch
        .haystack_bytes
        .reserve_exact(crate::types::MAX_SCAN_CHUNK_BYTES + 1);
    scratch
        .hit_bytes
        .reserve_exact(crate::types::MAX_SCAN_CHUNK_BYTES + 1);
    scratch
        .haystack_bytes
        .extend_from_slice(b"credential-adjacent-haystack");
    scratch
        .hit_bytes
        .extend_from_slice(b"credential-adjacent-results");

    super::gpu_literal_scratch::zero_scan_dispatch_scratch(&mut scratch);

    assert!(scratch.haystack_bytes.is_empty());
    assert!(scratch.hit_bytes.is_empty());
    assert_eq!(scratch.haystack_bytes.capacity(), 0);
    assert_eq!(scratch.hit_bytes.capacity(), 0);
}

/// WHY: coalesced GPU batching may fill the portable dispatch grid, but its thread-local host buffers must never retain more than that selected-route ceiling after a dispatch.
#[cfg(feature = "gpu")]
#[test]
fn gpu_region_outlier_is_released_to_portable_route_bound() {
    let mut scratch = super::gpu_region_batch::RegionPresenceScratch::default();
    scratch.reserve_outlier_for_test();
    {
        let _guard = super::gpu_region_batch::ZeroRegionPresenceScratch::new(&mut scratch);
    }

    assert!(scratch.is_empty());
    assert_eq!(scratch.retained_bytes_for_test(), (0, 0));
}
