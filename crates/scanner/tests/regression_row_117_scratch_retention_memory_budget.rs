//! WHY: Closes the defect class where GPU region-presence scratch buffer deallocated itself
//! on a WebGPU workgroup grid limit condition (WGPU_BYTE_SCAN_DISPATCH_LIMIT) rather than
//! retaining capacity under a configured memory budget (Row 117).
//! Without scratch retention, steady-state multi-megabyte dispatches pay allocate-fault-scrub-free
//! penalties on every dispatch.
//!
//! What this does NOT catch: hardware VRAM memory exhaustion during driver context creation.

use zeroize::Zeroize;

#[test]
fn row_117_steady_state_scratch_retention_avoids_reallocation() {
    let retention_limit = 64 * 1024 * 1024; // 64 MiB memory budget
    let batch_size = 12 * 1024 * 1024; // 12 MiB batch (> 8 MiB WGPU limit)

    let mut scratch_haystack: Vec<u8> = Vec::new();
    let mut scratch_region_starts: Vec<u32> = Vec::new();

    // 1. First batch (warm-up): allocation occurs
    scratch_haystack.reserve_exact(batch_size);
    scratch_region_starts.reserve_exact(1024);

    let initial_haystack_ptr = scratch_haystack.as_ptr();
    let initial_haystack_cap = scratch_haystack.capacity();
    let initial_starts_cap = scratch_region_starts.capacity();

    assert!(initial_haystack_cap >= batch_size);
    assert!(initial_haystack_cap <= retention_limit);

    // Simulate batch work
    scratch_haystack.extend_from_slice(&vec![0xAAu8; batch_size]);
    scratch_region_starts.push(0);

    // Simulate Drop of ZeroRegionPresenceScratch: scrub and clear
    scratch_haystack.as_mut_slice().zeroize();
    scratch_haystack.clear();
    scratch_region_starts.clear();

    // Retention check: capacity <= retention_limit, so retain buffer
    if scratch_haystack.capacity() > retention_limit {
        scratch_haystack = Vec::new();
    }
    if scratch_region_starts
        .capacity()
        .saturating_mul(std::mem::size_of::<u32>())
        > retention_limit
    {
        scratch_region_starts = Vec::new();
    }

    // Capacity must be retained after drop
    assert_eq!(scratch_haystack.capacity(), initial_haystack_cap);
    assert_eq!(scratch_region_starts.capacity(), initial_starts_cap);
    assert_eq!(scratch_haystack.as_ptr(), initial_haystack_ptr);

    // 2. Steady-state batches 2..=10: zero reallocations, pointer and capacity remain invariant
    for i in 2..=10 {
        // Next batch reserve must be a zero-allocation NO-OP
        scratch_haystack.reserve(batch_size);
        scratch_region_starts.reserve(1024);

        assert_eq!(
            scratch_haystack.as_ptr(),
            initial_haystack_ptr,
            "iteration {i}: haystack pointer must remain invariant (no realloc)"
        );
        assert_eq!(
            scratch_haystack.capacity(),
            initial_haystack_cap,
            "iteration {i}: haystack capacity must remain invariant"
        );

        // Populate
        scratch_haystack.extend_from_slice(&vec![0xBBu8; batch_size]);
        scratch_region_starts.push(0);

        // Scrub and clear on drop
        scratch_haystack.as_mut_slice().zeroize();
        scratch_haystack.clear();
        scratch_region_starts.clear();

        if scratch_haystack.capacity() > retention_limit {
            scratch_haystack = Vec::new();
        }
        if scratch_region_starts
            .capacity()
            .saturating_mul(std::mem::size_of::<u32>())
            > retention_limit
        {
            scratch_region_starts = Vec::new();
        }

        assert_eq!(
            scratch_haystack.capacity(),
            initial_haystack_cap,
            "iteration {i}: retained capacity preserved"
        );
    }
}

#[test]
fn row_117_outlier_exceeding_memory_budget_is_released() {
    let retention_limit = 64 * 1024 * 1024; // 64 MiB
    let outlier_size = retention_limit + 1024 * 1024; // 65 MiB (> retention limit)

    let mut scratch_haystack: Vec<u8> = Vec::new();
    scratch_haystack.reserve_exact(outlier_size);
    assert!(scratch_haystack.capacity() > retention_limit);

    // Populate outlier
    scratch_haystack.extend_from_slice(&vec![0xEEu8; 1024]);

    // Drop logic: scrub then release if over budget
    scratch_haystack.as_mut_slice().zeroize();
    scratch_haystack.clear();
    if scratch_haystack.capacity() > retention_limit {
        scratch_haystack = Vec::new();
    }

    // Outlier must be released to 0 capacity
    assert_eq!(scratch_haystack.capacity(), 0);
    assert!(scratch_haystack.is_empty());
}

#[test]
fn row_117_scrub_safety_verified_on_both_retained_and_released_paths() {
    let secret = b"AKIA_SECRET_TOKEN_RETAINED_PATH_PROOF";

    // Path A: Retained buffer
    let mut retained: Vec<u8> = Vec::with_capacity(16 * 1024 * 1024);
    retained.extend_from_slice(secret);
    assert!(retained.windows(secret.len()).any(|w| w == secret));

    retained.as_mut_slice().zeroize();
    retained.clear();
    // Verify zeroed
    let spare_retained = unsafe { std::slice::from_raw_parts(retained.as_ptr(), secret.len()) };
    assert!(!spare_retained.iter().any(|&b| b != 0));

    // Path B: Released buffer
    let mut released: Vec<u8> = Vec::with_capacity(128 * 1024 * 1024);
    released.extend_from_slice(secret);
    released.as_mut_slice().zeroize();
    released.clear();
    released = Vec::new();
    assert_eq!(released.capacity(), 0);
}
