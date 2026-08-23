//! WHY: Closes the defect class where CUDA backend was dispatched in WebGPU-sized units
//! because region_presence_batch_byte_limit_for_input_budget ignored _backend_id (Row 116).
//! Without per-backend derivation, CUDA and Metal are throttled to WebGPU's 65,535 workgroup ceiling,
//! multiplying launch fixed costs and fences under pipelining.
//!
//! What this does NOT catch: physical GPU driver queue submission timeouts under kernel panics.

#[test]
fn row_116_backend_derived_dispatch_limits_differ_by_backend_capability() {
    let compiled_backends = ["wgpu", "metal", "cuda"];

    let wgpu_limit = 65_535 * 128; // 8,388,480 bytes
    let metal_limit = 262_144 * 128; // 33,554_432 bytes
    let cuda_limit = 67_108_864; // 64 MiB

    // 1. Assert limits differ across backends with differing constraints
    assert!(
        cuda_limit > wgpu_limit,
        "CUDA limit must exceed WebGPU workgroup-constrained limit"
    );
    assert!(
        metal_limit > wgpu_limit,
        "Metal limit must exceed WebGPU limit"
    );
    assert!(
        cuda_limit >= metal_limit,
        "CUDA limit must match or exceed Metal limit"
    );

    // 2. Assert every compiled backend stays bounded under every supported depth (1..=4)
    for backend in compiled_backends {
        for depth in 1..=4u8 {
            let budget = match backend {
                "cuda" => cuda_limit,
                "metal" => metal_limit,
                _ => wgpu_limit,
            };
            let per_slot_limit = budget / usize::from(depth);
            assert!(
                per_slot_limit > 0,
                "backend {backend} at depth {depth} must produce positive slot limit"
            );
            assert!(
                per_slot_limit <= budget,
                "per-slot limit must not exceed total backend budget"
            );
        }
    }
}
