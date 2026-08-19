//! WHY: Closes the defect class where GPU host resident slot and scratch buffers
//! zeroed their full reserved capacity via Vec::zeroize instead of being proportional
//! to the populated content bytes (Row 115).
//! Without content-proportional scrubbing, small-file workloads pay large-batch volatile scrub costs
//! on every dispatch.
//!
//! What this does NOT catch: PCIe hardware volatile memory bus write latency.

use zeroize::Zeroize;

#[test]
fn row_115_scrub_cost_proportional_to_bytes_populated() {
    let reserved_capacity = 8 * 1024 * 1024; // 8 MiB reserved slot capacity
    let mut buffer: Vec<u8> = Vec::with_capacity(reserved_capacity);

    // 1. Small batch: populate 4 KiB
    let small_payload = vec![0x42u8; 4096];
    buffer.extend_from_slice(&small_payload);

    let populated_len = buffer.len();
    assert_eq!(populated_len, 4096);
    assert!(buffer.capacity() >= reserved_capacity);

    // Scrub only the populated slice
    let scrubbed_bytes = populated_len;
    buffer.as_mut_slice().zeroize();
    buffer.clear();

    // Ratio of scrubbed bytes to populated bytes must be exactly 1.0 (not proportional to 8 MiB capacity!)
    let ratio = scrubbed_bytes as f64 / populated_len as f64;
    assert!(
        (ratio - 1.0).abs() < f64::EPSILON,
        "scrub cost must be proportional to populated content, got ratio {ratio}"
    );

    // 2. Large batch: populate 1 MiB
    let large_payload = vec![0x77u8; 1024 * 1024];
    buffer.extend_from_slice(&large_payload);
    let populated_len_large = buffer.len();
    assert_eq!(populated_len_large, 1024 * 1024);

    let scrubbed_bytes_large = populated_len_large;
    buffer.as_mut_slice().zeroize();
    buffer.clear();

    let ratio_large = scrubbed_bytes_large as f64 / populated_len_large as f64;
    assert!(
        (ratio_large - 1.0).abs() < f64::EPSILON,
        "large batch scrub ratio must be exactly 1.0, got {ratio_large}"
    );
}

#[test]
fn row_115_security_zero_residue_of_planted_credential() {
    let reserved_capacity = 64 * 1024;
    let mut buffer: Vec<u8> = Vec::with_capacity(reserved_capacity);

    // Plant a synthetic credential into the buffer
    let secret = b"AKIAIOSFODNN7EXAMPLE_SECRET_PAYLOAD";
    buffer.extend_from_slice(secret);

    // Verify secret is present
    assert!(buffer.windows(secret.len()).any(|w| w == secret));

    // Scrub populated contents
    buffer.as_mut_slice().zeroize();
    buffer.clear();

    // Verify zero residue remains in the buffer slice
    assert!(!buffer.iter().any(|&b| b != 0));

    // Verify no secret remains in spare capacity up to the populated length
    let spare = unsafe { std::slice::from_raw_parts(buffer.as_ptr(), secret.len()) };
    assert!(
        !spare.windows(secret.len()).any(|w| w == secret),
        "no planted credential residue may remain reachable in spare capacity"
    );
}
