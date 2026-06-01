//! Migrated from src/entropy_fast.rs — SIMD-vs-scalar entropy parity.
//!
//! The misalignment-boundary differential (the unrolled SIMD entropy kernel
//! must agree with both the naive scalar path and an independent reference
//! over a sweep of misaligned offsets/lengths) lives here rather than inline,
//! per the Santh folder contract (KH-GAP-004).

use keyhog_scanner::entropy_fast::{shannon_entropy_scalar, shannon_entropy_simd};

/// Reference Shannon entropy (bits/byte). Deliberately naive (a fresh
/// 256-bin histogram, no unrolling) so it cannot share a bug with the
/// implementation under test.
///
/// The test inputs below contain NO null bytes, so the null-skip branch
/// (present in the scalar / AVX2 / SSE2 / NEON paths but NOT the AVX-512
/// path, which counts every byte) is a no-op and all code paths agree.
/// That keeps the cross-check valid on every CPU feature level - the
/// misalignment bug under test is independent of null handling.
fn reference_entropy(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    if data.is_empty() {
        return 0.0;
    }
    let len = data.len() as f64;
    let mut e = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            e -= p * p.log2();
        }
    }
    e
}

/// The AVX2/SSE2 paths align the read pointer with a byte-at-a-time prologue
/// and then run an aligned-vector loop. The loop bound must account for that
/// prologue offset; a `len & !31` bound (the pre-fix code) over-reads past the
/// slice and issues an aligned vector load from an unaligned address whenever
/// the prologue advanced the cursor.
///
/// Drive `shannon_entropy_simd` over a misaligned base pointer across a sweep
/// of lengths that straddle the 16/32-byte boundaries, and require it to agree
/// with both the scalar path and the independent reference.
#[test]
fn simd_matches_scalar_on_misaligned_slices() {
    // A varied, non-trivial byte pattern (repeats, mixed high/low) in a heap
    // buffer. No null bytes: see `reference_entropy` - that keeps the
    // SIMD-vs-scalar cross-check valid across all CPU feature levels.
    let mut backing = vec![0u8; 4096];
    for (i, slot) in backing.iter_mut().enumerate() {
        // 1..=250, never 0, so every path histograms the same bytes.
        *slot = ((i * 131 + 7) % 250 + 1) as u8;
    }

    // Offsets 0..=7 guarantee at least one base that is not 32-aligned;
    // lengths around each 16/32 multiple expose off-by-one boundary bugs.
    for offset in 0..8usize {
        for len in 0..200usize {
            if offset + len > backing.len() {
                continue;
            }
            let slice = &backing[offset..offset + len];
            let simd = shannon_entropy_simd(slice);
            let scalar = shannon_entropy_scalar(slice);
            let reference = reference_entropy(slice);
            // The AVX-512 entropy path uses a polynomial log2 approximation
            // (no table-lookup shortcut), so the band must tolerate its ~1e-3
            // approximation error. The misalignment bug under test corrupted
            // the histogram and threw the result off by O(0.1)+ bits, an order
            // of magnitude outside this band, so 2e-2 still catches a
            // regression cleanly while never flaking on AVX-512.
            assert!(
                (simd - scalar).abs() < 2e-2,
                "SIMD/scalar entropy diverged at offset={offset} len={len}: \
                 simd={simd} scalar={scalar}"
            );
            assert!(
                (simd - reference).abs() < 2e-2,
                "SIMD entropy left the reference band at offset={offset} \
                 len={len}: simd={simd} reference={reference}"
            );
        }
    }
}

/// Concrete, hand-checkable value: 64 bytes that are 4 distinct symbols in
/// equal proportion have exactly log2(4) = 2.0 bits/byte of entropy. Placed at
/// a deliberately misaligned offset so the aligned-loop path runs over a
/// non-32-aligned base.
#[test]
fn simd_known_entropy_value_misaligned() {
    let mut backing = vec![0xAAu8; 1]; // 1-byte pad to misalign the slice
    for i in 0..64u8 {
        backing.push(b"ABCD"[(i % 4) as usize]);
    }
    let slice = &backing[1..]; // 64 bytes, base = backing.as_ptr()+1
    let e = shannon_entropy_simd(slice);
    // 2e-2 band: the AVX-512 path computes this via a polynomial log2
    // approximation rather than the exact table-lookup the shorter-vector
    // paths use for len<=255, so the value lands very close to but not
    // bit-exactly 2.0 on AVX-512 hardware.
    assert!(
        (e - 2.0).abs() < 2e-2,
        "expected ~2.0 bits/byte for 4 equal symbols, got {e}"
    );
}

#[test]
fn simd_null_bytes_match_scalar_semantics() {
    let data = b"\0\0\0ABCDABCD\0EFGH1234\0";
    let simd = shannon_entropy_simd(data);
    let scalar = shannon_entropy_scalar(data);
    assert!(
        (simd - scalar).abs() < f64::EPSILON,
        "SIMD/scalar null-byte entropy diverged: simd={simd} scalar={scalar}"
    );
}
