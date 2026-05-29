//! Failure-oriented adversarial tests for hash primitives.
//!
//! Focus: hostile boundaries, overflow, invalid offsets, property invariants.
#![cfg(feature = "hash")]

use vyre_primitives::hash::{crc32::*, fnv1a::*};

#[test]
fn fnv1a32_empty_is_offset() {
    assert_eq!(fnv1a32(b""), FNV1A32_OFFSET);
}

#[test]
fn fnv1a32_all_zeros() {
    let input = vec![0u8; 1024];
    let h1 = fnv1a32(&input);
    let h2 = fnv1a32(&input);
    assert_eq!(h1, h2, "must be deterministic");
    assert_ne!(h1, FNV1A32_OFFSET, "long input should differ from empty");
}

#[test]
fn fnv1a32_all_ones() {
    let input = vec![0xFFu8; 1024];
    let h = fnv1a32(&input);
    assert_ne!(h, FNV1A32_OFFSET);
}

#[test]
fn fnv1a32_hostile_lengths() {
    for len in [0, 1, 31, 32, 33, 255, 256, 1023, 1024, 65535] {
        let input = vec![0xABu8; len];
        let hash = fnv1a32(&input);
        if len == 0 {
            assert_eq!(hash, FNV1A32_OFFSET);
        } else {
            assert_ne!(hash, FNV1A32_OFFSET);
        }
    }
}

#[test]
fn fnv1a32_single_bit_flip_changes_output() {
    let base = fnv1a32(b"hello");
    for i in 0..5usize {
        let mut mutated = *b"hello";
        mutated[i] ^= 0x01;
        let mutated_hash = fnv1a32(&mutated);
        assert_ne!(base, mutated_hash, "bit flip at byte {i} must change hash");
    }
}

#[test]
fn fnv1a64_empty_is_offset() {
    assert_eq!(fnv1a64(b""), FNV1A64_OFFSET);
}

#[test]
fn fnv1a64_hostile_lengths() {
    for len in [0, 1, 31, 32, 33, 255, 256, 1023, 1024, 65535] {
        let input = vec![0xCDu8; len];
        let hash = fnv1a64(&input);
        if len == 0 {
            assert_eq!(hash, FNV1A64_OFFSET);
        } else {
            assert_ne!(hash, FNV1A64_OFFSET);
        }
    }
}

#[test]
fn crc32_empty_is_zero() {
    assert_eq!(crc32(b""), 0);
}

#[test]
fn crc32_hostile_lengths() {
    for len in [0, 1, 31, 32, 33, 255, 256, 1023, 1024, 65535] {
        let input = vec![0x00u8; len];
        let _ = crc32(&input);
        let input2 = vec![0xFFu8; len];
        let _ = crc32(&input2);
    }
}

#[test]
fn crc32_known_vectors() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(&[0x00]), 0xD202_EF8D);
}

#[test]
fn crc32_table_deterministic() {
    let t1 = build_table();
    let t2 = build_table();
    assert_eq!(t1, t2);
    assert_eq!(t1[0], 0);
    assert_eq!(t1[1], 0x7707_3096);
}
