//! Differential gate for the `matched_caesar_shifts` optimization, migrated out
//! of `src/decode/caesar.rs` (no-inline-tests gate): the set of decoded chunks
//! emitted by shifting ONLY the rotated-prefix-matched `k`s must equal,
//! byte-for-byte, the set emitted by the old exhaustive "try all 25 shifts"
//! path, across 100k+ generated candidates including ones seeded to force every
//! (prefix, shift) alignment. Divergence means the optimization is dropping (or
//! inventing) a decoded variant: a recall/precision bug, not a speedup.

use keyhog_scanner::testing::decode_caesar::{
    caesar_credential_shape_gate, caesar_shift, candidate_shape_invariant, matched_caesar_shifts,
    KNOWN_PREFIXES, MIN_CAESAR_LEN,
};
use std::collections::BTreeSet;

/// Reference: emitted-variant set under the ORIGINAL all-25-shifts loop (gated by
/// `candidate_shape_invariant` + `caesar_credential_shape_gate`, exactly as the
/// pre-optimization code was).
fn reference_emit(candidate: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if candidate.len() < MIN_CAESAR_LEN || !candidate_shape_invariant(candidate) {
        return out;
    }
    for shift in 1..=25u8 {
        let decoded = caesar_shift(candidate, shift);
        if caesar_credential_shape_gate(&decoded) {
            out.insert(decoded);
        }
    }
    out
}

/// Optimized: shift only the matched `k`s, same per-shift predicate.
fn optimized_emit(candidate: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if candidate.len() < MIN_CAESAR_LEN || !candidate_shape_invariant(candidate) {
        return out;
    }
    let try_shift = matched_caesar_shifts(candidate);
    for shift in 1..=25u8 {
        if !try_shift[shift as usize] {
            continue;
        }
        let decoded = caesar_shift(candidate, shift);
        if caesar_credential_shape_gate(&decoded) {
            out.insert(decoded);
        }
    }
    out
}

// Deterministic xorshift64 (no rand dependency, reproducible across runs).
fn next(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[test]
fn matched_shifts_emit_identical_set_to_all_25() {
    let mut state = 0x9E3779B97F4A7C15u64;
    let prefixes: Vec<&str> = (&*KNOWN_PREFIXES).iter().map(|s| s.as_str()).collect();
    let mut checked = 0u64;
    for i in 0..100_000u64 {
        // Build a random alnum candidate of length 8..=48.
        let len = 8 + (next(&mut state) % 41) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let b = ALNUM[(next(&mut state) as usize) % ALNUM.len()];
            s.push(b as char);
        }
        // For ~half the cases, splice in a back-rotated known prefix so the
        // matched-shift path actually fires (and so some shift CAN pass the
        // predicate). needle(P,k) = caesar_shift(P, 26-k); embedding it makes
        // shift `k` of the candidate contain P.
        if i % 2 == 0 && !prefixes.is_empty() {
            let p = prefixes[(next(&mut state) as usize) % prefixes.len()];
            let k = 1 + (next(&mut state) % 25) as u8;
            let needle = caesar_shift(p, 26 - k);
            if !needle.is_empty() {
                let pos = (next(&mut state) as usize) % (s.len() + 1);
                // Only splice at a char boundary (all ASCII here, so any index).
                s.insert_str(pos.min(s.len()), &needle);
                // Guarantee a digit + 8-run survive for shape invariance.
                s.push_str("0ABCDEFGH");
            }
        }
        let reference = reference_emit(&s);
        let optimized = optimized_emit(&s);
        assert_eq!(
            reference, optimized,
            "shift-selection diverged on candidate {s:?} (case {i})"
        );
        checked += 1;
    }
    assert_eq!(checked, 100_000);
}
