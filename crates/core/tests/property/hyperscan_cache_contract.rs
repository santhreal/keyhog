//! Property / robustness invariants for the shared Hyperscan cache header
//! contract (`keyhog_core::{hyperscan_cache_header_is_valid,
//! write_hyperscan_cache_header, hyperscan_cache_filename}`).
//!
//! The 8-byte header (`magic + little-endian version`) is what lets the scanner
//! TRUST a serialized compiled-pattern database on disk instead of recompiling
//! from the detector rules. It MUST fail closed: any header that is not
//! byte-exactly the current magic+version has to be REJECTED. If the validator
//! ever accepted a stale (old-version), corrupt, or truncated header, the
//! scanner would load the WRONG compiled patterns and silently scan with reduced
//! recall, a miss the operator cannot see. So "reject everything but the exact
//! header" is a recall-safety invariant, not a nicety.
//!
//! Fixed-vector coverage of the write/validate round-trip lives in
//! `regression_hyperscan_cache_header`; this file sweeps the fail-closed
//! boundary (every single-byte mutation, every wrong length, every wrong
//! version) and the filename-format contract. Assertions pin exact booleans /
//! bytes, never a shape check.

use keyhog_core::{
    hyperscan_cache_filename, hyperscan_cache_header_is_valid, write_hyperscan_cache_header,
    HYPERSCAN_CACHE_HEADER_LEN, HYPERSCAN_CACHE_MAGIC, HYPERSCAN_CACHE_VERSION,
};
use proptest::prelude::*;

fn canonical_header() -> Vec<u8> {
    let mut h = Vec::new();
    write_hyperscan_cache_header(&mut h);
    h
}

#[test]
fn written_header_is_valid_and_canonical() {
    let h = canonical_header();
    assert_eq!(h.len(), HYPERSCAN_CACHE_HEADER_LEN);
    assert!(hyperscan_cache_header_is_valid(&h));
    assert_eq!(&h[..4], &HYPERSCAN_CACHE_MAGIC[..]);
    assert_eq!(
        u32::from_le_bytes([h[4], h[5], h[6], h[7]]),
        HYPERSCAN_CACHE_VERSION
    );
}

#[test]
fn any_single_byte_mutation_is_rejected() {
    // The validator is EXACT: perturbing any single byte of the canonical header
    // must make it invalid, a corrupted magic OR a bumped/rolled version, so
    // the scanner rebuilds from patterns instead of trusting stale bytes.
    let base = canonical_header();
    for pos in 0..base.len() {
        for b in 0u8..=255 {
            if b == base[pos] {
                continue;
            }
            let mut m = base.clone();
            m[pos] = b;
            assert!(
                !hyperscan_cache_header_is_valid(&m),
                "mutated header (pos {pos} -> {b}) must be rejected: {m:?}"
            );
        }
    }
}

#[test]
fn wrong_length_is_rejected() {
    // Any length other than the exact header length is rejected, including a
    // VALID header followed by extra bytes (no prefix acceptance) and any
    // truncation of it.
    let base = canonical_header();
    for len in 0..=(HYPERSCAN_CACHE_HEADER_LEN * 2) {
        if len == HYPERSCAN_CACHE_HEADER_LEN {
            continue;
        }
        let mut buf = base.clone();
        buf.resize(len, 0u8);
        assert!(
            !hyperscan_cache_header_is_valid(&buf),
            "header of length {len} (!= {HYPERSCAN_CACHE_HEADER_LEN}) must be rejected"
        );
    }
    // Empty input is rejected too.
    assert!(!hyperscan_cache_header_is_valid(&[]));
}

#[test]
fn filename_format_and_determinism() {
    // Deterministic, embeds the shard key verbatim, and wears the shared
    // `hs-`/`.db` affixes so writer and lockdown-gate reader never disagree.
    for k in ["", "abc", "0123456789abcdef", "a/b", "weird key .db"] {
        let f = hyperscan_cache_filename(k);
        assert_eq!(f, hyperscan_cache_filename(k), "must be deterministic");
        assert!(f.starts_with("hs-"), "must carry the shared prefix: {f}");
        assert!(f.ends_with(".db"), "must carry the shared suffix: {f}");
        // Stripping the affixes recovers exactly the shard key (round-trip).
        let inner = f
            .strip_prefix("hs-")
            .and_then(|s| s.strip_suffix(".db"))
            .expect("filename must carry both affixes");
        assert_eq!(inner, k, "affix strip must recover the shard key");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// An arbitrary 8-byte buffer validates IFF it is exactly the canonical
    /// magic+version (the validator has no other accepting input).
    #[test]
    fn only_the_exact_header_validates(bytes in prop::array::uniform8(any::<u8>())) {
        let valid = hyperscan_cache_header_is_valid(&bytes);
        let is_canonical = &bytes[..4] == &HYPERSCAN_CACHE_MAGIC[..]
            && u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
                == HYPERSCAN_CACHE_VERSION;
        prop_assert_eq!(valid, is_canonical);
    }

    /// A right-magic but WRONG-version header is always rejected, the stale-cache
    /// guard: a v1 or v3 serialized database must never be trusted as the current
    /// version.
    #[test]
    fn right_magic_wrong_version_is_rejected(
        version in any::<u32>().prop_filter("not current", |v| *v != HYPERSCAN_CACHE_VERSION)
    ) {
        let mut h = HYPERSCAN_CACHE_MAGIC.to_vec();
        h.extend_from_slice(&version.to_le_bytes());
        prop_assert!(!hyperscan_cache_header_is_valid(&h));
    }

    /// The filename map is injective: distinct shard keys never collide onto one
    /// cache file (a collision would let one shard's compiled DB masquerade as
    /// another's).
    #[test]
    fn distinct_shard_keys_give_distinct_filenames(
        a in "[a-zA-Z0-9._/-]{0,32}",
        b in "[a-zA-Z0-9._/-]{0,32}",
    ) {
        prop_assume!(a != b);
        prop_assert_ne!(hyperscan_cache_filename(&a), hyperscan_cache_filename(&b));
    }
}
