//! Contract for `stable_hash::StableHasher`: the blake3, length-prefixed stable
//! hasher behind orchestrator config-identity (scan-cache-key) computation.
//! Previously untested directly.
//!
//! The cache reuses a prior scan's results iff the current config hashes to the
//! same 64-bit digest, so the hasher's job is a total, collision-resistant,
//! order- and type-sensitive encoding of a config's fields. A false COLLISION
//! (two distinct configs → same digest) silently serves stale results for the
//! wrong config, a correctness bug, not a perf one. A false SPLIT (the same
//! config → different digests across runs) silently defeats the cache, a Law-7
//! performance bug. These pin both directions:
//!   * determinism, identical field sequences produce identical digests;
//!   * domain sep, the same fields under a different domain differ;
//!   * field-name/value sensitivity, changing either changes the digest;
//!   * type-tag sep: `bool` and `u64` (and `bytes`/`str`) are distinct even
//!                     when their payload bytes coincide (`false` vs `0`);
//!   * option totality: `None`, `Some("")`, and `Some("x")` are three digests;
//!   * width equivalence: `usize` == `u64` of the same magnitude, and
//!                     `f64_bits` == `u64` of `to_bits()` (the documented aliases);
//!   * length-prefix anti-collision: `("ab","")` and `("a","b")` do NOT collide
//!                     (the classic concatenation-ambiguity property that the
//!                     length prefix in `tagged_bytes` exists to defeat);
//!   * field-order sensitivity (swapping two fields changes the digest).

use keyhog::testing::StableHashProbe;

fn probe(domain: &str) -> StableHashProbe {
    StableHashProbe::new(domain)
}

#[test]
fn identical_field_sequences_are_deterministic() {
    let a = probe("scan")
        .str("root", "/repo")
        .u64("depth", 7)
        .bool("follow_symlinks", true)
        .finish();
    let b = probe("scan")
        .str("root", "/repo")
        .u64("depth", 7)
        .bool("follow_symlinks", true)
        .finish();
    assert_eq!(
        a, b,
        "the same domain + field sequence must hash identically"
    );
}

#[test]
fn a_different_domain_changes_the_digest() {
    let scan = probe("scan").str("root", "/repo").finish();
    let index = probe("index").str("root", "/repo").finish();
    assert_ne!(
        scan, index,
        "the same fields under a different domain must not collide"
    );
}

#[test]
fn changing_a_field_name_changes_the_digest() {
    let depth = probe("d").u64("depth", 7).finish();
    let width = probe("d").u64("width", 7).finish();
    assert_ne!(depth, width, "the field NAME is part of the identity");
}

#[test]
fn changing_a_field_value_changes_the_digest() {
    let seven = probe("d").u64("depth", 7).finish();
    let eight = probe("d").u64("depth", 8).finish();
    assert_ne!(seven, eight, "the field VALUE is part of the identity");
}

#[test]
fn bool_false_and_u64_zero_do_not_collide() {
    // Both encode a single zero byte in payload, but the TYPE TAG differs
    // (`bool` vs `u64`: and the u64 payload is 8 bytes, not 1). A collision
    // here would let a boolean flag masquerade as an integer field.
    let as_bool = probe("d").bool("x", false).finish();
    let as_u64 = probe("d").u64("x", 0).finish();
    assert_ne!(
        as_bool, as_u64,
        "bool(false) and u64(0) must be distinguished by their type tag"
    );
}

#[test]
fn bytes_and_str_with_the_same_payload_do_not_collide() {
    let as_str = probe("d").str("x", "hello").finish();
    let as_bytes = probe("d").bytes("x", b"hello").finish();
    assert_ne!(
        as_str, as_bytes,
        "str and bytes carry distinct type tags even with identical payloads"
    );
}

#[test]
fn none_and_some_empty_and_some_value_are_three_distinct_digests() {
    let none = probe("d").opt_str("x", None).finish();
    let some_empty = probe("d").opt_str("x", Some("")).finish();
    let some_val = probe("d").opt_str("x", Some("v")).finish();
    assert_ne!(none, some_empty, "None must differ from Some(\"\")");
    assert_ne!(
        some_empty, some_val,
        "Some(\"\") must differ from Some(\"v\")"
    );
    assert_ne!(none, some_val, "None must differ from Some(\"v\")");
}

#[test]
fn usize_is_equivalent_to_u64_of_the_same_magnitude() {
    // `field_usize` is documented to delegate to `field_u64`: same digest.
    let via_usize = probe("d").usize("n", 42).finish();
    let via_u64 = probe("d").u64("n", 42).finish();
    assert_eq!(
        via_usize, via_u64,
        "usize must hash identically to the u64 of the same value"
    );
}

#[test]
fn f64_bits_is_equivalent_to_u64_of_its_bit_pattern() {
    let f = 3.5f64;
    let via_f64 = probe("d").f64_bits("r", f).finish();
    let via_bits = probe("d").u64("r", f.to_bits()).finish();
    assert_eq!(
        via_f64, via_bits,
        "f64_bits must hash identically to u64(to_bits())"
    );
}

#[test]
fn option_usize_matches_option_u64_of_the_same_magnitude() {
    let via_usize = probe("d").opt_usize("n", Some(9)).finish();
    let via_u64 = probe("d").opt_u64("n", Some(9)).finish();
    assert_eq!(
        via_usize, via_u64,
        "opt_usize(Some(n)) must hash identically to opt_u64(Some(n as u64))"
    );
}

#[test]
fn length_prefixes_defeat_the_concatenation_ambiguity() {
    // The classic collision the length prefix exists to prevent: without it,
    // two adjacent string fields ("ab","") and ("a","b") would concatenate to
    // the same byte stream. `tagged_bytes` prepends each value's length, so the
    // two field sequences MUST produce different digests.
    let ab_empty = probe("d").str("f", "ab").str("g", "").finish();
    let a_b = probe("d").str("f", "a").str("g", "b").finish();
    assert_ne!(
        ab_empty, a_b,
        "length prefixing must prevent (\"ab\",\"\") from colliding with (\"a\",\"b\")"
    );
}

#[test]
fn length_prefixes_defeat_the_ambiguity_for_bytes_too() {
    let ab_empty = probe("d").bytes("f", b"ab").bytes("g", b"").finish();
    let a_b = probe("d").bytes("f", b"a").bytes("g", b"b").finish();
    assert_ne!(
        ab_empty, a_b,
        "byte fields are length-prefixed too, so (\"ab\",\"\") != (\"a\",\"b\")"
    );
}

#[test]
fn swapping_two_fields_changes_the_digest() {
    // The hasher is order-sensitive: the same two fields in a different order
    // are a different config identity.
    let ab = probe("d").u64("a", 1).u64("b", 2).finish();
    let ba = probe("d").u64("b", 2).u64("a", 1).finish();
    assert_ne!(ab, ba, "field ORDER is part of the identity");
}

#[test]
fn a_field_name_can_not_absorb_an_adjacent_value() {
    // A second length-prefix guard, across the name|value boundary: field name
    // "xy" with value "z" must not collide with name "x" and value "yz".
    let xy_z = probe("d").str("xy", "z").finish();
    let x_yz = probe("d").str("x", "yz").finish();
    assert_ne!(
        xy_z, x_yz,
        "the length prefix must keep the field NAME from bleeding into the value"
    );
}
