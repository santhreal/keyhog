//! Regression: base32 decode is NOT part of the keyhog decode pipeline.
//!
//! keyhog ships NO base32 (RFC-4648) decoder, the only base-N style decoders in
//! the default registry are `base64`, `hex` (base16), and `z85` (base85). This
//! file pins that fact together with the full canonical composition/order/count
//! of the default decoder registry, so that:
//!   - a future "add base32" change cannot silently reshuffle the pipeline, and
//!   - the base-N family stays exactly {base64, hex, z85} until deliberately
//!     extended (base32/base16/base85/ascii85 literal names must stay absent).
//!
//! Everything here is host-independent: `default_decoder_names_for_test()`
//! reconstructs the DEFAULT set from `default_decoders()` on every call and does
//! not consult any accelerator (Hyperscan/SIMD/GPU), the global mutable registry,
//! or thread-local registrations. No accel presence is assumed.
#![cfg(feature = "decode")]

use keyhog_scanner::testing::default_decoder_names_for_test as decoder_names;

/// The canonical default decode pipeline (every `name()` in registration order).
/// Mirror of `registry::default_decoders()`; the order is load-bearing (reverse
/// and caesar run last) and base32 is intentionally absent.
const EXPECTED: [&str; 14] = [
    "base64",
    "hex",
    "url",
    "quoted-printable",
    "html-named-entity",
    "html-numeric-entity",
    "octal-escape",
    "mime-encoded-word",
    "json",
    "unicode-escape",
    "z85",
    "javascript-static",
    "reverse",
    "caesar",
];

// ---- base32 absence (the primary contract) --------------------------------

#[test]
fn base32_decoder_is_absent() {
    let names = decoder_names();
    assert!(
        !names.iter().any(|n| *n == "base32"),
        "no decoder named `base32` may exist in the default pipeline; got {names:?}"
    );
}

#[test]
fn absent_base_n_family_literal_names_are_all_missing() {
    // Negative-twin sweep: none of the RFC-4648/ascii85 base-N *literal* decoder
    // names keyhog does NOT implement may appear. `hex` covers base16 and `z85`
    // covers base85, but neither of those literal spellings is a decoder name.
    let names = decoder_names();
    for absent in ["base32", "base16", "base85", "ascii85", "base58", "base62"] {
        assert!(
            !names.iter().any(|n| *n == absent),
            "decoder `{absent}` must not be present; got {names:?}"
        );
    }
}

#[test]
fn present_base_n_decoders_are_exactly_base64_hex_z85() {
    // Positive twin to the absence test: the base-N style decoders that DO exist
    // are precisely these three, in this relative order (base64 first, hex second,
    // z85 near the end just before the evasion decoders).
    let names = decoder_names();
    let base_n: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| matches!(*n, "base64" | "hex" | "z85"))
        .collect();
    assert_eq!(
        base_n,
        vec!["base64", "hex", "z85"],
        "the base-N decoder family must be exactly [base64, hex, z85] in this order"
    );
}

// ---- full composition, order, and count -----------------------------------

#[test]
fn default_pipeline_is_exact_ordered_composition() {
    assert_eq!(
        decoder_names(),
        EXPECTED.to_vec(),
        "default decode pipeline composition/order drifted"
    );
}

#[test]
fn default_pipeline_joined_string_is_exact() {
    // A single strong byte-for-byte assertion over the whole ordered set, any
    // rename, reorder, insertion, or deletion (including sneaking in `base32`)
    // changes this exact string.
    let joined = decoder_names().join(",");
    assert_eq!(
        joined,
        "base64,hex,url,quoted-printable,html-named-entity,\
html-numeric-entity,octal-escape,mime-encoded-word,json,\
unicode-escape,z85,javascript-static,reverse,caesar"
    );
}

#[test]
fn default_decoder_count_is_fourteen() {
    assert_eq!(
        decoder_names().len(),
        14,
        "there are exactly 14 default decoders"
    );
}

#[test]
fn first_decoder_is_base64() {
    assert_eq!(decoder_names().first().copied(), Some("base64"));
}

#[test]
fn last_two_decoders_are_reverse_then_caesar() {
    let names = decoder_names();
    assert_eq!(
        &names[names.len() - 2..],
        &["reverse", "caesar"],
        "evasion decoders reverse+caesar must remain the final two, in that order"
    );
}

#[test]
fn hex_is_index_one_second_decoder() {
    // `hex` (base16) is keyhog's stand-in for base32's sibling; pin its slot so a
    // base32 insertion between base64 and hex would be caught.
    let names = decoder_names();
    assert_eq!(names.get(1).copied(), Some("hex"));
}

#[test]
fn z85_is_index_ten() {
    // z85 (base85) is the 11th decoder (0-based index 10), immediately before
    // static JavaScript recovery and the reverse/caesar evasion pair.
    let names = decoder_names();
    assert_eq!(names.get(10).copied(), Some("z85"));
}

// ---- structural ordering invariants ---------------------------------------

#[test]
fn structural_decoders_precede_evasion_decoders() {
    let names = decoder_names();
    let idx = |target: &str| {
        names
            .iter()
            .position(|n| *n == target)
            .unwrap_or_else(|| panic!("decoder `{target}` missing from {names:?}"))
    };
    let base64 = idx("base64");
    let json = idx("json");
    let reverse = idx("reverse");
    let caesar = idx("caesar");
    assert!(
        base64 < reverse,
        "base64({base64}) must precede reverse({reverse})"
    );
    assert!(
        json < reverse,
        "json({json}) must precede reverse({reverse})"
    );
    assert!(
        reverse < caesar,
        "reverse({reverse}) must precede caesar({caesar})"
    );
    // Exact positions, not just relative order.
    assert_eq!((reverse, caesar), (12, 13));
}

// ---- profiler capacity boundary -------------------------------------------

#[test]
fn default_count_fits_profiler_and_leaves_two_free_slots() {
    // The per-decoder profiler is a fixed [AtomicU64; MAX_PROFILED_DECODERS] with
    // MAX_PROFILED_DECODERS == 16; a decoder past slot 16 is silently un-profiled.
    // 14 defaults leave exactly 2 free slots of headroom.
    let count = decoder_names().len();
    assert!(
        count <= 16,
        "default decoders ({count}) must fit 16 profiler slots"
    );
    assert_eq!(16 - count, 2, "expected exactly 2 free profiler slots");
}

// ---- registry hygiene / adversarial ---------------------------------------

#[test]
fn decoder_names_are_unique_no_duplicates() {
    let names = decoder_names();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        names.len(),
        "default decoder names must be unique; duplicates found in {names:?}"
    );
}

#[test]
fn decoder_names_are_stable_identifiers() {
    // Names are used as profiler/registry keys: they must stay lowercase ASCII
    // (letters, digits, or '-') with no whitespace, so nothing can accidentally
    // register a decoder under a mangled key.
    for name in decoder_names() {
        assert!(!name.is_empty(), "decoder name must not be empty");
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "decoder name `{name}` must be lowercase ascii / digits / '-'"
        );
        assert!(
            !name.contains(char::is_whitespace),
            "decoder name `{name}` must contain no whitespace"
        );
    }
}

#[test]
fn default_decoder_names_are_deterministic_across_calls() {
    // The default set is rebuilt from scratch each call and must not depend on
    // prior calls, global registry mutation, or accelerator state.
    let a = decoder_names();
    let b = decoder_names();
    assert_eq!(
        a, b,
        "default decoder composition must be call-order independent"
    );
    assert_eq!(a, EXPECTED.to_vec());
}
