//! Regression pins for the decode-pipeline default decoder registry
//! composition (`crates/scanner/src/decode/pipeline/registry.rs`).
//!
//! The registration ORDER is load-bearing: `base64` must run FIRST (structural,
//! highest-yield unwrap) and the `reverse` + `caesar` transposition decoders
//! must run LAST, after every structural decoder, so the pipeline never feeds a
//! caesar-mangled span into a structural stage. The count is fixed at 13 and
//! must stay within the profiler's slot capacity. `base32` / `base58` are
//! deliberately NOT in the default set (only `z85` from the ascii85/z85 family
//! is), so a stray addition of them must be caught here.
//!
//! Every assertion pins a concrete literal name or index — a reorder, rename,
//! add, or drop turns one of these red. Host-independent: the registry
//! composition is a pure compile-time vector, no accelerator involved.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::default_decoder_names_for_test;

/// The canonical decode-pipeline composition, in registration order. Mirrors
/// `default_decoders()` verbatim.
const EXPECTED: [&str; 13] = [
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
    "reverse",
    "caesar",
];

#[test]
fn full_ordered_vector_matches_canonical() {
    let names = default_decoder_names_for_test();
    assert_eq!(
        names,
        EXPECTED.to_vec(),
        "decode registry order/composition drifted from the pinned canonical list"
    );
}

#[test]
fn exactly_thirteen_decoders() {
    let names = default_decoder_names_for_test();
    assert_eq!(
        names.len(),
        13,
        "default decoder count must stay 13 (profiler slot capacity)"
    );
}

#[test]
fn base64_is_first() {
    let names = default_decoder_names_for_test();
    assert_eq!(
        names[0], "base64",
        "base64 must be the FIRST default decoder"
    );
    assert_eq!(
        names.iter().position(|&n| n == "base64"),
        Some(0),
        "base64 must occupy index 0 exactly"
    );
}

#[test]
fn caesar_is_last() {
    let names = default_decoder_names_for_test();
    assert_eq!(
        names[names.len() - 1],
        "caesar",
        "caesar must be the LAST default decoder"
    );
    assert_eq!(
        names.iter().position(|&n| n == "caesar"),
        Some(12),
        "caesar must occupy index 12 exactly"
    );
}

#[test]
fn reverse_is_second_to_last() {
    let names = default_decoder_names_for_test();
    assert_eq!(
        names[names.len() - 2],
        "reverse",
        "reverse must be the SECOND-TO-LAST default decoder"
    );
    assert_eq!(
        names.iter().position(|&n| n == "reverse"),
        Some(11),
        "reverse must occupy index 11 exactly"
    );
}

#[test]
fn caesar_and_reverse_are_the_final_two() {
    let names = default_decoder_names_for_test();
    let tail: Vec<&str> = names[names.len() - 2..].to_vec();
    assert_eq!(
        tail,
        vec!["reverse", "caesar"],
        "the transposition decoders must be the last two, in reverse-then-caesar order"
    );
}

#[test]
fn every_structural_decoder_precedes_reverse_and_caesar() {
    let names = default_decoder_names_for_test();
    let reverse_idx = names.iter().position(|&n| n == "reverse").unwrap();
    let caesar_idx = names.iter().position(|&n| n == "caesar").unwrap();
    // All 11 structural decoders must sit strictly before both transposition ones.
    for structural in &[
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
    ] {
        let idx = names.iter().position(|n| n == structural).unwrap();
        assert!(
            idx < reverse_idx && idx < caesar_idx,
            "structural decoder {structural:?} at index {idx} must precede reverse ({reverse_idx}) and caesar ({caesar_idx})"
        );
    }
}

#[test]
fn no_duplicate_names() {
    let names = default_decoder_names_for_test();
    let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "decode registry must have no duplicate decoder names"
    );
    assert_eq!(unique.len(), 13, "unique decoder name count must be 13");
}

#[test]
fn base64_appears_exactly_once() {
    let names = default_decoder_names_for_test();
    let count = names.iter().filter(|&&n| n == "base64").count();
    assert_eq!(count, 1, "base64 must be registered exactly once");
}

#[test]
fn base32_is_absent() {
    let names = default_decoder_names_for_test();
    assert!(
        !names.contains(&"base32"),
        "base32 must NOT be a default decoder; found it in {names:?}"
    );
    assert_eq!(
        names.iter().position(|&n| n == "base32"),
        None,
        "base32 must have no index in the default registry"
    );
}

#[test]
fn base58_is_absent() {
    let names = default_decoder_names_for_test();
    assert!(
        !names.contains(&"base58"),
        "base58 must NOT be a default decoder; found it in {names:?}"
    );
    assert_eq!(
        names.iter().position(|&n| n == "base58"),
        None,
        "base58 must have no index in the default registry"
    );
}

#[test]
fn z85_is_present_at_index_ten() {
    // z85 is the ONLY member of the ascii85/z85 family that ships by default —
    // this pins that it is present (and where) so a swap for base32/base58 is caught.
    let names = default_decoder_names_for_test();
    assert_eq!(
        names.iter().position(|&n| n == "z85"),
        Some(10),
        "z85 must occupy index 10 exactly"
    );
}

#[test]
fn exact_joined_string() {
    let names = default_decoder_names_for_test();
    let joined = names.join(",");
    assert_eq!(
        joined,
        "base64,hex,url,quoted-printable,html-named-entity,html-numeric-entity,octal-escape,mime-encoded-word,json,unicode-escape,z85,reverse,caesar",
        "joined decode-registry name string drifted"
    );
}

#[test]
fn per_name_index_mapping() {
    let names = default_decoder_names_for_test();
    // Pin the exact index of every canonical name individually.
    let expected_index: &[(&str, usize)] = &[
        ("base64", 0),
        ("hex", 1),
        ("url", 2),
        ("quoted-printable", 3),
        ("html-named-entity", 4),
        ("html-numeric-entity", 5),
        ("octal-escape", 6),
        ("mime-encoded-word", 7),
        ("json", 8),
        ("unicode-escape", 9),
        ("z85", 10),
        ("reverse", 11),
        ("caesar", 12),
    ];
    for &(name, idx) in expected_index {
        assert_eq!(
            names.iter().position(|&n| n == name),
            Some(idx),
            "decoder {name:?} must sit at index {idx}"
        );
    }
}

#[test]
fn name_set_equality_regardless_of_order() {
    let names = default_decoder_names_for_test();
    let got: std::collections::BTreeSet<&str> = names.iter().copied().collect();
    let want: std::collections::BTreeSet<&str> = EXPECTED.iter().copied().collect();
    assert_eq!(
        got, want,
        "the SET of default decoder names must equal the canonical 13-name set"
    );
}
