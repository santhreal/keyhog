//! Behavioral contract for the decode-pipeline registry's DEFAULT decoder set
//! (crates/scanner/src/decode/pipeline/registry.rs::default_decoders).
//!
//! The default registry is the decode pipeline's composition. Two things about
//! it are load-bearing and were pinned nowhere:
//!   1. ORDER — `reverse` and `caesar` deliberately run LAST, after the
//!      structural decoders (their µ-blocks document "runs after the other
//!      decoders"); a reorder would change which decoder first claims a chunk.
//!   2. COUNT — the per-decoder profiler is a fixed `[AtomicU64; 16]`
//!      (`MAX_PROFILED_DECODERS`); a default set that outgrows 16 would be
//!      silently un-profiled past slot 16 (`record_decoder_run` drops it).
#![cfg(feature = "decode")]

use keyhog_scanner::testing::default_decoder_names_for_test as decoder_names;

const EXPECTED_DEFAULT_DECODERS: [&str; 13] = [
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
fn decoder_registry_default_order_is_exact() {
    assert_eq!(
        decoder_names(),
        EXPECTED_DEFAULT_DECODERS.to_vec(),
        "the default decode pipeline must be exactly these decoders, in this order"
    );
}

#[test]
fn reverse_and_caesar_run_last() {
    let names = decoder_names();
    // base64 is the primary/first decoder.
    assert_eq!(names.first(), Some(&"base64"));
    // reverse then caesar are the final two — the evasion decoders run after the
    // structural ones so they only fire on what nothing else already decoded.
    assert_eq!(
        &names[names.len() - 2..],
        &["reverse", "caesar"],
        "reverse and caesar must remain the last two decoders, in that order"
    );
}

#[test]
fn default_decoder_count_stays_within_profiler_capacity() {
    let count = decoder_names().len();
    assert_eq!(count, 13, "there are exactly 13 default decoders today");
    // MAX_PROFILED_DECODERS is 16; a default set beyond that would be silently
    // un-profiled past slot 16. This guards the headroom.
    assert!(
        count <= 16,
        "default decoders ({count}) must fit the 16-slot per-decoder profiler"
    );
}
