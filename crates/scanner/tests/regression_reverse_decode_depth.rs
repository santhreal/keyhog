//! Regression coverage for the reverse decoder's *pipeline* behaviour, how it
//! interacts with the BFS decode-through depth cap, the `MIN_REVERSE_LEN` gate,
//! and its own anti-recursion guard (`source_type.contains("/reverse")`).
//!
//! The `regression_z85_reverse_decoders.rs` sibling already pins the pure
//! `reverse_str` / `looks_reversible` seams in isolation; this file drives the
//! real `decode::decode_chunk` BFS (via the `testing::decode_chunk` seam) and
//! the full `CompiledScanner::scan` end-to-end path, asserting CONCRETE recovered
//! bytes, exact chunk counts, and exact detector-id / credential values.
//!
//! HOST-INDEPENDENCE: the reverse decoder and the decode pipeline are pure
//! scalar CPU code with no accelerator dependency, and `CompiledScanner::scan`
//! always has the CPU path available, so every contract below is fully
//! host-independent (no Hyperscan/SIMD/GPU assumption).

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::{
    decode_chunk, default_decoder_names_for_test, looks_reversible_for_test, reverse_str_for_test,
};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

/// A non-example AWS access-key-id that the scanner surfaces verbatim (shared
/// with the `reverse_aws_key_reversed_in_quotes` adversarial fixture, so it is
/// known NOT to trip example-credential suppression).
const AWS_SECRET: &str = "AKIAQYLPMN5HFIQR7XYA";
/// `AWS_SECRET` reversed char-by-char. Pinned as a literal AND re-derived at
/// runtime below so a drift in either the constant or `reverse_str` is caught.
const AWS_REVERSED: &str = "AYX7RQIFH5NMPLYQAIKA";

fn chunk_with(data: &str, source_type: &str) -> Chunk {
    Chunk {
        data: data.to_string().into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some("reverse-depth.txt".into()),
            ..Default::default()
        },
    }
}

/// Chunks emitted DIRECTLY by the reverse decoder have a `source_type` ending in
/// exactly `/reverse` (deeper decoders append `/base64` etc., and the
/// anti-recursion guard forbids `/reverse/reverse`).
fn reverse_outputs(decoded: &[Chunk]) -> Vec<&Chunk> {
    decoded
        .iter()
        .filter(|c| c.metadata.source_type.ends_with("/reverse"))
        .collect()
}

fn compile_scanner() -> CompiledScanner {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // crates/
    d.pop(); // repo root
    d.push("detectors");
    CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("load detectors"))
        .expect("compile scanner")
}

// ---------------------------------------------------------------------------
// Pure seams: reversal + admission gate (host-independent, exact values)
// ---------------------------------------------------------------------------

#[test]
fn reversed_constant_matches_reverse_str_and_is_involutive() {
    // The pinned reversed literal is exactly `reverse_str(AWS_SECRET)` ...
    assert_eq!(reverse_str_for_test(AWS_SECRET), AWS_REVERSED);
    // ... and reversing twice recovers the original byte-for-byte (the
    // "doubly-reversed == original" property the pipeline relies on).
    assert_eq!(reverse_str_for_test(AWS_REVERSED), AWS_SECRET);
    assert_eq!(
        reverse_str_for_test(&reverse_str_for_test(AWS_SECRET)),
        AWS_SECRET,
    );
}

#[test]
fn looks_reversible_true_for_reversed_aws_secret() {
    // 20-char alnum run (>= 12) AND contains "AIKA" (= reverse of the known
    // prefix "AKIA"). Both admission gates pass.
    assert_eq!(looks_reversible_for_test(AWS_REVERSED), true);
}

#[test]
fn looks_reversible_false_for_alpha_prose_without_reversed_prefix() {
    // 16-char alnum run satisfies gate 1, but the reverse ("PONMLKJIHGFEDCBA")
    // contains no reversed provider prefix => gate 2 rejects. This is the exact
    // decoy class the prefix gate exists to keep out of the pipeline.
    assert_eq!(looks_reversible_for_test("ABCDEFGHIJKLMNOP"), false);
}

#[test]
fn looks_reversible_false_when_alnum_run_too_short_despite_reversed_prefix() {
    // Contains "AIKA" (reverse of "AKIA"), so gate 2 alone would pass, but the
    // longest reversed-direction alnum run is only 4 ("AIKA"), far below the
    // 12-char floor, so gate 1 rejects first. Proves the run gate is enforced
    // independently of the prefix gate.
    assert_eq!(looks_reversible_for_test("xy-AIKA"), false);
}

// ---------------------------------------------------------------------------
// Pipeline: exact recovery of a reversed secret through decode_chunk
// ---------------------------------------------------------------------------

#[test]
fn decode_chunk_recovers_reversed_secret_with_exact_spliced_bytes() {
    let input = format!("token = \"{AWS_REVERSED}\"");
    let chunk = chunk_with(&input, "regr");
    let decoded = decode_chunk(&chunk, 3, false, None, None);

    let rev = reverse_outputs(&decoded);
    // Exactly one direct reverse output: the single long quoted candidate.
    assert_eq!(
        rev.len(),
        1,
        "expected one /reverse chunk, got source_types={:?}",
        decoded
            .iter()
            .map(|c| c.metadata.source_type.as_ref())
            .collect::<Vec<_>>(),
    );
    // The decoded text is the parent line with the reversed blob replaced by the
    // recovered forward secret (splice preserves the `token = "…"` context).
    let recovered: &str = &rev[0].data;
    assert_eq!(recovered, "token = \"AKIAQYLPMN5HFIQR7XYA\"");
    assert!(recovered.contains(AWS_SECRET));
    // The reversed form is gone (it was decoded, not merely copied through).
    assert!(!recovered.contains(AWS_REVERSED));
    // Provenance records the reverse decoder.
    assert_eq!(rev[0].metadata.source_type.as_ref(), "regr/reverse");
}

#[test]
fn decode_chunk_depth_cap_boundary_gates_reverse_output() {
    let input = format!("token = \"{AWS_REVERSED}\"");
    let chunk = chunk_with(&input, "regr");

    // max_depth == 0: the root is dequeued at depth 0, `0 >= 0` short-circuits
    // before any decoder runs, so NOTHING is produced.
    assert_eq!(decode_chunk(&chunk, 0, false, None, None).len(), 0);

    // max_depth == 1: the root (depth 0 < 1) is decoded exactly once, so the
    // reverse output appears. One decode layer is the minimum that recovers it.
    let decoded = decode_chunk(&chunk, 1, false, None, None);
    let rev = reverse_outputs(&decoded);
    assert_eq!(rev.len(), 1);
    assert!(rev[0].data.contains(AWS_SECRET));
}

#[test]
fn decode_chunk_never_double_reverses_its_own_output() {
    // reverse(reverse(s)) == s, so a recursive reverse pass would re-emit the
    // original credential under a `/reverse/reverse` source_type. The decoder's
    // guard (`source_type.contains("/reverse")`) must prevent that at every BFS
    // depth: NO produced chunk carries a doubled `/reverse` segment.
    let input = format!("token = \"{AWS_REVERSED}\"");
    let chunk = chunk_with(&input, "regr");
    let decoded = decode_chunk(&chunk, 4, false, None, None);
    let doubled = decoded
        .iter()
        .filter(|c| c.metadata.source_type.contains("/reverse/reverse"))
        .count();
    assert_eq!(doubled, 0);
}

#[test]
fn decode_chunk_reverse_guard_blocks_when_root_already_reverse_sourced() {
    // A chunk whose provenance already contains `/reverse` (as any descendant of
    // a reverse output would) must NOT be reverse-decoded again, the guard
    // returns empty for it and, because every descendant inherits the marker,
    // no `/reverse`-terminating chunk is ever produced in this BFS.
    let input = format!("token = \"{AWS_REVERSED}\"");
    let chunk = chunk_with(&input, "seed/reverse");
    let decoded = decode_chunk(&chunk, 4, false, None, None);
    let rev = reverse_outputs(&decoded);
    assert_eq!(
        rev.len(),
        0,
        "guarded input must yield no reverse output, got source_types={:?}",
        decoded
            .iter()
            .map(|c| c.metadata.source_type.as_ref())
            .collect::<Vec<_>>(),
    );
}

#[test]
fn decode_chunk_ignores_non_reversible_prose() {
    // A 16-char alnum quoted value that fails `looks_reversible` (no reversed
    // provider prefix) must NOT be reverse-decoded, even though it clears the
    // MIN_REVERSE_LEN length floor.
    assert_eq!(looks_reversible_for_test("ABCDEFGHIJKLMNOP"), false);
    let chunk = chunk_with("note = \"ABCDEFGHIJKLMNOP\"", "regr");
    let decoded = decode_chunk(&chunk, 3, false, None, None);
    assert_eq!(reverse_outputs(&decoded).len(), 0);
}

#[test]
fn decode_chunk_min_reverse_len_boundary() {
    // Both candidates pass `looks_reversible` (15/16-char alnum runs, each ends
    // in "AIKA" = reverse of "AKIA"), isolating the MIN_REVERSE_LEN == 16 gate as
    // the ONLY differentiator.
    let reversed_15 = "LKJIHGFEDCBAIKA"; // 15 chars
    let reversed_16 = "MLKJIHGFEDCBAIKA"; // 16 chars
    assert_eq!(reversed_15.len(), 15);
    assert_eq!(reversed_16.len(), 16);
    assert_eq!(looks_reversible_for_test(reversed_15), true);
    assert_eq!(looks_reversible_for_test(reversed_16), true);
    // The recovered forward strings (what a reverse decode would produce).
    assert_eq!(reverse_str_for_test(reversed_15), "AKIABCDEFGHIJKL");
    assert_eq!(reverse_str_for_test(reversed_16), "AKIABCDEFGHIJKLM");

    // 15-char candidate: below the length floor => reverse never fires.
    let short = chunk_with(&format!("k = \"{reversed_15}\""), "regr");
    assert_eq!(
        reverse_outputs(&decode_chunk(&short, 3, false, None, None)).len(),
        0
    );

    // 16-char candidate: at the floor => reverse fires and recovers the forward
    // string exactly.
    let long = chunk_with(&format!("k = \"{reversed_16}\""), "regr");
    let decoded = decode_chunk(&long, 3, false, None, None);
    let rev = reverse_outputs(&decoded);
    assert_eq!(rev.len(), 1);
    assert!(rev[0].data.contains("AKIABCDEFGHIJKLM"));
}

// ---------------------------------------------------------------------------
// End-to-end: full CompiledScanner::scan over forward and reversed inputs
// ---------------------------------------------------------------------------

#[test]
fn full_scan_finds_forward_aws_key_directly() {
    // The "doubly-reversed == original" case: a forward key needs no reverse
    // decode and is surfaced directly by the scanner with its exact bytes.
    let scanner = compile_scanner();
    let chunk = chunk_with(&format!("token = \"{AWS_SECRET}\""), "direct");
    let matches = scanner.scan(&chunk);
    let aws: Vec<&str> = matches
        .iter()
        .filter(|m| &*m.detector_id == "aws-access-key")
        .map(|m| &*m.credential)
        .collect();
    assert!(
        aws.contains(&AWS_SECRET),
        "forward aws-access-key must surface verbatim; aws creds = {aws:?}",
    );
}

#[test]
fn full_scan_surfaces_reversed_aws_key_as_forward_credential() {
    // Reverse-evasion: the on-disk text holds the REVERSED key; the decode
    // pipeline must recover it so the scanner reports the FORWARD credential
    // and never the reversed literal.
    let scanner = compile_scanner();
    let chunk = chunk_with(&format!("token = \"{AWS_REVERSED}\""), "evasion");
    let matches = scanner.scan(&chunk);

    let has_forward = matches
        .iter()
        .any(|m| &*m.detector_id == "aws-access-key" && &*m.credential == AWS_SECRET);
    assert!(
        has_forward,
        "reversed aws-access-key must surface as the forward key; matches = {:?}",
        matches
            .iter()
            .map(|m| (&*m.detector_id, &*m.credential))
            .collect::<Vec<_>>(),
    );
    // The reversed byte-sequence is never reported AS an aws-access-key (the
    // evasion target): aws-access-key requires the literal AKIA/ASIA prefix,
    // which the reversed form lacks, so it fires only on the RECOVERED forward
    // key. (A generic/high-entropy detector may legitimately flag the 20-char
    // reversed literal on its own bytes, that is a separate, correct finding
    // and not the reverse-evasion path under test here.)
    let reports_reversed_as_aws = matches
        .iter()
        .any(|m| &*m.detector_id == "aws-access-key" && &*m.credential == AWS_REVERSED);
    assert!(
        !reports_reversed_as_aws,
        "aws-access-key must never fire on the reversed literal; matches = {:?}",
        matches
            .iter()
            .map(|m| (&*m.detector_id, &*m.credential))
            .collect::<Vec<_>>(),
    );
}

// ---------------------------------------------------------------------------
// Composition: reverse runs late so it decodes structural-decoder output
// ---------------------------------------------------------------------------

#[test]
fn reverse_decoder_runs_after_structural_decoders_and_before_caesar() {
    // The BFS visits decoders in registration order; `reverse` deliberately runs
    // after the structural decoders (base64/hex/z85 …) so it can operate on
    // their output, and immediately before `caesar` (the two evasion decoders
    // run last). Pin the exact positions.
    let names = default_decoder_names_for_test();
    let pos = |needle: &str| {
        names
            .iter()
            .position(|n| *n == needle)
            .unwrap_or_else(|| panic!("decoder {needle:?} missing from {names:?}"))
    };
    let base64 = pos("base64");
    let z85 = pos("z85");
    let reverse = pos("reverse");
    let caesar = pos("caesar");
    assert_eq!(base64, 0);
    assert!(
        base64 < reverse,
        "base64({base64}) must precede reverse({reverse})"
    );
    assert!(z85 < reverse, "z85({z85}) must precede reverse({reverse})");
    assert_eq!(
        reverse + 1,
        caesar,
        "caesar must immediately follow reverse"
    );
    assert_eq!(names.last().copied(), Some("caesar"));
}
