//! Regression coverage for the reverse decoder's DECOY-SUPPRESSION predicate
//! (`decode::reverse::looks_reversible`, exposed via the `looks_reversible_for_test`
//! seam) and the reversal primitive (`reverse_str_for_test`).
//!
//! The predicate is the reverse decoder's admission gate: it decides whether a
//! candidate is worth reverse-decoding at all. It suppresses reversed DECOYS
//! (long alnum blobs whose reverse carries NO known provider prefix, and the
//! deliberately-excluded 2-char `0x` Ethereum prefix) while admitting a
//! genuinely reversed secret whose reverse DOES carry a 3+ char provider prefix.
//! Every assertion pins a CONCRETE bool / string.
//!
//! Distinct from `regression_reverse_decode_depth.rs` (BFS depth cap + MIN_REVERSE_LEN
//! + anti-recursion) and `regression_z85_reverse_decoders.rs`: this file focuses on
//! the *decoy vs real-secret* boundary of the predicate — the 2-char-prefix
//! exclusion, the exact 11-vs-12 alnum-run floor, case sensitivity, and the
//! run-must-be-contiguous rule — plus two end-to-end `decode_chunk` suppression
//! checks.
//!
//! HOST-INDEPENDENCE: `looks_reversible`, `reverse_str`, and the decode pipeline
//! are pure scalar CPU code with NO accelerator (Hyperscan/SIMD/GPU) dependency,
//! so every contract below holds identically on any host.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::{decode_chunk, looks_reversible_for_test, reverse_str_for_test};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn chunk_with(data: &str, source_type: &str) -> Chunk {
    Chunk {
        data: data.to_string().into(),
        metadata: ChunkMetadata {
            source_type: source_type.into(),
            path: Some("reverse-decoy.txt".into()),
            ..Default::default()
        },
    }
}

/// Chunks emitted DIRECTLY by the reverse decoder have a `source_type` ending in
/// exactly `/reverse`.
fn reverse_output_count(decoded: &[Chunk]) -> usize {
    decoded
        .iter()
        .filter(|c| c.metadata.source_type.ends_with("/reverse"))
        .count()
}

// ---------------------------------------------------------------------------
// reverse_str: the primitive (scalar-correct, involutive)
// ---------------------------------------------------------------------------

#[test]
fn reverse_str_empty_and_single_are_identities() {
    assert_eq!(reverse_str_for_test(""), "");
    assert_eq!(reverse_str_for_test("a"), "a");
    assert_eq!(reverse_str_for_test("Z"), "Z");
}

#[test]
fn reverse_str_is_unicode_scalar_reversal_not_byte_reversal() {
    // "café" = c, a, f, é (é is a 2-byte UTF-8 scalar). A *byte* reversal would
    // corrupt the é into mojibake; the scalar reversal keeps it intact.
    assert_eq!(reverse_str_for_test("café"), "éfac");
    // Round-trip recovers the original exactly.
    assert_eq!(reverse_str_for_test("éfac"), "café");
}

#[test]
fn reverse_str_github_literal_and_involution() {
    // Pinned literal catches drift in reverse_str; involution is the property the
    // whole reverse-evasion recovery relies on (reverse(reverse(s)) == s).
    let forward = "ghp_0123456789ABCDEFGH";
    let reversed = "HGFEDCBA9876543210_phg";
    assert_eq!(reverse_str_for_test(forward), reversed);
    assert_eq!(reverse_str_for_test(reversed), forward);
    assert_eq!(
        reverse_str_for_test(&reverse_str_for_test(forward)),
        forward
    );
}

// ---------------------------------------------------------------------------
// looks_reversible: a REAL reversed secret is ADMITTED (not suppressed)
// ---------------------------------------------------------------------------

#[test]
fn real_reversed_github_pat_is_admitted_but_its_forward_twin_is_not() {
    // The reversed github PAT: 18-char alnum run AND ends in "_phg"
    // (= reverse of the known prefix "ghp_"). Both gates pass -> admitted.
    let reversed = "HGFEDCBA9876543210_phg";
    assert_eq!(looks_reversible_for_test(reversed), true);

    // Negative twin: the FORWARD real secret is NOT itself "reversible" — it has
    // a long alnum run but contains no *reversed* provider prefix ("_phg"), so it
    // is left for the scanner to find directly rather than reverse-decoded.
    let forward = "ghp_0123456789ABCDEFGH";
    assert_eq!(looks_reversible_for_test(forward), false);
}

#[test]
fn real_reversed_secrets_across_prefix_families_are_admitted() {
    // For each family, the reverse of `PREFIX + 16-alnum-body` ends in the
    // reversed prefix and carries a 16-char alnum run -> admitted.
    let body = "ABCDEFGHIJKLMNOP"; // 16 alnum chars
    for prefix in ["hf_", "SG.", "eyJ", "xoxb-", "glpat-", "AKIA"] {
        let forward = format!("{prefix}{body}");
        let reversed = reverse_str_for_test(&forward);
        assert_eq!(
            looks_reversible_for_test(&reversed),
            true,
            "reversed {prefix:?}-prefixed secret must be admitted, got reversed={reversed:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// looks_reversible: DECOYS are SUPPRESSED
// ---------------------------------------------------------------------------

#[test]
fn reversed_alphabet_decoy_is_suppressed() {
    // 26-char alnum run clears gate 1, but the reverse
    // ("ABCDEFGHIJKLMNOPQRSTUVWXYZ") contains NO reversed provider prefix ->
    // gate 2 rejects. This is the exact prose-decoy class the prefix gate exists
    // to keep out (Kimi-decode audit finding #4).
    assert_eq!(
        looks_reversible_for_test("ZYXWVUTSRQPONMLKJIHGFEDCBA"),
        false,
    );
    // A shorter pure-alnum word with no reversed prefix is also suppressed.
    assert_eq!(looks_reversible_for_test("PONMLKJIHGFEDCBA"), false);
}

#[test]
fn two_char_0x_prefix_is_excluded_while_three_char_prefix_is_admitted() {
    // Paired boundary isolating the MIN_REVERSE_PREFIX_LEN == 3 exclusion.
    // Both candidates have a 12+ alnum run AND reverse to a valid known-prefix
    // credential; the ONLY difference is prefix length.

    let body = "1".repeat(12); // 12-char alnum run — clears gate 1 for both

    // Candidate A reverses to "0x" + body — a real Ethereum-style prefix, but
    // "0x" is len 2 and deliberately EXCLUDED (it hits ~1.6% of long base64 by
    // chance and drove FPs), so the candidate is SUPPRESSED.
    let a = format!("{body}x0");
    assert_eq!(reverse_str_for_test(&a), format!("0x{body}"));
    assert_eq!(looks_reversible_for_test(&a), false);

    // Candidate B reverses to "hf_" + body — "hf_" is len 3, still gated in, so
    // the structurally-identical candidate is ADMITTED.
    let b = format!("{body}_fh");
    assert_eq!(reverse_str_for_test(&b), format!("hf_{body}"));
    assert_eq!(looks_reversible_for_test(&b), true);
}

// ---------------------------------------------------------------------------
// looks_reversible: exact alnum-run floor (MIN_REVERSE_ALNUM_RUN == 12)
// ---------------------------------------------------------------------------

#[test]
fn alnum_run_floor_is_exactly_twelve() {
    // Both candidates contain "AIKA" (reverse of "AKIA"), so gate 2 passes for
    // both — the alnum-run gate is the sole differentiator.
    let admitted = "ABCDEFGHAIKA"; // 12 contiguous alnum chars
    let suppressed = "BCDEFGHAIKA"; // 11 contiguous alnum chars
    assert_eq!(admitted.len(), 12);
    assert_eq!(suppressed.len(), 11);
    // 12 == floor -> admitted; 11 == floor-1 -> suppressed.
    assert_eq!(looks_reversible_for_test(admitted), true);
    assert_eq!(looks_reversible_for_test(suppressed), false);
}

#[test]
fn run_must_be_contiguous_split_run_is_suppressed_despite_prefix() {
    // Contains "AIKA" (reverse of "AKIA") so gate 2 alone would pass, but the
    // longest CONTIGUOUS alnum run is 9 ("CCCCCCCCC") — the "AIKA" segment is
    // only 4 and is severed by the '-'. Neither run reaches 12 -> suppressed.
    // Proves the run gate counts a single contiguous run, not total alnum chars.
    assert_eq!(looks_reversible_for_test("AIKA-CCCCCCCCC"), false);
}

// ---------------------------------------------------------------------------
// looks_reversible: case sensitivity (adversarial)
// ---------------------------------------------------------------------------

#[test]
fn reversed_prefix_match_is_case_sensitive() {
    // The reversed-prefix needle "AIKA" is uppercase. An attacker lowercasing the
    // reversed key ("aika") no longer matches any needle, so the lowercase form
    // is SUPPRESSED — which is correct, since the forward AWS detector is itself
    // case-sensitive on "AKIA" and would not fire on "akia" either.
    assert_eq!(looks_reversible_for_test("111111111111aika"), false);
    // Uppercase twin (identical 16-char alnum run) IS admitted.
    assert_eq!(looks_reversible_for_test("111111111111AIKA"), true);
}

#[test]
fn empty_and_tiny_candidates_are_suppressed() {
    // Below the alnum-run floor there is nothing to reverse-decode.
    assert_eq!(looks_reversible_for_test(""), false);
    assert_eq!(looks_reversible_for_test("AIKA"), false); // 4-char run only
    assert_eq!(looks_reversible_for_test("_phg"), false); // prefix but 0 long run
}

// ---------------------------------------------------------------------------
// End-to-end: the decode pipeline honours the predicate
// ---------------------------------------------------------------------------

#[test]
fn decode_chunk_recovers_reversed_github_pat_and_suppresses_alphabet_decoy() {
    // Real reversed github PAT (22 chars, >= MIN_REVERSE_LEN): the pipeline
    // reverse-decodes it and recovers the FORWARD credential exactly.
    let secret_chunk = chunk_with("token = \"HGFEDCBA9876543210_phg\"", "regr");
    let decoded = decode_chunk(&secret_chunk, 3, false, None, None);
    assert_eq!(
        reverse_output_count(&decoded),
        1,
        "expected exactly one /reverse output, got source_types={:?}",
        decoded
            .iter()
            .map(|c| c.metadata.source_type.as_ref())
            .collect::<Vec<_>>(),
    );
    let recovered = decoded
        .iter()
        .find(|c| c.metadata.source_type.ends_with("/reverse"))
        .expect("one reverse output");
    let recovered_data: &str = &recovered.data;
    assert_eq!(recovered_data, "token = \"ghp_0123456789ABCDEFGH\"");
    assert_eq!(recovered.metadata.source_type.as_ref(), "regr/reverse");

    // Reversed alphabet decoy (26 chars, also >= MIN_REVERSE_LEN): looks_reversible
    // is false, so the pipeline emits ZERO reverse outputs — it is suppressed.
    let decoy_chunk = chunk_with("note = \"ZYXWVUTSRQPONMLKJIHGFEDCBA\"", "regr");
    let decoy_decoded = decode_chunk(&decoy_chunk, 3, false, None, None);
    assert_eq!(reverse_output_count(&decoy_decoded), 0);
}

#[test]
fn decode_chunk_suppresses_reversed_0x_decoy_at_pipeline() {
    // A 20-char blob (>= MIN_REVERSE_LEN) that reverses to "0x1111...": the only
    // provider prefix its reverse carries is the excluded 2-char "0x", so
    // looks_reversible is false and NO reverse chunk is emitted. This is the exact
    // base64-protobuf "0x-by-chance" decoy class the exclusion was added to kill.
    let candidate = format!("{}x0", "1".repeat(18)); // 18 + "x0" = 20 chars
    assert_eq!(candidate.len(), 20);
    assert_eq!(looks_reversible_for_test(&candidate), false);
    let chunk = chunk_with(&format!("addr = \"{candidate}\""), "regr");
    let decoded = decode_chunk(&chunk, 3, false, None, None);
    assert_eq!(reverse_output_count(&decoded), 0);
}
