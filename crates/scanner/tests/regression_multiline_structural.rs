//! Regression lock: multiline / structural extraction contracts.
//!
//! Covers the four load-bearing shapes the `crates/scanner/src/multiline/`
//! preprocessor + structural reassembler must get exactly right:
//!
//!   1. A multi-line PEM private-key block is carried through byte-identically
//!      (exact boundaries preserved) so the private-key detector sees the whole
//!      `-----BEGIN…-----END` envelope, the preprocessor must NOT rewrite or
//!      shred it. Verified through both the joined-text seam and the offset→line
//!      mapping.
//!   2. A secret embedded in a multi-line JSON body survives preprocessing
//!      whole (JSON is rejected as a concatenation indicator up front and passes
//!      through byte-identically), so the value stays a contiguous span.
//!   3. A function-style string concatenation (R `paste()`/`paste0()`, Rust
//!      `concat!()`) split across quoted fragments is reassembled into the whole
//!      secret and appended after the original text.
//!   4. A non-secret multiline (plain prose, or a `+`-join of non-credential
//!      variable names) is NOT reassembled into a synthetic candidate.
//!
//! Plus the structural cluster / variable-reference resolver / template-literal
//! resolver paths, each with a positive and a negative twin, asserting the exact
//! reassembled bytes and mapping boundaries.
//!
//! Source under test:
//!   * crates/scanner/src/multiline/preprocessor.rs (`preprocess_multiline`)
//!   * crates/scanner/src/multiline/structural.rs
//!       (`collect_structural_fragments`, `resolve_template_reference`,
//!        `resolve_concat_reference`, cluster reassembly, SYNTHETIC_BASE_LINE)
//!   * crates/scanner/src/multiline/string_extract.rs
//!       (`extract_function_concatenation`, `extract_prefix`)
//!   * crates/scanner/src/multiline/config.rs (`has_concatenation_indicators`)

#![cfg(feature = "multiline")]

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{
    collect_structural_fragments_for_test, extract_prefix_for_test,
    has_concatenation_indicators_for_test, preprocess_multiline, preprocess_multiline_for_test,
    resolve_template_reference_for_test, MultilineConfig,
};
use keyhog_scanner::{CompiledScanner, ScanBackend};

/// The synthetic base line number the structural `+`-reference resolver stamps
/// onto reassembled var-reference fragments so they never merge with real
/// source-line windows (structural.rs `SYNTHETIC_BASE_LINE`).
const SYNTHETIC_BASE_LINE: usize = 1_000_000_000;

/// Byte offsets of each `\n`-joined line, matching `crate::compute_line_offsets`
/// over the original text `lines.join("\n")`: feeds the structural seam so its
/// `original_start_offset` bookkeeping resolves without a telemetry gap record.
fn line_offsets(lines: &[&str]) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(lines.len());
    let mut cursor = 0usize;
    for line in lines {
        offsets.push(cursor);
        cursor += line.len() + 1; // +1 for the joining '\n'
    }
    offsets
}

// ── 1. PEM private-key block: byte-identical passthrough, exact boundaries ────

/// A raw PEM block (no quotes / `+` / backtick / paste marker) trips NO
/// concatenation indicator, so the preprocessor must pass it through verbatim.
#[test]
fn pem_private_key_block_is_not_a_concatenation_indicator() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
               MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
               KUpRKfFLfRYC9AIKjbJTWit0CRTDadmczVkACnnj4GkxFhD90vcNLYLInFEX6Ppy=\n\
               -----END RSA PRIVATE KEY-----";
    assert!(
        !has_concatenation_indicators_for_test(pem),
        "a raw PEM block must not be treated as a concatenation candidate"
    );
}

/// The whole `-----BEGIN…-----END` envelope is reassembled with EXACT
/// boundaries: the joined text equals the input byte-for-byte and
/// `original_end` equals the input length (no synthetic bytes appended).
#[test]
fn pem_private_key_block_passes_through_byte_identical() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
               MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
               KUpRKfFLfRYC9AIKjbJTWit0CRTDadmczVkACnnj4GkxFhD90vcNLYLInFEX6Ppy=\n\
               -----END RSA PRIVATE KEY-----";
    let (joined, original_end) = preprocess_multiline_for_test(pem);
    assert_eq!(joined, pem, "PEM body must be carried through unchanged");
    assert_eq!(
        original_end,
        pem.len(),
        "original_end must equal the exact input byte length"
    );
}

/// The offset→line mapping over the passed-through PEM resolves each envelope
/// boundary to its exact 1-based source line (BEGIN=1, first body=2, END=4).
#[test]
fn pem_private_key_block_offset_mapping_preserves_line_boundaries() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\n\
               MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n\
               KUpRKfFLfRYC9AIKjbJTWit0CRTDadmczVkACnnj4GkxFhD90vcNLYLInFEX6Ppy=\n\
               -----END RSA PRIVATE KEY-----";
    let cache = FragmentCache::new(64);
    let pre = preprocess_multiline(pem, &MultilineConfig::default(), &cache);

    assert_eq!(pre.original_end, pem.len());
    // BEGIN marker is line 1.
    assert_eq!(pre.line_for_offset(0), Some(1));
    // First base64 body line is line 2.
    let body_off = pem.find("MIIBOg").expect("body line present");
    assert_eq!(pre.line_for_offset(body_off), Some(2));
    // END marker is line 4.
    let end_off = pem.find("-----END").expect("END marker present");
    assert_eq!(pre.line_for_offset(end_off), Some(4));
}

// ── 2. JSON-embedded secret: preserved whole across lines ─────────────────────

/// A JSON body is rejected as a concatenation indicator (its first non-space
/// byte is `{`), so a secret on its own line survives byte-identically as a
/// contiguous span.
#[test]
fn json_embedded_secret_across_lines_passes_through_whole() {
    let secret = "wJalrXUtnFEMIbPxRfiCYEXAMPLEKEY1234567890";
    let json = format!("{{\n  \"aws_secret_access_key\": \"{secret}\"\n}}");

    assert!(
        !has_concatenation_indicators_for_test(&json),
        "a JSON object body must not be treated as a concatenation candidate"
    );

    let (joined, original_end) = preprocess_multiline_for_test(&json);
    assert_eq!(joined, json, "JSON body must be carried through unchanged");
    assert_eq!(original_end, json.len());
    assert!(
        joined.contains(secret),
        "the embedded secret must remain a contiguous span: {joined:?}"
    );
}

// ── 3. Function-style concat (paste0 / paste / concat!) reassembly ───────────

/// R `paste0("gh", "p_…")` reassembles to the whole `ghp_…` secret, appended
/// after the original line, with `original_end` still the input length.
#[test]
fn paste0_function_concat_reassembles_whole_secret() {
    let text = "token = paste0(\"gh\", \"p_deadbeefdeadbeefdeadbeef\")";
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert_eq!(
        joined,
        format!("{text}\nghp_deadbeefdeadbeefdeadbeef"),
        "paste0 fragments must reassemble into one appended candidate"
    );
    assert_eq!(original_end, text.len());
}

/// Rust `concat!("ghp_", "…")` reassembles the same way (shared marker set).
#[test]
fn concat_macro_reassembles_whole_secret() {
    let text = "let x = concat!(\"ghp_\", \"abcdef0123456789abcdef01\");";
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert_eq!(joined, format!("{text}\nghp_abcdef0123456789abcdef01"));
    assert_eq!(original_end, text.len());
}

/// R `paste(...)` (no trailing `0`) is the third form of the shared function
/// concat marker; the literals are joined with NO separator (the extractor
/// concatenates literal contents verbatim).
#[test]
fn r_paste_function_concat_reassembles_whole_secret() {
    let text = "key <- paste(\"AKIA\", \"IOSFODNN7EXAMPLE\")";
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert_eq!(joined, format!("{text}\nAKIAIOSFODNN7EXAMPLE"));
    assert_eq!(original_end, text.len());
}

#[test]
fn obfuscated_javascript_array_join_reassembles_known_prefix_secret() {
    let secret = "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";
    let text = "const _a = (() => { const _b = [\"ghp_\", \"69121b4cdeef\", \
                \"f121c88dffac\", \"1f9dbc2giIjE\"]; return _b.join(''); })();";

    assert!(
        has_concatenation_indicators_for_test(text),
        "empty-separator JavaScript array join must enter structural recovery"
    );
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert_eq!(original_end, text.len());
    assert!(
        joined[original_end..].contains(secret),
        "known-prefix array fragments must recover {secret}; got {joined:?}"
    );
}

#[test]
fn production_scan_recovers_obfuscated_javascript_array_join() {
    let secret = concat!("ghp_", "8ee59b1f3a8b98f8fd4f4bd6d563321t2nrI");
    let text = concat!(
        "'use strict';\n",
        "const _fa1f85493086 = (() => { const _bfff63975e3e = ",
        "[\"ghp_\", \"8ee59b1f3a8b\", \"98f8fd4f4bd6\", \"d563321t2nrI\"]; ",
        "return _bfff63975e3e.join(''); })();\n",
        "module.exports = _fa1f85493086;\n",
    );
    let scanner = CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("compile embedded detectors");
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("sample.js".into()),
            ..Default::default()
        },
    };

    let matches = scanner.scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback);
    assert!(
        matches
            .iter()
            .flatten()
            .any(
                |matched| matched.detector_id.as_ref() == "github-classic-pat"
                    && matched.credential.as_ref() == secret
            ),
        "production scan must surface the exact recovered GitHub PAT; got {matches:?}"
    );
}

#[test]
fn obfuscated_javascript_array_join_without_secret_prefix_is_not_emitted() {
    let joined_value = "ordinarymetadatavalue";
    let text = "const _a = (() => { const _b = [\"ordinary\", \"metadata\", \
                \"value\"]; return _b.join(\"\"); })();";

    assert!(has_concatenation_indicators_for_test(text));
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert!(
        !joined[original_end..].contains(joined_value),
        "non-credential array metadata must not become a synthetic candidate"
    );
}

#[test]
fn non_empty_javascript_array_join_is_not_a_concat_indicator() {
    let text = "const values = [\"alpha\", \"beta\"].join(',');";
    assert!(!has_concatenation_indicators_for_test(text));
}

#[test]
fn unrelated_empty_join_does_not_authorize_known_prefix_array() {
    let secret = "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";
    let text = concat!(
        "const harmless = [\"alpha\", \"beta\"].join('');\n",
        "const _b = [\"ghp_\", \"69121b4cdeef\", \"f121c88dffac\", ",
        "\"1f9dbc2giIjE\"].join('-');",
    );

    assert!(has_concatenation_indicators_for_test(text));
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert!(
        !joined[original_end..].contains(secret),
        "an empty join on another array must not authorize recovery"
    );
}

#[test]
fn dynamic_array_elements_do_not_emit_partial_known_prefix_candidate() {
    let partial = "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";
    let text = concat!(
        "const runtime = getPart(); ",
        "const _b = [\"ghp_\", runtime, \"69121b4cdeeff121c88dffac1f9dbc2giIjE\"]",
        ".join('');",
    );

    assert!(has_concatenation_indicators_for_test(text));
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert!(
        !joined[original_end..].contains(partial),
        "dropping a dynamic array element must not fabricate a credential"
    );
}

// ── A `+`-split credential reassembled across two real source lines ──────────

/// The canonical "secret split across lines" case: `api_key = "AKIA" +` on line
/// one continued by `"IOSFODNN7EXAMPLE"` on line two reassembles to the whole
/// AWS access-key id, appended after the untouched original two-line body.
#[test]
fn plus_concat_across_two_lines_reassembles_credential() {
    let text = "api_key = \"AKIA\" +\n\"IOSFODNN7EXAMPLE\"";
    let (joined, original_end) = preprocess_multiline_for_test(text);
    assert_eq!(joined, format!("{text}\nAKIAIOSFODNN7EXAMPLE"));
    assert_eq!(original_end, text.len());
    assert!(
        joined.starts_with(text),
        "original bytes preserved verbatim"
    );
}

// ── 4. Non-secret multiline is NOT reassembled ───────────────────────────────

/// Plain multi-line prose has no concatenation indicator, so it passes through
/// byte-identically with NOTHING appended (joined == input exactly).
#[test]
fn non_secret_prose_multiline_is_unchanged() {
    let prose = "This is a normal\nparagraph of text\nwith no secrets here";
    assert!(!has_concatenation_indicators_for_test(prose));
    let (joined, original_end) = preprocess_multiline_for_test(prose);
    assert_eq!(joined, prose, "prose must not gain an appended candidate");
    assert_eq!(original_end, prose.len());
}

// ── Structural cluster reassembly: positive + non-credential negative twin ────

/// Two related, credential-named fragments (`apikey_part1`, `apikey_part2`)
/// cluster on their shared `apikey` prefix and reassemble into one candidate,
/// mapped back to the cluster's first source line (line 1) with exact offsets.
#[test]
fn structural_cluster_reassembles_related_credential_fragments() {
    let lines = [
        "apikey_part1 = \"AKIAIOSFO\"",
        "apikey_part2 = \"DNN7EXAMPLE\"",
    ];
    let offsets = line_offsets(&lines);
    let cache = FragmentCache::new(64);
    let (joined, mappings) = collect_structural_fragments_for_test(&lines, &offsets, 0, &cache);

    assert_eq!(
        joined,
        vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
        "the two credential fragments must reassemble to the whole key"
    );
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].line_number, 1, "cluster maps to its first line");
    assert_eq!(mappings[0].start_offset, 0);
    assert_eq!(mappings[0].end_offset, "AKIAIOSFODNN7EXAMPLE".len());
}

/// The negative twin: identically-shaped fragments whose names are NOT
/// credential-like (`greeting_part*`) are dropped (no cluster, no candidate).
#[test]
fn structural_cluster_skips_non_credential_names() {
    let lines = [
        "greeting_part1 = \"Hello wo\"",
        "greeting_part2 = \"rld today\"",
    ];
    let offsets = line_offsets(&lines);
    let cache = FragmentCache::new(64);
    let (joined, mappings) = collect_structural_fragments_for_test(&lines, &offsets, 0, &cache);

    assert_eq!(
        joined,
        Vec::<String>::new(),
        "non-credential-named fragments must not reassemble"
    );
    assert_eq!(mappings.len(), 0);
}

// ── Structural `+`-variable-reference resolver: positive + negative twin ──────

/// `aws_key = aws_prefix + aws_suffix` resolves each identifier to its earlier
/// recorded literal and joins them, even though the two fragment names share no
/// common prefix. The resolved fragment is stamped with the synthetic base line.
#[test]
fn structural_variable_reference_resolves_prefix_and_suffix() {
    let lines = [
        "aws_prefix = \"AKIA\"",
        "aws_suffix = \"IOSFODNN7EXAMPLE\"",
        "aws_key = aws_prefix + aws_suffix",
    ];
    let offsets = line_offsets(&lines);
    let cache = FragmentCache::new(64);
    let (joined, mappings) = collect_structural_fragments_for_test(&lines, &offsets, 0, &cache);

    assert_eq!(joined, vec!["AKIAIOSFODNN7EXAMPLE".to_string()]);
    assert_eq!(mappings.len(), 1);
    assert_eq!(
        mappings[0].line_number, SYNTHETIC_BASE_LINE,
        "resolved var-ref fragments carry the synthetic base line"
    );
    assert_eq!(mappings[0].start_offset, 0);
    assert_eq!(mappings[0].end_offset, "AKIAIOSFODNN7EXAMPLE".len());
}

/// Negative twin: when the referenced identifiers were never assigned a
/// literal, the var-reference resolver cannot glue anything (no candidate).
#[test]
fn structural_variable_reference_unresolved_yields_nothing() {
    // `count` / `amount` are never assigned string literals above, so the
    // `total = count + amount` reference cannot resolve to a value.
    let lines = ["total_key = count + amount"];
    let offsets = line_offsets(&lines);
    let cache = FragmentCache::new(64);
    let (joined, mappings) = collect_structural_fragments_for_test(&lines, &offsets, 0, &cache);

    assert_eq!(joined, Vec::<String>::new());
    assert_eq!(mappings.len(), 0);
}

// ── Template-literal interpolation resolver: positive + negatives ─────────────

/// Adjacent `${a}${b}` interpolations resolve each identifier to its bound
/// literal and concatenate (the whole `xoxb-…` token).
#[test]
fn template_literal_adjacent_interpolation_reassembles() {
    let resolved = resolve_template_reference_for_test(
        "token = `${a}${b}`;",
        &[("a", "xoxb-"), ("b", "123456789012")],
    );
    assert_eq!(resolved, Some("xoxb-123456789012".to_string()));
}

/// A string literal spliced INTO an interpolation (`ghp_${"BODY"}`) contributes
/// its inner bytes verbatim; surrounding template text is kept.
#[test]
fn template_literal_string_literal_interpolation_reassembles() {
    let resolved = resolve_template_reference_for_test("x = `ghp_${\"BODY123456\"}`", &[]);
    assert_eq!(resolved, Some("ghp_BODY123456".to_string()));
}

/// Negative twin: any unresolved interpolation reference makes the whole
/// resolver return `None` (a partial / garbage candidate is never emitted).
#[test]
fn template_literal_unresolved_reference_returns_none() {
    let resolved = resolve_template_reference_for_test("x = `${a}${missing}`", &[("a", "xoxb-")]);
    assert_eq!(resolved, None);
}

// ── Fragment-name prefix extraction (cluster grouping key) ────────────────────

/// `extract_prefix` strips `_`/`-` separators, `part` segments (case-
/// insensitive), and trailing digits so split-credential fragment names collapse
/// to one grouping key.
#[test]
fn extract_prefix_collapses_fragment_suffix_and_digits() {
    assert_eq!(extract_prefix_for_test("apikey_part1"), "apikey");
    // A `part` segment mid-name plus a trailing digit both strip; case-folded.
    assert_eq!(extract_prefix_for_test("TOKEN_PART_2"), "token");
    // `prefix`/`suffix` are NOT the literal `part` token, so they survive as
    // body characters (distinguishing this from the credential-suffix stripper).
    assert_eq!(extract_prefix_for_test("aws_prefix"), "awsprefix");
    assert_eq!(extract_prefix_for_test("aws_suffix"), "awssuffix");
}
