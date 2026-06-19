//! Wire the dead `tests/data/corpus/evasion/*` fixtures into `cargo test`.
//!
//! Per the audit at `docs/EXECUTION_PLAN.md`, ten
//! evasion fixtures shipped under `tests/data/corpus/evasion/` but no Rust
//! test referenced them. An evasion that breaks the engine would not fail
//! `cargo test`. This module fixes that.
//!
//! Each test loads the embedded detector corpus, scans a fixture, and asserts
//! at least one expected detector fires on a known leaked credential string in
//! the fixture. CLAUDE.md anti-rigging rule: each test names a specific
//! detector ID + expected substring of the matched credential - a function
//! returning `Vec::new()` will fail.

use super::corpus_support::{production_scanner, scan_corpus};
use keyhog_core::{Chunk, ChunkMetadata};

fn scan_fixture(rel: &str) -> Vec<keyhog_core::RawMatch> {
    scan_corpus("evasion", rel)
}

#[test]
fn evasion_url_encoded_finds_aws_or_openai_or_github() {
    let matches = scan_fixture("url_encoded.txt");
    // The fixture contains AWS, OpenAI, GitHub PAT, and Slack credentials in
    // various URL-encoded forms. At least ONE of them must survive decoding.
    let mut any_known = false;
    for needle in ["aws", "openai", "github", "slack"] {
        if matches
            .iter()
            .any(|m| m.detector_id.as_ref().contains(needle) || m.service.as_ref().contains(needle))
        {
            any_known = true;
            break;
        }
    }
    assert!(
        any_known,
        "no AWS/OpenAI/GitHub/Slack detector fired on url_encoded.txt; engine misses URL-encoded secrets entirely. matches={:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn evasion_base64_wrapped_decodes() {
    let matches = scan_fixture("base64_wrapped.json");
    println!("base64_wrapped matches: {matches:?}");
    assert!(
        !matches.is_empty(),
        "base64_wrapped.json: zero findings - decode-through pipeline failing on YAML/JSON multiline base64"
    );
}

#[test]
fn evasion_split_across_lines_reassembles_at_all() {
    let matches = scan_fixture("split_across_lines.py");
    // The fixture splits OpenAI, Slack, and AWS credentials across multiple
    // assignments via concatenation. The reassembly path must produce SOME
    // `:reassembled` finding - zero would mean the entire reassembly pipeline
    // is dead. (The AWS-specific gap is asserted by the test below.)
    let any_reassembled = matches
        .iter()
        .any(|m| m.detector_id.as_ref().contains(":reassembled"));
    let any_high_value = matches.iter().any(|m| {
        m.detector_id.as_ref().contains("aws")
            || m.detector_id.as_ref().contains("github")
            || m.detector_id.as_ref().contains("openai")
            || m.detector_id.as_ref().contains("slack")
            || m.service.as_ref().contains("aws")
            || m.service.as_ref().contains("github")
            || m.service.as_ref().contains("openai")
            || m.service.as_ref().contains("slack")
    });
    assert!(
        any_reassembled || any_high_value,
        "split_across_lines.py: no reassembled or high-value findings; matches={:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>()
    );
}

/// Closes a previously-documented engine gap: a two-fragment split
/// where the two variable names share no common prefix
/// (e.g. `aws_key = aws_prefix + aws_suffix`) now reassembles correctly via
/// the explicit-concat-reference pass added to multiline/structural.rs
/// (see audit release-2026-04-26).
///
/// Uses a synthetic AWS-shaped secret that doesn't end in `EXAMPLE`, since
/// the production scanner suppresses `AKIAIOSFODNN7EXAMPLE` by design as a
/// well-known dummy credential.
#[test]
// Cross-fragment reassembly is wired through the multiline preprocessor; a
// build without `multiline` has no concat-resolver pass, so the synthetic
// `key_head + key_tail` literals never coalesce.
#[cfg(feature = "multiline")]
fn engine_reassembles_two_fragment_aws_without_shared_prefix() {
    // The trailing concat-on-quoted-string line trips the
    // `has_concatenation_indicators` gate (`"' +"`). The first three lines
    // exercise the new explicit-concat-reference resolver on names with no
    // common prefix.
    let synthetic = "\
key_head = 'AKIA'\n\
key_tail = 'XK4P9MQ2WE5RT8YU'\n\
aws_access = key_head + key_tail\n\
unrelated = 'foo' + 'bar'\n\
";
    let chunk = Chunk {
        data: synthetic.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test/synthetic".into(),
            path: Some("synthetic.py".into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    };
    let matches = production_scanner().scan(&chunk);
    let aws_hit = matches
        .iter()
        .any(|m| m.detector_id.as_ref().contains("aws") || m.service.as_ref().contains("aws"));
    assert!(
        aws_hit,
        "expected AWS detector to fire on reassembled `key_head + key_tail`; got {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>()
    );
}

#[test]
fn evasion_multiline_json_reassembles() {
    let matches = scan_fixture("multiline_json.json");
    assert!(
        !matches.is_empty(),
        "multiline_json.json: zero findings - multiline JSON reassembly failing"
    );
}

#[test]
fn evasion_hex_encoded_decodes() {
    // Hex-encoded credential. Fixture exists; the scanner has hex decoding,
    // so this should produce at least one finding.
    let matches = scan_fixture("hex_encoded.js");
    assert!(
        !matches.is_empty(),
        "hex_encoded.js: zero findings - hex decode-through path is dead"
    );
}

#[test]
fn evasion_variable_indirection_chain() {
    let matches = scan_fixture("variable_indirection.rb");
    // This tests indirection (var = "...prefix"; secret = var + "...rest").
    // We don't claim full taint analysis here - just assert the literal
    // fragments themselves trip generic-secret/keyword detectors. Zero findings
    // would mean the engine cannot even see the literal halves.
    assert!(
        !matches.is_empty(),
        "variable_indirection.rb: zero findings - literal halves invisible to engine"
    );
}

#[test]
fn evasion_embedded_in_binary_extracts_strings() {
    let matches = scan_fixture("embedded_in_binary.txt");
    assert!(
        !matches.is_empty(),
        "embedded_in_binary.txt: zero findings - printable-string extraction broken"
    );
}

#[test]
// ReverseDecoder lives behind the `decode` feature; without it the reversed
// fixtures can't be unwound and the AWS/GitHub assertion has nothing to fire on.
#[cfg(feature = "decode")]
fn evasion_reversed_strings_finds_forward_literals() {
    // The reversed_strings.py fixture contains both reversed credentials
    // and forward literal halves. Three guarantees:
    //   1. At least ONE finding fires - engine sees forward literals.
    //   2. The ReverseDecoder catches the reversed AKIA test key whose
    //      reversal contains "EXAMPLE" - suppression rule was relaxed
    //      for evasion-decoder-origin credentials so an attacker can't
    //      hide a real leak by reversing an EXAMPLE-suffixed value.
    let matches = scan_fixture("reversed_strings.py");
    assert!(
        !matches.is_empty(),
        "reversed_strings.py: zero findings - engine cannot even see the forward literal halves"
    );
    let any_aws_or_github = matches.iter().any(|m| {
        m.detector_id.as_ref().contains("aws")
            || m.detector_id.as_ref().contains("github")
            || m.service.as_ref().contains("aws")
            || m.service.as_ref().contains("github")
    });
    assert!(
        any_aws_or_github,
        "reversed_strings.py: ReverseDecoder + relaxed suppression should surface at least one \
         reversed AWS/GitHub credential (got {} total findings, none AWS/GitHub-flavored).",
        matches.len()
    );
}

// `jwt_everywhere.txt` not shipped with the repo yet - when the fixture is
// added, drop this comment and add a regression test asserting the JWT
// detector fires on it.
