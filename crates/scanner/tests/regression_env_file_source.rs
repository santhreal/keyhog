//! Regression contract for scanning dotenv (`.env`) files.
//!
//! The KEY=VALUE / dotenv parser lives in
//! `crates/scanner/src/structured/parsers/env.rs` (NOT in `keyhog-sources`,
//! which only reads bytes off a backend). It is `pub(crate)`, so this file pins
//! its OBSERVABLE contract through the public `CompiledScanner::scan` surface: a
//! planted secret inside an `.env` file must surface with the correct 1-based
//! line, under every dotenv quoting/`export`/inline-comment style, and comment
//! + blank lines must never shift a real secret's line or fabricate a match.
//!
//! HOST-INDEPENDENCE: the openai-api-key detector is LITERAL-anchored
//! (keywords include `sk-`), so it fires on the scalar/AC-literal path with no
//! Hyperscan/SIMD/GPU present. Every assertion below is therefore true on a
//! bare CI runner, not only on an accelerated host. The `.env` structured pass
//! is purely additive context — the raw byte scan already recovers each value —
//! so these contracts hold whether or not the structured preprocessor runs,
//! which is exactly the recall-safe, no-silent-degrade behaviour we want to
//! lock.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch, Severity};
use keyhog_scanner::CompiledScanner;

/// The proven high-entropy legacy OpenAI key shape: `sk-` + exactly 48
/// alphanumeric chars, matched by `sk-[a-zA-Z0-9]{48}\b`. Reused from the
/// existing bug-62 fixture so we know it clears the confidence/suppression
/// floors on the scalar path.
const KEY: &str = "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ";
/// A second, distinct legacy key: a permutation of `KEY`'s 48-char body, so it
/// has byte-identical Shannon entropy and fires the same detector, but a
/// different credential value (needed to observe two matches, since the final
/// match set dedups on (detector_id, credential)).
const KEY2: &str = "sk-qnzN2vhcoPRYHb9DWY8E4ZaKfXkMIVMLup3RBwxg7VQktsTj";

const OPENAI_DETECTOR_ID: &str = "openai-api-key";

/// Compile the full on-disk detector set and scan `content` as a file at
/// `path`. A fresh scanner per call keeps each test independent (matching the
/// pattern used by the other scanner integration tests).
fn scan_as(path: &str, content: &str) -> Vec<RawMatch> {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = Chunk {
        data: content.into(),
        metadata: ChunkMetadata {
            source_type: "envtest".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner.scan(&chunk)
}

/// True iff some match is the openai-api-key detector, carries exactly
/// `credential` (proving the reported bytes are the unquoted token with no
/// surrounding quote/comment/whitespace), and is anchored to `line`.
fn has_openai_at(matches: &[RawMatch], credential: &str, line: usize) -> bool {
    matches.iter().any(|m| {
        &*m.detector_id == OPENAI_DETECTOR_ID
            && &*m.credential == credential
            && m.location.line == Some(line)
    })
}

/// Count of openai-api-key matches (any line/credential). Used for the "no
/// secret present" negative twins and the dedup contract.
fn openai_count(matches: &[RawMatch]) -> usize {
    matches
        .iter()
        .filter(|m| &*m.detector_id == OPENAI_DETECTOR_ID)
        .count()
}

// ---------------------------------------------------------------------------
// Positive: the core KEY=VALUE contract + surfaced metadata.
// ---------------------------------------------------------------------------

#[test]
fn plain_key_value_surfaces_secret_with_service_severity_and_line() {
    let matches = scan_as(".env", &format!("OPENAI_API_KEY={KEY}\n"));
    let m = matches
        .iter()
        .find(|m| &*m.detector_id == OPENAI_DETECTOR_ID)
        .expect("openai key on a plain KEY=VALUE line must surface");
    assert_eq!(&*m.credential, KEY, "credential must be the exact token");
    assert_eq!(&*m.service, "openai", "service namespace must be openai");
    assert_eq!(m.severity, Severity::Critical, "openai key is critical");
    assert_eq!(m.location.line, Some(1), "single line is line 1");
    assert_eq!(
        m.location.file_path.as_deref(),
        Some(".env"),
        "location must carry the .env path metadata"
    );
}

#[test]
fn export_prefixed_key_still_surfaces_secret() {
    // `export KEY=VALUE` is a valid dotenv shell-export line; the `export `
    // prefix must be handled and the value recovered on line 1.
    let matches = scan_as(".env", &format!("export OPENAI_API_KEY={KEY}\n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "an `export`-prefixed dotenv assignment must still surface the secret"
    );
}

#[test]
fn double_quoted_value_surfaces_unquoted_credential() {
    // Value wrapped in ASCII double quotes: the reported credential must be the
    // token WITHOUT the surrounding quotes.
    let matches = scan_as(".env", &format!("OPENAI_API_KEY=\"{KEY}\"\n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "double-quoted value must surface the unquoted token at line 1"
    );
}

#[test]
fn single_quoted_value_surfaces_unquoted_credential() {
    let matches = scan_as(".env", &format!("OPENAI_API_KEY='{KEY}'\n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "single-quoted value must surface the unquoted token at line 1"
    );
}

#[test]
fn backtick_quoted_value_surfaces_unquoted_credential() {
    // dotenv-cli and several shells accept backtick-quoted bodies; the parser
    // documents this style explicitly.
    let matches = scan_as(".env", &format!("OPENAI_API_KEY=`{KEY}`\n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "backtick-quoted value must surface the unquoted token at line 1"
    );
}

#[test]
fn inline_comment_after_unquoted_value_is_not_part_of_credential() {
    // `KEY=<token> # note` — the inline comment must be stripped from an
    // UNQUOTED value, so the credential is exactly the token (no ` # note`).
    let matches = scan_as(
        ".env",
        &format!("OPENAI_API_KEY={KEY} # rotate quarterly\n"),
    );
    assert!(
        has_openai_at(&matches, KEY, 1),
        "inline comment after an unquoted value must not pollute the credential"
    );
}

#[test]
fn trailing_whitespace_value_is_trimmed_to_exact_token() {
    // Trailing spaces after the value must be trimmed; credential stays exact.
    let matches = scan_as(".env", &format!("OPENAI_API_KEY={KEY}   \n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "trailing whitespace must be trimmed, leaving the exact token at line 1"
    );
}

// ---------------------------------------------------------------------------
// Line-mapping: comments / blank lines must not shift a real secret's line.
// ---------------------------------------------------------------------------

#[test]
fn secret_after_comment_and_blank_lines_reports_correct_line() {
    // Lines: 1 `# header`, 2 blank, 3 `# note`, 4 blank, 5 the secret.
    let content = format!("# header\n\n# note\n\nOPENAI_API_KEY={KEY}\n");
    let matches = scan_as(".env", &content);
    assert!(
        has_openai_at(&matches, KEY, 5),
        "leading comment + blank lines must not shift the secret off line 5"
    );
}

#[test]
fn two_distinct_secrets_report_their_own_lines() {
    // Line 1 comment, line 2 first secret, line 3 blank, line 4 second secret.
    let content = format!("# api creds\nOPENAI_API_KEY={KEY}\n\nBACKUP_OPENAI_KEY={KEY2}\n");
    let matches = scan_as(".env", &content);
    assert!(
        has_openai_at(&matches, KEY, 2),
        "first secret must be anchored to line 2"
    );
    assert!(
        has_openai_at(&matches, KEY2, 4),
        "second, distinct secret must be anchored to line 4"
    );
}

#[test]
fn crlf_line_endings_report_correct_line() {
    // Windows CRLF `.env`: the parser trims `\r`; the secret sits on line 2.
    let content = format!("# windows env\r\nOPENAI_API_KEY={KEY}\r\n");
    let matches = scan_as(".env", &content);
    assert!(
        has_openai_at(&matches, KEY, 2),
        "CRLF line endings must still map the secret to line 2"
    );
}

// ---------------------------------------------------------------------------
// Malformed / adversarial lines: recall preserved, no fabricated matches.
// ---------------------------------------------------------------------------

#[test]
fn malformed_line_without_equals_does_not_break_following_valid_line() {
    // Line 1 has no `=` (malformed per contract → skipped by the parser); the
    // valid assignment on line 2 must still surface.
    let content = format!("THIS_LINE_HAS_NO_EQUALS_SIGN_AT_ALL\nOPENAI_API_KEY={KEY}\n");
    let matches = scan_as(".env", &content);
    assert!(
        has_openai_at(&matches, KEY, 2),
        "a preceding malformed (no `=`) line must not stop line 2 from parsing"
    );
    assert_eq!(
        openai_count(&matches),
        1,
        "exactly one openai match — the malformed line yields no extra secret \
         and the raw+synthetic hits dedup to one"
    );
}

#[test]
fn empty_key_line_still_scans_the_value() {
    // `=<token>` has an empty key; the parser skips emitting a synthetic pair,
    // but recall is preserved — the raw byte scan still surfaces the token.
    let matches = scan_as(".env", &format!("={KEY}\n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "an empty-key dotenv line must not drop the value from the scan"
    );
}

// ---------------------------------------------------------------------------
// Negative twins: no secret ⇒ no openai match.
// ---------------------------------------------------------------------------

#[test]
fn comment_blank_and_low_entropy_lines_produce_no_openai_match() {
    // A realistic secret-free `.env`: comments, a blank, and low-entropy
    // config values. Nothing here is an OpenAI key.
    let content = "# app config\nDEBUG=true\n\nPORT=8080\nLOG_LEVEL=info\n";
    let matches = scan_as(".env", content);
    assert_eq!(
        openai_count(&matches),
        0,
        "a secret-free dotenv file must yield zero openai-api-key matches"
    );
}

#[test]
fn quoted_low_entropy_placeholder_is_not_reported_as_openai_key() {
    // `API_KEY="changeme"` is a placeholder, not a real key.
    let matches = scan_as(".env", "API_KEY=\"changeme\"\n");
    assert_eq!(
        openai_count(&matches),
        0,
        "a quoted low-entropy placeholder must not be reported as an openai key"
    );
}

// ---------------------------------------------------------------------------
// Path / detection edges: structured `.env` detection is additive, not required
// for recall, and must recognise real dotenv filenames + path separators.
// ---------------------------------------------------------------------------

#[test]
fn dot_prefixed_and_suffixed_env_filenames_both_find_secret() {
    // `.env.production` (starts with `.env`) and `service.env` (ends `.env`)
    // are both dotenv files.
    let a = scan_as(".env.production", &format!("OPENAI_API_KEY={KEY}\n"));
    assert!(
        has_openai_at(&a, KEY, 1),
        "`.env.production` must be recognised and the secret surfaced"
    );
    let b = scan_as("service.env", &format!("OPENAI_API_KEY={KEY}\n"));
    assert!(
        has_openai_at(&b, KEY, 1),
        "`service.env` must be recognised and the secret surfaced"
    );
}

#[test]
fn windows_backslash_path_env_file_finds_secret() {
    // Adversarial path form: a Windows-style backslash path ending in `.env`.
    let matches = scan_as("C:\\app\\config\\.env", &format!("OPENAI_API_KEY={KEY}\n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "a backslash-separated `.env` path must still surface the secret"
    );
}

#[test]
fn non_env_path_still_finds_secret_via_raw_scan() {
    // Negative twin for structured detection: a `.txt` path does NOT trigger
    // the `.env` structured pass, yet the raw byte scan must still recover the
    // KEY=VALUE secret — the structured pass is additive, never load-bearing
    // for recall (no silent degrade).
    let matches = scan_as("notes.txt", &format!("OPENAI_API_KEY={KEY}\n"));
    assert!(
        has_openai_at(&matches, KEY, 1),
        "recall must not depend on `.env` structured detection — the raw scan \
         must surface the secret from a non-.env path too"
    );
}
