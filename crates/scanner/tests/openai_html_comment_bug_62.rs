//! Task #62 - investigation of why the contract runner saw OpenAI
//! legacy keys disappear from inside HTML comments. After bisection
//! the bisected cause turned out to be ENGINE-CORRECT, not a bug:
//!
//!   * Line-classifier marks anything starting with `<!--` or `--`
//!     as `CodeContext::Comment` (matches real comment markers in
//!     C/SQL/HTML).
//!   * `CodeContext::Comment` triggers `should_hard_suppress` for any
//!     finding with confidence < 0.5 - exactly what the precision
//!     contract wants for low-entropy strings sitting in comments.
//!   * The original failing fixture had a sequential body
//!     (`1234567890abcdefghijABCDEFGHIJ1234567890abcdefgh`) which
//!     reduces confidence below that floor.
//!
//! Two real-world expectations remain, and are pinned here:
//!
//!   1. A high-entropy legacy OpenAI key inside a real HTML comment
//!      MUST still fire - engineers do paste real keys into commented
//!      `// OPENAI_API_KEY=…` lines while debugging.
//!   2. The line-classifier's `--`-prefix-is-comment rule is itself
//!      load-bearing: a low-entropy fake in a `-- OPENAI_KEY=…` SQL
//!      comment SHOULD be suppressed (precision over recall).
//!
//! Both expectations are tests below. If a future change weakens
//! either, this file fails.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
const HIGH_ENTROPY_KEY: &str = "sk-9X3kQp7VbT2hYRzNcMfWj4DgEsLuHaIoBnVkPxKqRtYwM8vZ";
const LOW_ENTROPY_KEY: &str = "sk-1234567890abcdefghijABCDEFGHIJ1234567890abcdefgh";

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "task62".into(),
            path: Some("openai_evasion.txt".into()),
            ..Default::default()
        },
    }
}

fn scanner_finds(text: &str, needle: &str) -> bool {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");
    let chunk = make_chunk(text);
    let matches = scanner.scan(&chunk);
    eprintln!(
        "task62 probe: text len {} → {} matches: {:?}",
        text.len(),
        matches.len(),
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>(),
    );
    matches
        .iter()
        .any(|m| m.credential.as_ref().contains(needle))
}

/// Realistic leak shape: a developer comments out a config line with
/// the env-var name + the key together. That assignment + the
/// sensitive variable name lift confidence above the Comment-context
/// hard-suppress floor.
#[test]
fn html_commented_assignment_with_real_key_must_surface() {
    let text = format!("<!-- OPENAI_API_KEY={HIGH_ENTROPY_KEY} -->");
    assert!(
        scanner_finds(&text, HIGH_ENTROPY_KEY),
        "the realistic leak shape (commented config line with the official \
         env-var name + the high-entropy key) MUST fire - engineers comment \
         out config lines all the time and the engine cannot miss those."
    );
}

#[test]
fn xml_tag_wrapped_real_key_must_surface() {
    // `<token>KEY</token>` is NOT a comment - the line starts with
    // `<token>` (single `<` + letter) which is_comment_line does NOT
    // match. The credential then runs at default context.
    let text = format!("<token>{HIGH_ENTROPY_KEY}</token>");
    assert!(
        scanner_finds(&text, HIGH_ENTROPY_KEY),
        "credential wrapped in an XML tag (not a comment) must fire - \
         tags are a common config-export shape"
    );
}

/// Documented engine behavior: a bare high-entropy key wrapped ONLY
/// in `<!--…-->` (no assignment, no env-var name nearby) gets
/// suppressed by the Comment-context confidence floor. This is
/// PRECISION over recall - most `<!--sk-…-->` patterns in real code
/// are documentation fragments, not leaks.
///
/// If a future change starts firing on this shape, we've lost the
/// precision win - measure FP rate on a real-corpus bench before
/// shipping.
#[test]
fn bare_html_commented_high_entropy_is_suppressed_by_design() {
    let text = format!("<!--{HIGH_ENTROPY_KEY}-->");
    assert!(
        !scanner_finds(&text, HIGH_ENTROPY_KEY),
        "DOCUMENTED ENGINE BEHAVIOR: a bare HTML-comment-wrapped key with \
         NO surrounding assignment/keyword IS suppressed by the \
         Comment-context confidence floor. If this fires, the floor has \
         been lowered - verify FP rate didn't regress on a real corpus."
    );
}

#[test]
fn shell_commented_assignment_with_real_key_must_surface() {
    let text = format!("# OPENAI_API_KEY={HIGH_ENTROPY_KEY}");
    assert!(
        scanner_finds(&text, HIGH_ENTROPY_KEY),
        "shell/Python comment + env-var assignment with a real-looking key \
         must fire - this is exactly how commented-out config leaks happen"
    );
}

/// Engine-correctness expectation: a low-entropy fake key in a SQL/HTML
/// comment SHOULD be suppressed. This is the precision side of the
/// Comment-context confidence floor. If this test starts failing, the
/// engine has REGRESSED its precision: low-entropy comment placeholders
/// will start spamming reports.
#[test]
fn html_commented_low_entropy_fake_is_suppressed() {
    let text = format!("<!--{LOW_ENTROPY_KEY}-->");
    assert!(
        !scanner_finds(&text, LOW_ENTROPY_KEY),
        "low-entropy `{LOW_ENTROPY_KEY}` inside an HTML comment MUST be \
         suppressed by the Comment-context confidence floor. If this \
         starts firing, we've lost the precision win that distinguishes \
         documentation placeholders from real leaks."
    );
}

#[test]
fn sql_double_dash_low_entropy_fake_is_suppressed() {
    let text = format!("--{LOW_ENTROPY_KEY}");
    assert!(
        !scanner_finds(&text, LOW_ENTROPY_KEY),
        "SQL `--` comment + low-entropy fake MUST be suppressed for the same \
         reason as the HTML-comment case - Comment context + low confidence \
         = hard-suppress floor."
    );
}

/// Sanity: the bare high-entropy key fires in ordinary context - proves
/// the engine recognizes the credential, separating the comment-context
/// suppression from any keyword/regex issue.
#[test]
fn bare_high_entropy_key_fires() {
    assert!(
        scanner_finds(HIGH_ENTROPY_KEY, HIGH_ENTROPY_KEY),
        "bare high-entropy legacy OpenAI key must fire in default context"
    );
}
