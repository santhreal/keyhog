//! Regression: the non-`multiline` passthrough preprocessor must attribute each
//! offset to its REAL physical line.
//!
//! Bug (pre-fix): `PreprocessedText::passthrough` (the `#[cfg(not(feature =
//! "multiline"))]` form) built a SINGLE whole-chunk `LineMapping` with
//! `line_number: 1`. So `line_for_offset` returned line 1 for EVERY offset in a
//! multi-line chunk. `match_line_number` then reported line 1 for a credential
//! on line 2, and `infer_context_with_documentation` (called at
//! `line - PREVIOUS_LINE_DISTANCE`) read the line ABOVE the credential. When
//! that line was a `#`/`//` comment, the credential — sitting on an ordinary
//! `key = value` line directly under the comment — was mis-classified as
//! `Comment` context and silently hard-suppressed. That is the ubiquitous
//! real-world shape:
//!
//!     # https://service.example/docs
//!     api_key=<secret>
//!
//! The fix builds one mapping per physical line (mirroring the `multiline`
//! passthrough), so line attribution — and therefore context classification —
//! is correct in BOTH feature builds. This test asserts the credential surfaces
//! AND lands on line 2, so it fails loudly under either regression
//! (suppression OR wrong reported line). It is feature-build-agnostic: it must
//! pass under default (`multiline`) and under `--no-default-features --features
//! simd` (non-`multiline`), which is where the bug lived.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn make_chunk(text: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "line-attr".into(),
            path: Some("config.txt".into()),
            ..Default::default()
        },
    }
}

fn line_attr_detector() -> DetectorSpec {
    DetectorSpec {
        id: "line-attr-probe".into(),
        name: "Line Attribution Probe".into(),
        service: "lineattr".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "lineattr_key=([A-Za-z0-9]{20,})".into(),
            group: Some(1),
            ..Default::default()
        }],
        keywords: vec!["lineattr_key".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

/// The credential is on line 2, directly under a `#` URL comment on line 1.
/// Pre-fix (non-`multiline`) this was attributed to line 1 → `Comment` context
/// → hard-suppressed. The fix surfaces it at line 2.
#[test]
fn credential_under_hash_comment_surfaces_on_line_two() {
    let scanner = CompiledScanner::compile(vec![line_attr_detector()]).expect("scanner compiles");
    // SECRET is a 24-char high-entropy body the detector captures verbatim.
    const SECRET: &str = "Xk9mPq2wL5nR8tWvZ4YbHc7T";
    let text = format!("# https://service.example/docs\nlineattr_key={SECRET}");
    let matches = scanner
        .scan(&make_chunk(&text))
        .expect("line attribution scan succeeds");

    let hit = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "line-attr-probe")
        .unwrap_or_else(|| {
            panic!(
                "credential directly under a `#` comment was suppressed — the \
                 passthrough line-attribution regression is back. matches={:?}",
                matches
                    .iter()
                    .map(|m| (m.detector_id.as_ref(), m.location.line))
                    .collect::<Vec<_>>()
            )
        });

    assert_eq!(
        hit.credential.as_ref(),
        SECRET,
        "captured credential must be the line-2 body verbatim",
    );
    assert_eq!(
        hit.location.line,
        Some(2),
        "credential is on physical line 2 (line 1 is the comment); a report of \
         line 1 means the passthrough mapping collapsed all offsets to line 1",
    );
}

/// `//` comment variant + a second non-comment line above, to prove the fix
/// resolves arbitrary line indices (not just line 2) and is not a one-off.
#[test]
fn credential_on_line_three_reports_line_three() {
    let scanner = CompiledScanner::compile(vec![line_attr_detector()]).expect("scanner compiles");
    const SECRET: &str = "Qm4Rs7Tw8Vk2Bn5Lp9Zc3Xj";
    let text = format!("first config line\n// auth section below\nlineattr_key={SECRET}");
    let matches = scanner
        .scan(&make_chunk(&text))
        .expect("line attribution scan succeeds");

    let hit = matches
        .iter()
        .find(|m| m.detector_id.as_ref() == "line-attr-probe")
        .expect("credential on line 3 must surface");
    assert_eq!(hit.credential.as_ref(), SECRET);
    assert_eq!(
        hit.location.line,
        Some(3),
        "credential is on physical line 3; wrong line = passthrough mapping bug",
    );
}
