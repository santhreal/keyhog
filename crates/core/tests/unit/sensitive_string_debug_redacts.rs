//! §15 fix: SensitiveString::Debug must never emit the inner string.
//!
//! `SensitiveString` carries scan-chunk data that can contain raw credential
//! material (decoded secrets, env-file lines, archive-entry contents). The
//! previous `{:?}` impl printed `SensitiveString("actual content")`, which
//! would expose the bytes in test failure output, `tracing::debug!(?chunk)`
//! spans, and panic messages. The fix prints only the byte count, matching
//! the pattern from `Credential::Debug` (kimi-wave1 audit finding 1.1).

use keyhog_core::SensitiveString;

#[test]
fn sensitive_string_debug_does_not_emit_content() {
    // Use a plausible secret-shaped value so the test would fail visibly
    // if the old `{:?}` impl were restored.
    let secret = concat!("AK", "IAIOSFODNN7EXAMPLE");
    let s = SensitiveString::from(secret);
    let debug_output = format!("{s:?}");

    // Must not contain the raw secret bytes.
    assert!(
        !debug_output.contains("AKIA"),
        "SensitiveString Debug must not emit raw bytes; got: {debug_output}"
    );
    // Must contain a redaction indicator so the output is still useful.
    assert!(
        debug_output.contains("redacted"),
        "SensitiveString Debug must indicate redaction; got: {debug_output}"
    );
    // The byte-count hint must be present (allows checking field lengths
    // without revealing content).
    assert!(
        debug_output.contains(&secret.len().to_string()),
        "SensitiveString Debug must include the byte count; got: {debug_output}"
    );
}

#[test]
fn sensitive_string_debug_empty_string_does_not_panic() {
    let s = SensitiveString::from("");
    let out = format!("{s:?}");
    assert!(out.contains("redacted"), "empty SensitiveString Debug must indicate redaction; got: {out}");
    assert!(!out.is_empty(), "empty SensitiveString Debug must not be empty");
}

#[test]
fn chunk_debug_does_not_emit_data_content() {
    use keyhog_core::{Chunk, ChunkMetadata};
    let secret = concat!("SK", "_LIVE_abcdefghijklmnopqrstuvwxyz012345");
    let chunk = Chunk {
        data: SensitiveString::from(secret),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("app.env".into()),
            ..Default::default()
        },
    };
    let debug_output = format!("{chunk:?}");
    assert!(
        !debug_output.contains("SK_LIVE"),
        "Chunk Debug must not expose the data field content; got: {debug_output}"
    );
}
