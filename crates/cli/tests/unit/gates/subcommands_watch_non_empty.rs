//! Gate `subcommands::watch`: substantive source, no todo!/unimplemented! in prod paths.

use keyhog::testing::{CliTestApi as _, API};
use keyhog_core::{MatchLocation, RawMatch, Severity};
use std::sync::Arc;
use std::time::Duration;

fn raw_match(detector_id: &str, line: Option<usize>, offset: usize) -> RawMatch {
    raw_match_with_hash(detector_id, line, offset, [0u8; 32])
}

fn raw_match_with_hash(
    detector_id: &str,
    line: Option<usize>,
    offset: usize,
    credential_hash: [u8; 32],
) -> RawMatch {
    RawMatch {
        detector_id: Arc::from(detector_id),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential: keyhog_core::SensitiveString::from("secret"),
        credential_hash: credential_hash.into(),
        companions: std::collections::HashMap::new(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("watched.env")),
            line,
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: None,
        confidence: None,
    }
}

#[test]
fn subcommands_watch_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/watch.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "subcommands::watch: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "subcommands::watch: todo!/unimplemented! forbidden in non-test source"
    );
}

#[test]
fn watch_dedupe_hashes_raw_bytes_not_lossy_text() {
    let first = b"API_KEY=abc\x80def\n";
    let second = b"API_KEY=abc\x81def\n";

    assert_eq!(
        String::from_utf8_lossy(first),
        String::from_utf8_lossy(second),
        "test fixture must prove two byte-distinct edits collapse to the same lossy text"
    );
    assert_ne!(
        API.watch_content_hash(first),
        API.watch_content_hash(second),
        "watch dedupe must key on raw bytes so a real invalid-UTF-8 edit is re-scanned"
    );
    assert_eq!(
        API.watch_duplicate_event_decisions(first, first, Duration::from_millis(1)),
        (false, true),
        "same-path same-byte notify bursts inside the dedupe window must suppress the second scan"
    );
    assert_eq!(
        API.watch_duplicate_event_decisions(first, second, Duration::from_millis(1)),
        (false, false),
        "byte-distinct edits inside the dedupe window must still be re-scanned even when lossy text is identical"
    );
    assert_eq!(
        API.watch_duplicate_event_decisions(first, first, Duration::from_secs(2)),
        (false, false),
        "same-byte events after the dedupe window are fresh scans, not permanent suppression"
    );
}

#[test]
fn watch_findings_dedupe_collapses_identical_finding_burst() {
    // A single save fires a CREATE+MODIFY(+CLOSE_WRITE) burst. A read taken
    // mid-write can return bytes that differ from the final read (e.g. missing
    // the trailing newline) yet locate the SAME secret at the SAME offset -- so
    // the raw-content dedupe misses and the finding printed twice. The finding
    // fingerprint keys on detector, credential hash, and complete location
    // (never credential bytes), so both reads of the same secret share it.
    let full_read = [raw_match("aws-access-key", Some(1), 17)];
    // Same finding set surfaced by a byte-distinct partial read; the secret sits
    // at the same offset, so the fingerprint must match the full read's.
    let partial_read = [raw_match("aws-access-key", Some(1), 17)];
    let fp_full = API.watch_findings_fingerprint(&full_read);
    let fp_partial = API.watch_findings_fingerprint(&partial_read);
    assert_eq!(
        fp_full, fp_partial,
        "two reads locating the same secret at the same offset must fingerprint identically"
    );
    assert_eq!(
        API.watch_duplicate_findings_decisions(fp_full, fp_partial, Duration::from_millis(1)),
        (false, true),
        "a save burst that re-finds the same secret must print once, not twice"
    );

    // A genuine edit that surfaces a DIFFERENT finding set is a different
    // fingerprint and must still print.
    let edited = [raw_match("aws-access-key", Some(4), 92)];
    let fp_edited = API.watch_findings_fingerprint(&edited);
    assert_ne!(
        fp_full, fp_edited,
        "a finding at a different location must not collide with the original fingerprint"
    );
    assert_eq!(
        API.watch_duplicate_findings_decisions(fp_full, fp_edited, Duration::from_millis(1)),
        (false, false),
        "a real edit changing the finding set must re-print, not be suppressed"
    );

    // Replacing one credential with another at the same detector and span is a
    // real security event. The old location-only key suppressed it for 750 ms.
    let replacement_a = [raw_match_with_hash(
        "aws-access-key",
        Some(1),
        17,
        [0x11; 32],
    )];
    let replacement_b = [raw_match_with_hash(
        "aws-access-key",
        Some(1),
        17,
        [0x22; 32],
    )];
    let fp_replacement_a = API.watch_findings_fingerprint(&replacement_a);
    let fp_replacement_b = API.watch_findings_fingerprint(&replacement_b);
    assert_ne!(fp_replacement_a, fp_replacement_b);
    assert_eq!(
        API.watch_duplicate_findings_decisions(
            fp_replacement_a,
            fp_replacement_b,
            Duration::from_millis(1),
        ),
        (false, false),
        "a different credential at the same span must emit immediately"
    );

    // Fingerprint is order-independent: the same set in a different order must
    // collapse, so a backend that emits findings in a different order across two
    // reads of one save still dedupes.
    let a = raw_match("aws-access-key", Some(1), 17);
    let b = raw_match("github-pat", Some(9), 40);
    let forward = [a.clone(), b.clone()];
    let reversed = [b, a];
    assert_eq!(
        API.watch_findings_fingerprint(&forward),
        API.watch_findings_fingerprint(&reversed),
        "finding-set fingerprint must be independent of match order"
    );

    // Same fingerprint after the dedupe window is a fresh scan, not permanent
    // suppression.
    assert_eq!(
        API.watch_duplicate_findings_decisions(fp_full, fp_full, Duration::from_secs(2)),
        (false, false),
        "an identical finding set after the dedupe window must re-print"
    );
}

#[test]
fn watch_notify_channel_send_failure_is_visible() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/watch.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("let _ = tx.send(res)"),
        "watch must not silently discard notify event channel send failures"
    );
    assert!(
        src.contains("tx.send(res).is_err()")
            && src.contains("internal watcher event channel closed")
            && src.contains("changed path was NOT re-scanned")
            && src.contains("AtomicBool"),
        "watch notify channel closure must be surfaced once with recall-loss context"
    );
}
