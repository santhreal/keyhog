//! Gate `subcommands::watch`: substantive source, no todo!/unimplemented! in prod paths.

use keyhog::testing::{CliTestApi as _, API};
use std::time::Duration;

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
