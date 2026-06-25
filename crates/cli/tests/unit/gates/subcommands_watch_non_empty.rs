//! Gate `subcommands::watch`: substantive source, no todo!/unimplemented! in prod paths.

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
