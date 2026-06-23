//! Gate `daemon::server`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn daemon_server_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/daemon/server.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "daemon::server: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "daemon::server: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("tracing::warn!(\"daemon: connection ended with error: {e:#}\");")
            && !prod.contains("tracing::debug!(\"daemon: connection ended with error: {e:#}\");"),
        "daemon connection framing/protocol errors must be warn-visible, not debug-only"
    );
    assert!(
        prod.contains(".context(\"daemon: accept loop task failed during shutdown\")?")
            && prod.contains("fn remove_daemon_socket_on_shutdown(")
            && prod.contains("daemon: remove socket {} during shutdown"),
        "daemon shutdown must surface accept-loop join and socket cleanup failures"
    );
    assert!(
        !prod.contains("let _ = accept_task.await")
            && !prod.contains("let _ = std::fs::remove_file(&socket_path)"),
        "daemon shutdown must not discard accept-loop or socket cleanup results"
    );
}
