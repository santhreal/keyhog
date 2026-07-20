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
    let await_position = prod
        .find("match accept_task.await")
        .expect("daemon shutdown awaits the accept task");
    let cleanup_position = prod
        .find("let cleanup = remove_daemon_socket_on_shutdown(socket_path)")
        .expect("daemon shutdown records socket cleanup");
    assert!(
        await_position < cleanup_position
            && prod.contains("DaemonServiceFailure::AcceptLoopTask(join_error.to_string())")
            && prod.contains("fn remove_daemon_socket_on_shutdown(")
            && prod.contains("daemon: remove socket {} during shutdown"),
        "daemon shutdown must preserve accept-loop failures and unlink only after termination"
    );
    assert!(
        !prod.contains("let _ = accept_task.await")
            && !prod.contains("let _ = std::fs::remove_file(&socket_path)"),
        "daemon shutdown must not discard accept-loop or socket cleanup results"
    );
    assert!(
        prod.contains("fn compile_daemon_scan_runtime(")
            && prod.contains("fn bind_trusted_daemon_socket(")
            && prod.contains("fn spawn_accept_loop(")
            && prod.contains("async fn run_accept_loop(")
            && prod.contains("fn handle_connection_spawn_error(")
            && prod.contains("async fn handle_accept_error("),
        "daemon server lifecycle must have named owners for compile, trusted bind, accept loop, connection-spawn errors, and accept errors"
    );
    assert!(
        prod.contains("pub(crate) fn is_transient_accept_error(")
            && !prod.contains("pub fn is_transient_accept_error("),
        "daemon accept-error classifier is an internal server policy; tests must use the testing facade instead of widening the production API"
    );
    let spawn_error = prod
        .split("fn handle_connection_spawn_error(")
        .nth(1)
        .and_then(|tail| tail.split("async fn handle_accept_error(").next())
        .expect("connection-spawn error handler extractable");
    assert!(
        spawn_error.contains("eprintln!")
            && spawn_error.contains("notify_waiters()")
            && spawn_error.contains("shutting down"),
        "connection handler spawn failure must be operator-visible and trigger daemon shutdown"
    );
    let run_body = prod
        .split("pub(crate) async fn run_with_backend_override(")
        .nth(1)
        .and_then(|tail| tail.split("fn compile_daemon_scan_runtime(").next())
        .expect("run_with_backend_override before compile helper");
    assert!(
        !run_body.contains("UnixListener::bind")
            && !run_body.contains("listener.accept()")
            && !run_body.contains("trust::set_socket_mode_user_only"),
        "run_with_backend_override must delegate trusted bind/chmod and accept-loop internals"
    );
}
