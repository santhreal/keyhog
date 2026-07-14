#![cfg(unix)]

use keyhog::testing::{CliTestApi as _, DaemonTerminalFixture, API};
use std::io::{Error, ErrorKind};

fn occupied_socket_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("temporary daemon directory");
    let socket = dir.path().join("daemon.sock");
    std::fs::write(&socket, b"bound socket fixture").expect("create socket cleanup fixture");
    (dir, socket)
}

#[tokio::test]
async fn fatal_listener_failure_cleans_socket_and_maps_to_system_exit() {
    let (_dir, socket) = occupied_socket_path();
    let error = API
        .finish_daemon_terminal_fixture(
            socket.clone(),
            DaemonTerminalFixture::FatalAccept(Error::new(
                ErrorKind::PermissionDenied,
                "listener descriptor became unusable",
            )),
        )
        .await
        .expect_err("fatal listener failure must leave the daemon as an error");

    assert!(
        !socket.exists(),
        "terminal error must be returned after socket cleanup"
    );
    assert_eq!(
        error.to_string(),
        "daemon service failed: listener accept failed fatally: listener descriptor became unusable"
    );
    assert_eq!(
        API.cli_error_exit_code(&error),
        keyhog::exit_codes::EXIT_SYSTEM_ERROR,
        "the typed daemon failure must override the nested permission-denied user-I/O mapping"
    );
}

#[tokio::test]
async fn handler_spawn_failure_cleans_socket_and_maps_to_system_exit() {
    let (_dir, socket) = occupied_socket_path();
    let error = API
        .finish_daemon_terminal_fixture(
            socket.clone(),
            DaemonTerminalFixture::ConnectionHandlerSpawn("connection limiter closed".to_string()),
        )
        .await
        .expect_err("handler spawn failure must leave the daemon as an error");

    assert!(
        !socket.exists(),
        "terminal error must be returned after socket cleanup"
    );
    assert_eq!(
        error.to_string(),
        "daemon service failed: connection handler spawn failed: connection limiter closed"
    );
    assert_eq!(
        API.cli_error_exit_code(&error),
        keyhog::exit_codes::EXIT_SYSTEM_ERROR
    );
}

#[tokio::test]
async fn cleanup_failure_cannot_mask_the_typed_terminal_failure() {
    let dir = tempfile::TempDir::new().expect("temporary daemon directory");
    let socket = dir.path().join("socket-is-a-directory");
    std::fs::create_dir(&socket).expect("create non-removable socket fixture");
    let error = API
        .finish_daemon_terminal_fixture(
            socket.clone(),
            DaemonTerminalFixture::FatalAccept(Error::new(
                ErrorKind::PermissionDenied,
                "listener descriptor became unusable",
            )),
        )
        .await
        .expect_err("fatal listener and cleanup failures must remain errors");

    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("daemon socket cleanup also failed")
            && rendered.contains("listener accept failed fatally"),
        "both failures must remain visible: {rendered}"
    );
    assert_eq!(
        API.cli_error_exit_code(&error),
        keyhog::exit_codes::EXIT_SYSTEM_ERROR,
        "cleanup failure must not hide the typed daemon terminal failure"
    );
    assert!(
        socket.is_dir(),
        "failed cleanup must leave the fixture intact"
    );
}

#[tokio::test]
async fn accept_loop_task_failure_cleans_socket_and_maps_to_system_exit() {
    let (_dir, socket) = occupied_socket_path();
    let error = API
        .finish_daemon_terminal_fixture(socket.clone(), DaemonTerminalFixture::AcceptLoopPanic)
        .await
        .expect_err("accept-loop task failure must leave the daemon as an error");

    assert!(
        !socket.exists(),
        "join failure must not bypass daemon socket cleanup"
    );
    assert!(
        error.to_string().contains("accept loop task failed"),
        "typed task failure must remain visible: {error:#}"
    );
    assert_eq!(
        API.cli_error_exit_code(&error),
        keyhog::exit_codes::EXIT_SYSTEM_ERROR
    );
}

#[tokio::test]
async fn requested_clean_shutdown_cleans_socket_and_remains_success() {
    let (_dir, socket) = occupied_socket_path();
    API.finish_daemon_terminal_fixture(socket.clone(), DaemonTerminalFixture::CleanShutdown)
        .await
        .expect("requested clean shutdown succeeds");

    assert!(
        !socket.exists(),
        "clean shutdown must remove the daemon socket"
    );
    assert_eq!(keyhog::exit_codes::EXIT_SUCCESS, 0);
}
