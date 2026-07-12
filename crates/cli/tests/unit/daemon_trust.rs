#![cfg(unix)]

use keyhog::testing::{CliTestApi as _, API};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

fn chmod(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn private_tempdir() -> TempDir {
    let tmp = tempfile::tempdir().unwrap();
    chmod(tmp.path(), 0o700);
    tmp
}

fn bind_private_std_socket(path: &Path) -> std::os::unix::net::UnixListener {
    let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
    chmod(path, 0o600);
    listener
}

#[test]
fn daemon_socket_parent_is_created_0700() {
    let tmp = private_tempdir();
    let dir = tmp.path().join("keyhog");

    API.ensure_private_socket_dir(&dir).unwrap();

    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn daemon_socket_parent_existing_loose_dir_is_tightened() {
    let tmp = private_tempdir();
    let dir = tmp.path().join("keyhog");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o755);

    API.ensure_private_socket_dir(&dir).unwrap();

    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn daemon_socket_parent_refuses_intermediate_symlink() {
    let tmp = private_tempdir();
    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let redirected_parent = link.join("nested");

    let err = API
        .ensure_private_socket_dir(&redirected_parent)
        .expect_err("symlinked parent component must be refused");
    let msg = format!("{err:#}");
    assert!(msg.contains("symlink"), "{msg}");
    assert!(msg.contains("link"), "{msg}");
    assert!(
        !real.join("nested").exists(),
        "symlink refusal must happen before create_dir_all writes through the redirect"
    );
}

#[test]
fn daemon_stale_socket_cleanup_removes_only_trusted_socket() {
    let tmp = private_tempdir();
    let socket = tmp.path().join("server.sock");
    {
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        chmod(&socket, 0o600);
    }

    API.remove_stale_socket_if_trusted(&socket).unwrap();

    assert!(!socket.exists());
}

#[test]
fn daemon_stale_socket_cleanup_refuses_regular_file() {
    let tmp = private_tempdir();
    let socket = tmp.path().join("server.sock");
    std::fs::write(&socket, b"not a socket").unwrap();
    chmod(&socket, 0o600);

    let err = API
        .remove_stale_socket_if_trusted(&socket)
        .expect_err("regular file at daemon socket path must be refused");
    let msg = format!("{err:#}");
    assert!(msg.contains("not a Unix socket"), "{msg}");
    assert!(
        msg.contains("daemon:"),
        "shared trust validator must use server-safe daemon wording: {msg}"
    );
    assert!(
        !msg.contains("daemon client:") && !msg.contains("send scan paths"),
        "server-side stale-socket cleanup must not report client-only framing: {msg}"
    );
    assert!(
        socket.exists(),
        "refused non-socket path must not be removed"
    );
}

#[test]
fn daemon_client_accepts_private_socket_file() {
    let tmp = private_tempdir();
    let socket = tmp.path().join("server.sock");
    let _listener = bind_private_std_socket(&socket);

    API.validate_socket_for_connect(&socket).unwrap();
}

#[test]
fn daemon_client_refuses_group_accessible_socket_file() {
    let tmp = private_tempdir();
    let socket = tmp.path().join("server.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    chmod(&socket, 0o660);

    let err = API
        .validate_socket_for_connect(&socket)
        .expect_err("group-accessible daemon socket must be refused");
    let msg = format!("{err:#}");
    assert!(msg.contains("expected 0o600"), "{msg}");
    assert!(
        msg.contains("refusing to trust"),
        "shared trust validator must describe the trust failure: {msg}"
    );
    assert!(
        !msg.contains("send scan paths"),
        "shared trust validator must not bake client-only consequences into socket-file errors: {msg}"
    );
}

#[test]
fn daemon_client_refuses_regular_file_socket_path() {
    let tmp = private_tempdir();
    let socket = tmp.path().join("server.sock");
    std::fs::write(&socket, b"not a socket").unwrap();
    chmod(&socket, 0o600);

    let err = API
        .validate_socket_for_connect(&socket)
        .expect_err("regular file must not be treated as daemon socket");
    let msg = format!("{err:#}");
    assert!(msg.contains("not a Unix socket"), "{msg}");
    assert!(
        msg.contains("daemon:") && !msg.contains("daemon client:"),
        "socket-file validation wording must remain context-neutral: {msg}"
    );
}

#[test]
fn daemon_client_refuses_symlink_socket_path() {
    let tmp = private_tempdir();
    let real_socket = tmp.path().join("real.sock");
    let _listener = bind_private_std_socket(&real_socket);
    let link = tmp.path().join("server.sock");
    std::os::unix::fs::symlink(&real_socket, &link).unwrap();

    let err = API
        .validate_socket_for_connect(&link)
        .expect_err("symlinked daemon socket path must be refused");
    let msg = format!("{err:#}");
    assert!(msg.contains("symlink"), "{msg}");
    assert!(
        msg.contains("refusing to trust") && !msg.contains("send scan paths"),
        "socket symlink refusal must be usable from both client and server paths: {msg}"
    );
}

#[tokio::test]
async fn daemon_client_reads_kernel_peer_uid() {
    let tmp = private_tempdir();
    let socket = tmp.path().join("server.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    chmod(&socket, 0o600);

    let client_connect = tokio::net::UnixStream::connect(&socket);
    let accept = listener.accept();
    let (client_stream, accepted) = tokio::join!(client_connect, accept);
    let client_stream = client_stream.unwrap();
    let (server_stream, _) = accepted.unwrap();

    let current_uid = API.current_uid();
    assert_eq!(API.connected_peer_uid(&client_stream).unwrap(), current_uid);
    assert_eq!(API.connected_peer_uid(&server_stream).unwrap(), current_uid);
}

#[tokio::test]
async fn daemon_server_accepts_same_uid_peer() {
    let tmp = private_tempdir();
    let socket = tmp.path().join("server.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    chmod(&socket, 0o600);

    let client_connect = tokio::net::UnixStream::connect(&socket);
    let accept = listener.accept();
    let (client_stream, accepted) = tokio::join!(client_connect, accept);
    let _client_stream = client_stream.unwrap();
    let (server_stream, _) = accepted.unwrap();

    // The daemon runs `verify_accepted_peer` on every accepted connection before
    // reading a request; a same-uid peer (the only supported client) is accepted.
    API.verify_accepted_peer(&server_stream)
        .expect("same-uid peer must be accepted by the server-side peer-cred gate");
}
