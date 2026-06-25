//! Lane-10 (dogfood/robustness) regression: the daemon client must FAIL CLOSED
//! when the daemon reports a DIFFERENT keyhog version than this client.
//!
//! The staleness bug this pins: a `keyhog daemon start` left running across a
//! `keyhog update` keeps its OLD detector corpus + scan pipeline in memory.
//! The wire version can stay stable across such a release (e.g. 0.5.40 ->
//! 0.5.41, both wire v2), so the wire-version handshake alone does NOT catch
//! it — the upgraded client would route scans to the stale daemon and silently
//! get old-corpus results. `client::connect` now also gates on the keyhog
//! version; `client::connect_any_version` (used by `daemon stop`/`status`)
//! deliberately does not, so an operator can still stop/inspect a stale daemon.
//!
//! These tests stand up a real Unix-socket mock daemon that replies to `Hello`
//! with a chosen `keyhog_version`, then drive the real client against it.

#![cfg(unix)]

use keyhog::daemon::client;
use keyhog::daemon::frame;
use keyhog::daemon::protocol::{Request, Response, WIRE_VERSION};
use keyhog::testing::{CliTestApi as _, API};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixListener;

/// Spawn a one-shot mock daemon on `socket` that answers exactly one `Hello`
/// with the given wire + keyhog version, then closes. Returns once the listener
/// is bound so the client connect cannot race ahead of it.
async fn spawn_mock_daemon(socket: PathBuf, wire_version: u32, keyhog_version: String) {
    spawn_mock_daemon_response(
        socket,
        Response::Hello {
            wire_version,
            keyhog_version,
            detector_count: 902,
            uptime_secs: 1,
        },
    )
    .await;
}

/// Spawn a one-shot mock daemon that replies to the client's `Hello` with an
/// arbitrary response. Used for protocol-mismatch paths where the client must
/// not dump daemon-controlled payload fields into the operator error.
async fn spawn_mock_daemon_response(socket: PathBuf, response: Response) {
    if let Some(parent) = socket.parent() {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .expect("chmod mock daemon parent 0700");
    }
    let listener = UnixListener::bind(&socket).expect("bind mock daemon socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("chmod mock daemon socket 0600");
    tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (reader, writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut writer = BufWriter::new(writer);
            // Read the client's Hello.
            let req = frame::read_request(&mut reader).await;
            if !matches!(req, Ok(Some(Request::Hello))) {
                return;
            }
            let _ = frame::write_response(&mut writer, &response).await;
            // Keep the connection alive briefly so the client finishes reading.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
    // Give the spawned accept loop a beat to be ready.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
}

async fn spawn_stuck_handshake_daemon(socket: PathBuf) -> tokio::task::JoinHandle<()> {
    if let Some(parent) = socket.parent() {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .expect("chmod mock daemon parent 0700");
    }
    let listener = UnixListener::bind(&socket).expect("bind stuck mock daemon socket");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("chmod stuck mock daemon socket 0600");
    let handle = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            let (reader, _writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            if matches!(
                frame::read_request(&mut reader).await,
                Ok(Some(Request::Hello))
            ) {
                std::future::pending::<()>().await;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    handle
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_fails_closed_on_keyhog_version_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("stale.sock");
    // A daemon on the SAME wire version but an OLDER keyhog version: the exact
    // post-`keyhog update` staleness case.
    spawn_mock_daemon(socket.clone(), WIRE_VERSION, "0.0.1-stale".to_string()).await;

    let res = client::connect(&socket).await;
    assert!(
        res.is_err(),
        "connect must refuse a daemon running a different keyhog version"
    );
    let err = res.err().unwrap();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("version mismatch"),
        "error must name the version mismatch as the reason: {msg}"
    );
    assert!(
        msg.contains("0.0.1-stale"),
        "error must report the stale daemon's version so the operator can act: {msg}"
    );
    assert!(
        msg.contains("daemon stop") && msg.contains("daemon start"),
        "error must tell the operator how to clear the stale daemon: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_any_version_accepts_stale_daemon_so_stop_status_work() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("stale2.sock");
    spawn_mock_daemon(socket.clone(), WIRE_VERSION, "0.0.1-stale".to_string()).await;

    // `daemon stop`/`status` use this: it must succeed against a stale daemon
    // (you must be able to STOP the very daemon `connect` refuses).
    let conn = client::connect_any_version(&socket)
        .await
        .expect("connect_any_version must tolerate a keyhog-version mismatch");
    // And it must REPORT the staleness so `daemon status` can warn the operator.
    assert!(
        API.daemon_client_is_stale(&conn),
        "a daemon on a different keyhog version must be reported stale"
    );
    assert_eq!(
        API.daemon_client_version(&conn),
        "0.0.1-stale",
        "the daemon's reported version must be exposed for the status warning"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_succeeds_against_same_version_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("fresh.sock");
    // A daemon on the SAME keyhog version as this client: must connect cleanly.
    spawn_mock_daemon(
        socket.clone(),
        WIRE_VERSION,
        env!("CARGO_PKG_VERSION").to_string(),
    )
    .await;

    let conn = client::connect(&socket)
        .await
        .expect("connect must succeed when the daemon runs the same keyhog version");
    assert!(
        !API.daemon_client_is_stale(&conn),
        "a same-version daemon must NOT be reported stale"
    );
    assert_eq!(
        API.daemon_client_version(&conn),
        env!("CARGO_PKG_VERSION"),
        "connect must record the daemon's reported version"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_still_rejects_wire_version_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("badwire.sock");
    // Same keyhog version but an INCOMPATIBLE wire version: the original
    // framing guard must still fire (and take precedence over the version
    // check, since a wire-incompatible daemon cannot be framed at all).
    spawn_mock_daemon(
        socket.clone(),
        WIRE_VERSION.wrapping_add(1),
        env!("CARGO_PKG_VERSION").to_string(),
    )
    .await;

    let res = client::connect(&socket).await;
    assert!(
        res.is_err(),
        "connect must refuse an incompatible wire version"
    );
    let err = res.err().unwrap();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("wire version mismatch"),
        "wire-version mismatch must be reported distinctly: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_protocol_mismatch_does_not_dump_response_payload() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("wrong-kind.sock");
    spawn_mock_daemon_response(
        socket.clone(),
        Response::Error {
            message: "daemon-controlled plaintext payload must stay hidden".to_string(),
        },
    )
    .await;

    let res = client::connect(&socket).await;
    assert!(
        res.is_err(),
        "connect must reject a non-Hello handshake response"
    );
    let err = res.err().unwrap();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("expected Hello reply") && msg.contains("Error"),
        "protocol mismatch should name only the response kind: {msg}"
    );
    assert!(
        !msg.contains("plaintext payload") && !msg.contains("message:"),
        "daemon client must not Debug-dump daemon-controlled response fields: {msg}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_times_out_when_daemon_never_answers_hello() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("stuck-hello.sock");
    let stuck_daemon = spawn_stuck_handshake_daemon(socket.clone()).await;

    let started = Instant::now();
    let res = tokio::time::timeout(Duration::from_secs(3), client::connect(&socket))
        .await
        .expect("client::connect must return via its internal handshake timeout");
    stuck_daemon.abort();

    assert!(res.is_err(), "stuck daemon handshake must fail");
    let msg = format!("{:#}", res.err().unwrap());
    assert!(
        msg.contains("handshake timeout waiting for Hello"),
        "timeout error must name the stuck Hello handshake: {msg}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "internal handshake timeout should fire before the outer test guard"
    );
}
