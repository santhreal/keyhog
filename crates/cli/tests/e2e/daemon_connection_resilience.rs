//! E2E: one abusive or abandoned client must not degrade the shared daemon.
//!
//! The daemon is a long-lived process that serialises scan execution, so every
//! per-connection failure mode is a shared-fate question. These tests drive the
//! real binary over a real Unix socket and speak the wire by hand, because the
//! failures they defend against are all outside the typed client's happy path.
//!
//! WHY these exist: `main::reset_sigpipe` sets `SIGPIPE` to `SIG_DFL` process
//! wide so `keyhog scan | head` exits like a normal filter. The daemon inherited
//! that, so a client which abandoned a connection while the daemon was writing
//! the reply killed the whole daemon with signal 13. The trigger is the most
//! ordinary thing a client does: Ctrl-C, a timeout, or a partial read. One
//! careless client therefore terminated every other client's warm scanner, with
//! no diagnostic and a stale socket file left behind.

#![cfg(unix)]

use crate::e2e::support::{binary, DaemonGuard};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// One AWS session-key line with a high-entropy body, so every line is a real
/// finding rather than a placeholder the scanner suppresses. Deterministic, so
/// the fixture and therefore the response size are reproducible. The `ASIA`
/// prefix is split so this file is not itself a finding on the dogfood lane.
fn secret_line(index: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNPQRSTUVWXYZ23456789";
    let mut state = (index as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xD1B5_4A32_D192_ED03);
    let mut body = String::with_capacity(16);
    for _ in 0..16 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let pick = (state >> 33) as usize % ALPHABET.len();
        body.push(char::from(ALPHABET[pick]));
    }
    format!(
        "AWS_ACCESS_KEY_ID_{index} = \"{}{body}\"\n",
        concat!("ASI", "A")
    )
}

/// A file whose scan result exceeds a Unix socket send buffer (about 208 KiB on
/// Linux, roughly 1 KiB per raw match), so the daemon is guaranteed to still be
/// mid-write when a client walks away. `findings` trades response size against
/// scan duration: tests that must finish inside the daemon's shutdown grace
/// period ask for fewer.
fn many_secrets_file(dir: &Path, findings: usize) -> std::path::PathBuf {
    let path = dir.join(".env.many-secrets");
    let mut body = String::new();
    for index in 0..findings {
        body.push_str(&secret_line(index));
    }
    std::fs::write(&path, body).expect("write many-secrets fixture");
    path
}

/// Comfortably past the socket buffer, for tests that only need a response too
/// large to be absorbed by the kernel.
const OVERSIZED_RESPONSE_FINDINGS: usize = 2000;
/// Past the socket buffer but small enough that a debug-profile scan finishes
/// well inside the daemon's shutdown drain grace period.
const DRAINABLE_RESPONSE_FINDINGS: usize = 400;

fn connect(socket: &Path) -> UnixStream {
    let stream = UnixStream::connect(socket).expect("connect to daemon socket");
    stream
        // Generous: a debug-profile daemon scanning thousands of findings on a
        // loaded host is slow, and a timeout here would read as a hang.
        .set_read_timeout(Some(Duration::from_secs(600)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .expect("set write timeout");
    stream
}

fn send(stream: &mut UnixStream, request: &serde_json::Value) {
    let body = serde_json::to_vec(request).expect("encode request");
    let length = u32::try_from(body.len()).expect("request fits the length prefix");
    stream
        .write_all(&length.to_be_bytes())
        .expect("write frame length");
    stream.write_all(&body).expect("write frame body");
    stream.flush().expect("flush frame");
}

fn read_exact(stream: &mut UnixStream, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).expect("read exact");
    buf
}

fn recv(stream: &mut UnixStream) -> serde_json::Value {
    let header = read_exact(stream, 4);
    let len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    serde_json::from_slice(&read_exact(stream, len)).expect("parse response")
}

/// Announced body length of the next frame, without consuming the body.
fn recv_announced_len(stream: &mut UnixStream) -> usize {
    let header = read_exact(stream, 4);
    u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize
}

fn hello(socket: &Path) -> UnixStream {
    let mut stream = connect(socket);
    send(&mut stream, &serde_json::json!({ "op": "hello" }));
    let reply = recv(&mut stream);
    assert_eq!(
        reply["kind"], "hello",
        "handshake must return a hello frame, got {reply}"
    );
    stream
}

fn kind_of(response: &serde_json::Value) -> &str {
    response["kind"].as_str().unwrap_or("<absent>")
}

/// The daemon is serving if a fresh connection completes a handshake and a
/// `health` round trip. This is the liveness assertion every test below ends on.
fn assert_still_serving(daemon: &mut DaemonGuard, what: &str) {
    assert!(
        daemon.exited().is_none(),
        "{what}: the daemon process must still be running, but it exited with {:?}",
        daemon.exited()
    );
    let socket = daemon.socket();
    let mut stream = hello(&socket);
    send(&mut stream, &serde_json::json!({ "op": "health" }));
    let health = recv(&mut stream);
    assert_eq!(
        kind_of(&health),
        "health",
        "{what}: the daemon must still answer health, got {health}"
    );
}

fn scan_path_request(path: &Path) -> serde_json::Value {
    serde_json::json!({
        "op": "scan_path",
        "path": path.to_str().expect("utf-8 path"),
        "working_dir": serde_json::Value::Null,
        "dogfood": false,
        "profile": false,
    })
}

/// WHY: this is the exact shape that killed the daemon. The response is multiple
/// megabytes, so it cannot fit the socket buffer; reading only its length prefix
/// and closing leaves the daemon mid-`write(2)` on a dead peer.
#[test]
fn abandoning_a_large_response_leaves_the_daemon_serving() {
    let mut daemon = DaemonGuard::start_cpu();
    let socket = daemon.socket();
    let fixture_dir = tempfile::TempDir::new().expect("fixture dir");
    let target = many_secrets_file(fixture_dir.path(), OVERSIZED_RESPONSE_FINDINGS);

    let mut victim = hello(&socket);
    send(&mut victim, &scan_path_request(&target));
    let announced = recv_announced_len(&mut victim);
    assert!(
        announced > 256 * 1024,
        "fixture must produce a response larger than a socket buffer, got {announced} bytes"
    );
    // Read a token slice, then vanish while the rest is still queued.
    let mut sip = [0u8; 1024];
    victim.read_exact(&mut sip).expect("read part of the reply");
    drop(victim);

    assert_still_serving(&mut daemon, "abandoned large response");
}

/// WHY: closing before reading anything is what a Ctrl-C'd or timed-out client
/// does. The daemon must treat the resulting `EPIPE` as one dead connection.
#[test]
fn closing_without_reading_the_reply_leaves_the_daemon_serving() {
    let mut daemon = DaemonGuard::start_cpu();
    let socket = daemon.socket();
    let fixture_dir = tempfile::TempDir::new().expect("fixture dir");
    let target = many_secrets_file(fixture_dir.path(), OVERSIZED_RESPONSE_FINDINGS);

    for _ in 0..3 {
        let mut victim = hello(&socket);
        send(&mut victim, &scan_path_request(&target));
        drop(victim);
    }

    assert_still_serving(&mut daemon, "closed without reading");
}

/// WHY: the disconnect can land while the scan itself is running, before any
/// byte of the reply exists. The scan completes on an uncancellable blocking
/// worker, so the write failure happens later, on a socket that is already gone.
#[test]
fn abandoning_a_connection_during_the_scan_leaves_the_daemon_serving() {
    let mut daemon = DaemonGuard::start_cpu();
    let socket = daemon.socket();
    let fixture_dir = tempfile::TempDir::new().expect("fixture dir");
    let target = many_secrets_file(fixture_dir.path(), OVERSIZED_RESPONSE_FINDINGS);

    let mut victim = hello(&socket);
    send(&mut victim, &scan_path_request(&target));
    // No read at all: drop while the blocking scan is still in flight.
    drop(victim);

    assert_still_serving(&mut daemon, "abandoned during scan");
}

/// WHY: shared fate is the whole point. One client abandoning its connection
/// must not cost a concurrent client its results.
#[test]
fn one_abandoning_client_does_not_break_a_concurrent_client() {
    let mut daemon = DaemonGuard::start_cpu();
    let socket = daemon.socket();
    let fixture_dir = tempfile::TempDir::new().expect("fixture dir");
    let big = many_secrets_file(fixture_dir.path(), OVERSIZED_RESPONSE_FINDINGS);
    let small = fixture_dir.path().join(".env.small");
    std::fs::write(&small, secret_line(4242)).expect("write small fixture");

    let mut survivor = hello(&socket);
    let mut abandoner = hello(&socket);

    send(&mut abandoner, &scan_path_request(&big));
    let announced = recv_announced_len(&mut abandoner);
    assert!(announced > 0, "the abandoned request must have a reply");
    drop(abandoner);

    send(&mut survivor, &scan_path_request(&small));
    let reply = recv(&mut survivor);
    assert_eq!(
        kind_of(&reply),
        "scan_results",
        "the surviving client must still get its results, got {reply}"
    );

    assert_still_serving(&mut daemon, "concurrent client");
}

/// WHY: `ScanPath` is documented as a regular-file request and the client checks
/// that before sending, but the server used to reopen only the pathname. A
/// directory argument therefore made the daemon walk and scan an entire tree
/// while holding the fragment lease, and a FIFO or symlink swapped in after the
/// client's check was scanned in place of the file that was validated (KH-553).
#[test]
fn scan_path_refuses_anything_but_a_regular_file() {
    let mut daemon = DaemonGuard::start_cpu();
    let socket = daemon.socket();
    let fixture_dir = tempfile::TempDir::new().expect("fixture dir");
    let regular = fixture_dir.path().join(".env.real");
    std::fs::write(&regular, secret_line(7)).expect("write regular fixture");
    let directory = fixture_dir.path().join("tree");
    std::fs::create_dir(&directory).expect("create directory fixture");
    std::fs::write(directory.join(".env.inner"), secret_line(8)).expect("write inner fixture");
    let link = fixture_dir.path().join(".env.link");
    std::os::unix::fs::symlink(&regular, &link).expect("create symlink fixture");

    let mut stream = hello(&socket);
    for refused in [&directory, &link] {
        send(&mut stream, &scan_path_request(refused));
        let reply = recv(&mut stream);
        assert_eq!(
            kind_of(&reply),
            "error",
            "{} must be refused, got {reply}",
            refused.display()
        );
        let message = reply["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("regular files only"),
            "{} refusal must name the regular-file contract, got {message}",
            refused.display()
        );
    }

    // The same connection still serves the legitimate shape.
    send(&mut stream, &scan_path_request(&regular));
    let reply = recv(&mut stream);
    assert_eq!(
        kind_of(&reply),
        "scan_results",
        "a regular file must still be scanned, got {reply}"
    );

    assert_still_serving(&mut daemon, "scan_path file-type refusal");
}

/// WHY: the accept loop used to await a data-plane permit before it could hand a
/// connection to a handler, so clients holding every scan slot with half-sent
/// frames starved `Health` and `Shutdown` entirely: `daemon status` and `daemon
/// stop` timed out on the handshake and reported the live daemon as absent, and
/// there was no way left to reclaim it (KH-551).
#[test]
fn control_requests_survive_a_saturated_data_plane() {
    let mut daemon = DaemonGuard::start_cpu();
    let socket = daemon.socket();

    // Mirrors the server's data-plane sizing so the pool is provably exhausted.
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
    let scan_slots = (cores * 4).clamp(8, 256);

    let mut stalled = Vec::new();
    // Two past the data-plane pool proves it is exhausted, while leaving the
    // small reserved control pool with room for the `daemon status` below.
    for _ in 0..scan_slots + 2 {
        let mut stream = hello(&socket);
        // Announce a body and never send it: the handler stays parked in its
        // read while holding whichever admission it was granted.
        stream
            .write_all(&(64u32 * 1024 * 1024).to_be_bytes())
            .expect("announce a body");
        stream.flush().expect("flush announcement");
        stalled.push(stream);
    }

    let status = Command::new(binary())
        .env("XDG_RUNTIME_DIR", daemon.runtime_dir())
        .args(["daemon", "status"])
        .output()
        .expect("spawn daemon status");
    assert_eq!(
        status.status.code(),
        Some(0),
        "status must stay answerable with every scan slot held; stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    drop(stalled);
    assert_still_serving(&mut daemon, "saturated data plane");
}

/// WHY: the wire contract says `Shutdown` flushes in-flight scans, but the
/// daemon acknowledged immediately and left the accept loop, so a client whose
/// scan was mid-flight got a dropped socket instead of its results (KH-550).
#[test]
fn shutdown_delivers_an_in_flight_scan_before_acknowledging() {
    let daemon = DaemonGuard::start_cpu();
    let socket = daemon.socket();
    let fixture_dir = tempfile::TempDir::new().expect("fixture dir");
    let target = many_secrets_file(fixture_dir.path(), DRAINABLE_RESPONSE_FINDINGS);

    let mut scanner = hello(&socket);
    let mut prober = hello(&socket);
    let mut admin = hello(&socket);
    send(&mut scanner, &scan_path_request(&target));

    // Wait until the daemon reports the scan as active. Without this the drain
    // can start before the request is even read, and the daemon then correctly
    // refuses it as new work rather than flushing it, which tests nothing.
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        send(&mut prober, &serde_json::json!({ "op": "health" }));
        let health = recv(&mut prober);
        if health["active_scans"].as_u64().unwrap_or(0) >= 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the scan never became active, so the drain cannot be observed: {health}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Read the scan reply on its own thread. Real scanning and administering
    // clients are separate processes; a single-threaded test that waited for the
    // ack first would deadlock itself, because the multi-megabyte results frame
    // cannot fit the socket buffer and the drain is waiting for it to be read.
    let scan_reply = std::thread::spawn(move || recv(&mut scanner));

    send(&mut admin, &serde_json::json!({ "op": "shutdown" }));
    let ack = recv(&mut admin);
    assert_eq!(
        kind_of(&ack),
        "shutdown",
        "shutdown must be acknowledged, got {ack}"
    );

    let reply = scan_reply.join().expect("scan reader thread");
    // Delivery, not client-observed ordering, is the contract. Both frames are
    // in flight concurrently, so which read RETURNS first is a scheduling
    // detail; before the drain existed this connection was closed and the read
    // failed with EOF instead of returning results at all.
    assert_eq!(
        kind_of(&reply),
        "scan_results",
        "the in-flight scan must be delivered, not dropped, got {reply}"
    );
}
