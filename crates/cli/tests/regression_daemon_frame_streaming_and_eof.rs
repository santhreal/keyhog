//! Contract for the daemon length-prefixed frame codec (`cli/daemon/frame.rs`),
//! complementing `unit/daemon_wire.rs` (Hello/ScanText roundtrip + oversized-cap
//! rejection) and `regression_daemon_frame_incremental_read.rs` (truncated-EOF
//! *errors*). Those pin the happy path and the two EOF-error halves; this pins
//! the gaps that were previously uncovered:
//!
//!   * the OTHER half of the EOF contract — a peer that closes cleanly *between*
//!     frames (empty buffer at EOF) must yield `Ok(None)`, NOT an error and NOT a
//!     spurious frame (`decode_body`'s `if eof && !src.is_empty()` guard);
//!   * every remaining `Request` variant (ScanPath / Health / Shutdown) and the
//!     `Health` / `Error` `Response` variants survive a serialize→frame→parse
//!     roundtrip (only Hello + ScanText were exercised);
//!   * a valid length prefix followed by a NON-JSON body fails closed as a parse
//!     error (never a silent empty frame), and a zero-length frame is likewise a
//!     parse error rather than a phantom success;
//!   * the POSITIVE incremental-assembly path — a body delivered one byte at a
//!     time must reassemble into the exact frame. The existing incremental test
//!     only proves the decoder *errors* on a truncated body at EOF; this proves
//!     it *succeeds* when the bytes eventually all arrive ("grow only as bytes
//!     arrive", frame.rs:6-7), the behavior the DoS-bounding buffer depends on.
//!
//! All assertions drive the real `pub` async frame API over an in-memory duplex
//! — the production read/write path, not a facade.

use keyhog::daemon::frame;
use keyhog::daemon::protocol::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Capture the exact on-wire bytes a `Request` frames to, by writing it into one
/// end of a duplex and draining the other to EOF. Used to build byte-precise
/// adversarial and incremental inputs without re-deriving the frame layout.
async fn wire_bytes_for(request: &Request) -> Vec<u8> {
    let (mut w, mut r) = tokio::io::duplex(1 << 20);
    frame::write_request(&mut w, request)
        .await
        .expect("write request into capture duplex");
    drop(w);
    let mut wire = Vec::new();
    r.read_to_end(&mut wire).await.expect("drain framed bytes");
    wire
}

#[tokio::test]
async fn clean_eof_between_frames_returns_none_not_an_error() {
    // A peer that closes with NO partial frame in flight is a clean close, not a
    // truncation: the read must return Ok(None), distinct from the mid-frame EOF
    // errors that the sibling regression test pins.
    let (client, mut server) = tokio::io::duplex(64);
    drop(client); // close with an empty buffer
    let result = frame::read_request(&mut server).await;
    assert!(
        matches!(result, Ok(None)),
        "an empty clean EOF must be Ok(None), got {result:?}"
    );
}

#[tokio::test]
async fn scan_path_request_roundtrips() {
    let (mut client, mut server) = tokio::io::duplex(64 * 1024);
    let sent = Request::ScanPath {
        path: "src/main.rs".into(),
        working_dir: Some("/tmp/project".into()),
    };
    frame::write_request(&mut client, &sent)
        .await
        .expect("write ScanPath");
    let got = frame::read_request(&mut server)
        .await
        .expect("read ScanPath")
        .expect("a frame");
    match got {
        Request::ScanPath { path, working_dir } => {
            assert_eq!(path, "src/main.rs");
            assert_eq!(working_dir.as_deref(), Some("/tmp/project"));
        }
        other => panic!("expected ScanPath, got {other:?}"),
    }
}

#[tokio::test]
async fn health_and_shutdown_unit_requests_roundtrip() {
    // Two separate single-frame streams: each `read_request` builds a fresh
    // reader, so one frame per stream avoids any buffered-read interference.
    for sent in [Request::Health, Request::Shutdown] {
        let (mut client, mut server) = tokio::io::duplex(1024);
        frame::write_request(&mut client, &sent)
            .await
            .expect("write unit request");
        let got = frame::read_request(&mut server)
            .await
            .expect("read unit request")
            .expect("a frame");
        match (&sent, &got) {
            (Request::Health, Request::Health) | (Request::Shutdown, Request::Shutdown) => {}
            _ => panic!("unit request did not roundtrip: sent {sent:?}, got {got:?}"),
        }
    }
}

#[tokio::test]
async fn health_response_roundtrips() {
    let (mut server, mut client) = tokio::io::duplex(64 * 1024);
    frame::write_response(
        &mut server,
        &Response::Health {
            uptime_secs: 42,
            scans_served: 7,
            active_scans: 3,
            detector_count: 900,
        },
    )
    .await
    .expect("write Health response");
    let got = frame::read_response(&mut client)
        .await
        .expect("read Health response")
        .expect("a frame");
    match got {
        Response::Health {
            uptime_secs,
            scans_served,
            active_scans,
            detector_count,
        } => {
            assert_eq!(uptime_secs, 42);
            assert_eq!(scans_served, 7);
            assert_eq!(active_scans, 3);
            assert_eq!(detector_count, 900);
        }
        other => panic!("expected Health response, got {other:?}"),
    }
}

#[tokio::test]
async fn error_response_roundtrips_carrying_its_message() {
    let (mut server, mut client) = tokio::io::duplex(64 * 1024);
    frame::write_response(
        &mut server,
        &Response::Error {
            message: "scanner refused: path outside working_dir".into(),
        },
    )
    .await
    .expect("write Error response");
    let got = frame::read_response(&mut client)
        .await
        .expect("read Error response")
        .expect("a frame");
    match got {
        Response::Error { message } => {
            assert_eq!(message, "scanner refused: path outside working_dir");
        }
        other => panic!("expected Error response, got {other:?}"),
    }
}

#[tokio::test]
async fn a_valid_prefix_with_a_non_json_body_fails_closed_as_a_parse_error() {
    // Length prefix says 5 bytes; the body is `hello`, not JSON. The decoder must
    // surface a parse error naming the byte count — never treat garbage as a
    // silent empty frame (Law 10: fail closed, not a quiet fallback).
    let (mut client, mut server) = tokio::io::duplex(64);
    let body = b"hello";
    client
        .write_all(&(body.len() as u32).to_be_bytes())
        .await
        .expect("write length prefix");
    client.write_all(body).await.expect("write non-JSON body");
    drop(client);
    let err = frame::read_request(&mut server)
        .await
        .expect_err("non-JSON body must be a parse error, not a frame");
    let message = err.to_string();
    assert!(
        message.contains("parse request") && message.contains("5 bytes"),
        "parse error must name the operation and byte count; got {message}"
    );
}

#[tokio::test]
async fn a_zero_length_frame_is_a_parse_error_not_a_phantom_success() {
    // len=0 decodes to an empty body; an empty slice is not valid JSON, so the
    // frame must fail to parse rather than yield a bogus default Request.
    let (mut client, mut server) = tokio::io::duplex(64);
    client
        .write_all(&0u32.to_be_bytes())
        .await
        .expect("write zero length prefix");
    drop(client);
    let err = frame::read_request(&mut server)
        .await
        .expect_err("a zero-length body must not parse to a Request");
    assert!(
        err.to_string().contains("parse request"),
        "empty body must surface a parse error; got {err}"
    );
}

#[tokio::test]
async fn a_body_delivered_one_byte_at_a_time_reassembles_into_the_exact_frame() {
    // The positive of "grow only as bytes arrive": the decoder must buffer a
    // trickled body and decode exactly once the final byte lands — never decode
    // early on a partial body, never lose bytes across polls.
    let sent = Request::ScanText {
        path: Some("trickle.txt".into()),
        text: "a slowly delivered scan body".into(),
    };
    let wire = wire_bytes_for(&sent).await;
    assert!(
        wire.len() > 4,
        "frame must have a length prefix plus a body"
    );

    let (mut writer, mut reader) = tokio::io::duplex(64 * 1024);
    let feed = tokio::spawn(async move {
        // Prefix first, then the body one byte at a time, yielding between each so
        // the reader is polled on partial input and must accumulate rather than
        // decode prematurely.
        writer
            .write_all(&wire[..4])
            .await
            .expect("write length prefix");
        for byte in &wire[4..] {
            tokio::task::yield_now().await;
            writer
                .write_all(std::slice::from_ref(byte))
                .await
                .expect("write body byte");
        }
        // Hold the writer open until the frame is fully sent; drop implicitly here.
    });

    let got = frame::read_request(&mut reader)
        .await
        .expect("read trickled request")
        .expect("a fully reassembled frame");
    feed.await.expect("feeder task");
    match got {
        Request::ScanText { path, text } => {
            assert_eq!(path.as_deref(), Some("trickle.txt"));
            assert_eq!(text, "a slowly delivered scan body");
        }
        other => panic!("trickled frame did not reassemble to the original: {other:?}"),
    }
}
