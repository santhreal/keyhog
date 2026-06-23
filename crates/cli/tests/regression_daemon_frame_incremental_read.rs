//! Daemon frame reads must not allocate the announced length before bytes arrive.

use keyhog::daemon::{frame, protocol::MAX_FRAME_BYTES};
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn daemon_frame_reports_truncated_large_body_without_full_payload() {
    let (mut client, mut server) = tokio::io::duplex(256);
    client
        .write_all(&MAX_FRAME_BYTES.to_be_bytes())
        .await
        .expect("write length prefix");
    drop(client);

    let err = frame::read_request(&mut server)
        .await
        .expect_err("announced body without bytes must fail");
    let message = err.to_string();
    assert!(
        message.contains("closed after 0 of 67108864 announced bytes"),
        "truncated large frame must report bytes actually received; got {message}"
    );
}

#[tokio::test]
async fn daemon_frame_reports_truncated_length_prefix_as_error() {
    let (mut client, mut server) = tokio::io::duplex(16);
    client
        .write_all(&[0, 0])
        .await
        .expect("write partial length prefix");
    drop(client);

    let err = frame::read_request(&mut server)
        .await
        .expect_err("partial length prefix must fail, not look like a clean close");
    let message = err.to_string();
    assert!(
        message.contains("closed after 2 of 4 length-prefix bytes"),
        "partial header must report observed prefix bytes; got {message}"
    );
}

#[test]
fn daemon_frame_read_path_does_not_eager_allocate_announced_len() {
    let source = include_str!("../src/daemon/frame.rs");
    assert!(
        !source.contains("vec![0u8; len as usize]"),
        "read_frame must not allocate MAX_FRAME_BYTES before the peer sends the body"
    );
    assert!(
        source.contains("tokio_util::codec::{Decoder, Encoder, Framed, FramedRead, FramedWrite}"),
        "daemon frame transport should be owned by tokio_util codec types"
    );
    assert!(
        source.contains("fn decode_body(")
            && source.contains("peer closed after {} of {} announced bytes"),
        "frame decoder must grow only as bytes arrive and reject short bodies at EOF"
    );
    assert!(
        !source.contains("src.reserve(full_len - src.len())"),
        "frame decoder must not reserve the announced body length before bytes arrive"
    );
    assert!(
        !source.contains("read_exact(&mut len_bytes)")
            && !source.contains("vec![0u8; len as usize]"),
        "read_frame must distinguish clean EOF from partial length-prefix EOF"
    );
    assert!(
        source.contains("if eof && !src.is_empty()") && source.contains("length-prefix bytes"),
        "frame decoder must treat only empty EOF as clean close and reject partial length prefixes"
    );
}
