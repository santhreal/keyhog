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

#[test]
fn daemon_frame_read_path_does_not_eager_allocate_announced_len() {
    let source = include_str!("../src/daemon/frame.rs");
    assert!(
        !source.contains("vec![0u8; len as usize]"),
        "read_frame must not allocate MAX_FRAME_BYTES before the peer sends the body"
    );
    assert!(
        source.contains("reader.take(u64::from(len))"),
        "read_frame should cap reads with AsyncReadExt::take"
    );
    assert!(
        source.contains("body.len() != expected_len"),
        "read_frame must reject short reads after incremental buffering"
    );
}
