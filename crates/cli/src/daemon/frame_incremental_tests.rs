//! Daemon frame reads must not allocate the announced length before bytes arrive.

use crate::daemon::{frame, protocol::MAX_FRAME_BYTES};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// Direct serialization must preserve the exact legacy frame bytes even when
/// the destination already contains an earlier frame. This covers append
/// boundaries and the length-prefix backpatch; response roundtrips cover the
/// typed production caller.
#[test]
fn direct_json_frame_encoding_appends_exact_legacy_bytes() {
    let value = serde_json::json!({
        "kind": "mass-result",
        "rows": [1, 2, 3],
        "escaped": "\u{0000}\n\""
    });
    let body = serde_json::to_vec(&value).expect("serialize reference body");
    let mut expected = bytes::BytesMut::from(&b"prior-frame"[..]);
    expected.extend_from_slice(&(body.len() as u32).to_be_bytes());
    expected.extend_from_slice(&body);

    let mut encoded = bytes::BytesMut::from(&b"prior-frame"[..]);
    frame::encode_json_frame_for_test(&mut encoded, &value, usize::MAX)
        .expect("encode direct JSON frame");

    assert_eq!(encoded, expected);
}

/// The production response encoder must retain the exact wire body expected by
/// existing clients while switching from a temporary `Vec` to direct framing.
#[tokio::test]
async fn direct_response_serialization_preserves_exact_wire_bytes() {
    let response = crate::daemon::protocol::Response::Error {
        message: "bounded response fixture".to_owned(),
    };
    let expected = serde_json::to_vec(&response).expect("serialize reference response");
    let (mut client, mut server) = tokio::io::duplex(1024);

    frame::write_response(&mut server, &response)
        .await
        .expect("write response");
    let announced = client.read_u32().await.expect("read frame length") as usize;
    let mut body = vec![0u8; announced];
    client.read_exact(&mut body).await.expect("read frame body");

    assert_eq!(announced, expected.len());
    assert_eq!(body, expected);
}

/// A body that crosses the cap must leave the reusable transport buffer
/// byte-for-byte unchanged. Partial JSON from a rejected response must never
/// become the prefix of the next response on the same connection.
#[test]
fn direct_json_frame_encoding_rolls_back_on_cap_error() {
    let mut encoded = bytes::BytesMut::from(&b"completed-frame"[..]);
    let before = encoded.clone();
    let error = frame::encode_json_frame_for_test(
        &mut encoded,
        &serde_json::json!({"payload": "0123456789"}),
        8,
    )
    .expect_err("oversized serialized body must fail");

    assert!(
        error.to_string().contains("exceeds 8 byte cap"),
        "cap error must name the enforced bound: {error:#}"
    );
    assert_eq!(encoded, before, "failed frame must roll back exactly");
}

/// Non-I/O serializer errors may arrive after JSON bytes were emitted. The
/// direct encoder must apply the same rollback guarantee as its cap failure
/// path instead of retaining a partial object in the reusable buffer.
#[test]
fn direct_json_frame_encoding_rolls_back_on_serializer_error() {
    struct PartiallySerialized;

    impl serde::Serialize for PartiallySerialized {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::ser::SerializeMap;

            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("written", "before-error")?;
            Err(serde::ser::Error::custom(
                "deliberate partial serializer failure",
            ))
        }
    }

    let mut encoded = bytes::BytesMut::from(&b"completed-frame"[..]);
    let before = encoded.clone();
    let error = frame::encode_json_frame_for_test(&mut encoded, &PartiallySerialized, usize::MAX)
        .expect_err("serializer failure must reject the frame");

    assert!(
        format!("{error:#}").contains("deliberate partial serializer failure"),
        "serializer error must retain its cause: {error:#}"
    );
    assert_eq!(encoded, before, "failed frame must roll back exactly");
}
