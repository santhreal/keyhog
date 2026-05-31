//! Base64 splice must replace adjacent padding when the extractor found the
//! unpadded prefix first.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn base64_splice_consumes_padding_from_parent() {
    let text = concat!(
        "apiVersion: v1\n",
        "kind: Secret\n",
        "data:\n",
        "  token: Slc1VUstVE1aSTItV0lDREMtVDAwN00tSUFWT1A=\n",
    );
    let chunk = Chunk {
        data: text.into(),
        metadata: Default::default(),
    };

    let decoded = decode_chunk(&chunk, 2, false, None, None);

    assert!(
        decoded
            .iter()
            .any(|c| c.data.contains("token: JW5UK-TMZI2-WICDC-T007M-IAVOP\n")),
        "decoded base64 payload should replace the full padded source value: {decoded:?}"
    );
    assert!(
        !decoded
            .iter()
            .any(|c| c.data.contains("JW5UK-TMZI2-WICDC-T007M-IAVOP=")),
        "base64 padding must not remain attached to decoded credentials: {decoded:?}"
    );
}
