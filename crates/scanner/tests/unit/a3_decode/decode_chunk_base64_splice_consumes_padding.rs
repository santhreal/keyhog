//! Base64 splice must replace adjacent padding when the extractor found the
//! unpadded prefix first.

use keyhog_core::Chunk;
use keyhog_scanner::testing::decode_chunk;

#[test]
fn base64_splice_consumes_padding_from_parent() {
    for terminator in ["\n", "}", "]", "&"] {
        let text = format!(
            "{}{}{}{}",
            "apiVersion: v1\nkind: Secret\ndata:\n  token: ",
            "Slc1VUstVE1aSTItV0lDREMtVDAwN00tSUFWT1A=",
            terminator,
            "next_field: clean\n"
        );
        let chunk = Chunk {
            data: text.into(),
            metadata: Default::default(),
        };

        let decoded = decode_chunk(&chunk, 2, false, None, None);

        let expected = format!("token: JW5UK-TMZI2-WICDC-T007M-IAVOP{terminator}");
        assert!(
            decoded.iter().any(|c| c.data.contains(&expected)),
            "decoded base64 payload should replace the full padded source value before terminator {terminator:?}: {decoded:?}"
        );
        assert!(
            !decoded
                .iter()
                .any(|c| c.data.contains("JW5UK-TMZI2-WICDC-T007M-IAVOP=")),
            "base64 padding must not remain attached to decoded credentials before terminator {terminator:?}: {decoded:?}"
        );
    }
}
