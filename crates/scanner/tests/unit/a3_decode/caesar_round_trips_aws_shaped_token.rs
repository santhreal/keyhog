//! Caesar +1 ciphertext round-trips to AKIA-shaped plaintext.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::testing::decode_chunk;

#[test]
fn caesar_shift_surfaces_aws_access_key_plaintext() {
    let chunk = Chunk {
        data: "k = \"BLJBRS4EFGHIJKLM2345\";".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test".into(),
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let expected = concat!("AK", "IAQR4DEFGHIJKL2345");
    assert!(
        decoded.iter().any(|c| c.data.contains(expected)),
        "Caesar decoder did not surface round-trip plaintext among {} variants",
        decoded.len()
    );
}

#[test]
fn credential_url_line_does_not_disable_caesar_elsewhere_in_chunk() {
    let chunk = Chunk {
        data: "DATABASE_URL=postgres://user:pass@example.com/db\nrotated_token = \"BLJBRS4EFGHIJKLM2345\"\n".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "filesystem".into(),
            path: Some("mixed.env".into()),
            ..Default::default()
        },
    };
    let decoded = decode_chunk(&chunk, 2, false, None, None);
    let expected = concat!("AK", "IAQR4DEFGHIJKL2345");
    assert!(
        decoded.iter().any(|c| c.data.contains(expected)),
        "credential URL lines must only suppress Caesar candidates on that line, \
         not rotated credentials elsewhere in the same chunk. decoded={:?}",
        decoded.iter().map(|c| c.data.clone()).collect::<Vec<_>>()
    );
}
