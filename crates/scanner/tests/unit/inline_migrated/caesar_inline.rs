//! Migrated from src/decode/caesar.rs

use keyhog_scanner::testing::{
    caesar_shift, is_source_code_path, looks_credential_shaped, CaesarDecoder,
};

#[test]
fn rot13_round_trip() {
    let s = "AKIA64ABDEFSEWKRUMSEK1NR";
    let r13 = caesar_shift(s, 13);
    assert_eq!(caesar_shift(&r13, 13), s);
}

#[test]
fn shift_preserves_non_letters() {
    assert_eq!(caesar_shift("AB-CD_12", 1), "BC-DE_12");
}

#[test]
fn looks_credential_shaped_requires_digit_and_run() {
    assert!(looks_credential_shaped("AKIA64ABDEFSEWKR"));
    assert!(!looks_credential_shaped("HELLOWORLDFOOBAR")); // no digit
    assert!(!looks_credential_shaped("12-34-56-78-")); // no 8-alnum run
}

#[test]
fn is_source_code_path_matches_known_extensions() {
    assert!(is_source_code_path(Some("src/foo.rs")));
    assert!(is_source_code_path(Some("/abs/path/bar.py")));
    assert!(is_source_code_path(Some("RELATIVE.GO")));
    assert!(is_source_code_path(Some("docs/README.md")));
    assert!(!is_source_code_path(Some("config/secrets.env")));
    assert!(!is_source_code_path(Some("blob.bin")));
    assert!(!is_source_code_path(None));
}

#[test]
fn source_code_path_skips_caesar_decoder() {
    use keyhog_core::{Chunk, ChunkMetadata};
    // Comment in a Rust file that should never be Caesar-shifted - was the
    // source.rs:1 false positive that fired helicone-api-key in production.
    let chunk = Chunk {
        data: "//! Source trait and chunk types: pluggable input backends.".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "filesystem".into(),
            path: Some("crates/core/src/source.rs".into()),
            ..Default::default()
        },
    };
    let decoded = CaesarDecoder.decode_chunk(&chunk);
    assert!(
        decoded.is_empty(),
        "Caesar decoder must not run on .rs source files; got {} decoded variants",
        decoded.len()
    );
}

#[test]
fn decode_chunk_round_trips_aws_shaped_token() {
    use keyhog_core::{Chunk, ChunkMetadata};

    // Plaintext: AKIAQR4DEFGHIJKL2345. Caesar +1 (letters only) →
    // BLJBRS4EFGHIJKLM2345. Decoder runs all 25 non-trivial shifts;
    // shift 25 (== inverse +1) recovers the original.
    let chunk = Chunk {
        data: "k = \"BLJBRS4EFGHIJKLM2345\";".into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "test".into(),
            ..Default::default()
        },
    };
    let decoded = CaesarDecoder.decode_chunk(&chunk);
    assert!(
        decoded
            .iter()
            .any(|c| c.data.as_ref() == concat!("AK", "IAQR4DEFGHIJKL2345")),
        "Caesar decoder did not surface the round-trip plaintext among {} variants. \
         Got: {:?}",
        decoded.len(),
        decoded.iter().map(|c| c.data.clone()).collect::<Vec<_>>(),
    );
}
