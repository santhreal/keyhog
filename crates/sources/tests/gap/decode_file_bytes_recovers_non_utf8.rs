//! Law-10 recall-parity gate for the public `decode_file_bytes` entry point.
//!
//! `keyhog watch` used to read files with `std::fs::read_to_string`, which fails
//! on the FIRST non-UTF-8 byte and silently dropped the whole file. The `keyhog
//! scan` walker reads bytes and lossily decodes (recovering secrets in files
//! with a stray non-UTF-8 byte), so the two entry points scanned DIFFERENT sets
//! — a silent recall divergence invisible to the operator. Watch now routes
//! through `keyhog_sources::decode_file_bytes`, the SAME decoder the walker uses.
//!
//! These tests pin that contract: a non-strict-UTF-8 text file with an embedded
//! secret decodes to text containing the secret (so watch will scan it), while a
//! genuine binary blob returns `None` (so watch skips it exactly like scan).

use keyhog_sources::decode_file_bytes;

#[test]
fn recovers_secret_from_non_utf8_text() {
    // A `.env`-style config whose comment carries a stray Latin-1 byte (0xE9 =
    // 'é' in ISO-8859-1, an invalid lone continuation byte in UTF-8). Strict
    // `read_to_string` would reject the entire file; the walker's lossy decode
    // keeps every other byte intact, so the AWS key on the next line survives.
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(b"# cafe\xe9 config\n");
    bytes.extend_from_slice(b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n");

    let decoded = decode_file_bytes(&bytes)
        .expect("a config with one stray non-UTF-8 byte must still decode to text");

    assert!(
        decoded.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        "the secret on the clean line must survive lossy decode so `keyhog watch` \
         scans it identically to `keyhog scan`; got: {decoded:?}"
    );
}

#[test]
fn valid_utf8_passes_through_unchanged() {
    let text = "GITHUB_TOKEN=ghp_0123456789abcdefghijABCDEFGHIJ0123456789\n";
    let decoded = decode_file_bytes(text.as_bytes()).expect("plain UTF-8 must decode");
    assert_eq!(
        decoded, text,
        "valid UTF-8 must pass through byte-for-byte (no lossy mangling)"
    );
}

#[test]
fn genuine_binary_is_skipped_not_misdecoded() {
    // An ELF header is unambiguously binary: the decoder must return None so the
    // watch daemon skips it — matching the scan walker's binary policy, NOT
    // scanning a wall of replacement characters.
    let mut bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F'];
    bytes.extend_from_slice(&[0u8; 64]);
    assert!(
        decode_file_bytes(&bytes).is_none(),
        "a binary blob must decode to None so watch skips it like scan does"
    );
}
