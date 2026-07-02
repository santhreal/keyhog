//! Regression: pin the byte-exact stability contract of the credential hashing
//! primitive that the whole workspace shares — `keyhog_core::sha256_hash` and
//! the `CredentialHash` domain type it produces.
//!
//! WHY THIS MATTERS: `credential_hash` is a durable cross-report identity. It
//! drives `.keyhogignore` `hash:` suppression, report-scope dedup grouping, and
//! SARIF partial fingerprints. If the digest of a fixed credential ever drifts
//! (endianness change, `.as_bytes()` vs a char iterator, an accidental
//! normalization step), every previously-authored suppression silently stops
//! matching and dedup fragments. So this file pins the EXACT 64-hex SHA-256 of
//! several fixed inputs against digests computed INDEPENDENTLY (GNU
//! `sha256sum` / Python `hashlib`), never against `sha256_hash`'s own output.
//!
//! TEST-TRUTH: every assertion is a concrete value — an exact 64-char hex
//! string, an exact bool, an exact length, or an exact byte array. No
//! `is_empty()` / `is_some()` / `len() > 0`-only checks.
//!
//! HOST-INDEPENDENCE: SHA-256 is a pure scalar computation with no accelerator
//! path, so these assertions hold identically on every host.

use keyhog_core::{hex_encode, sha256_hash, CredentialHash};

// Independently-computed reference digests. Each was produced OUTSIDE this
// crate: `printf '<input>' | sha256sum` (GNU coreutils) and, for the 1000-byte
// case, `hashlib.sha256(('x'*1000).encode()).hexdigest()`.
const SHA256_AWS_EXAMPLE: &str = "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3";
const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_LOWER_A: &str = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb";
const SHA256_UPPER_A: &str = "559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd";
const SHA256_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
const SHA256_CAFE: &str = "850f7dc43910ff890f8879c0ed26fe697c93a067ad93a7d50f466a7028a9bf4e";
const SHA256_1000_X: &str = "44f8354494a5ba03ba1792a8d3e9c534c47a9181980fde7a3f44b06ef2ae7c7f";
const SHA256_CONTROL_BYTES: &str =
    "ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc";
const SHA256_PASSWORD123: &str = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f";

/// Positive: a fixed real-shaped AWS access-key example hashes to its exact,
/// independently-computed SHA-256 digest.
#[test]
fn aws_example_hashes_to_exact_digest() {
    let hash = sha256_hash("AKIAIOSFODNN7EXAMPLE");
    assert_eq!(hex_encode(&hash), SHA256_AWS_EXAMPLE);
}

/// Boundary: the empty string is a valid input and hashes to the canonical
/// SHA-256 of zero bytes — and crucially that digest is NOT the all-zero
/// `ZERO` compatibility sentinel.
#[test]
fn empty_string_hashes_to_canonical_empty_digest() {
    let hash = sha256_hash("");
    assert_eq!(hex_encode(&hash), SHA256_EMPTY);
    assert!(!hash.is_zero());
    assert_ne!(hash, CredentialHash::ZERO);
}

/// The all-zero sentinel is distinct from every real digest and reports itself
/// as zero; a real digest never does.
#[test]
fn zero_sentinel_is_distinct_from_real_digest() {
    assert!(CredentialHash::ZERO.is_zero());
    assert_eq!(hex_encode(CredentialHash::ZERO.as_bytes()), "0".repeat(64));
    let hash = sha256_hash("hello");
    assert_eq!(hex_encode(&hash), SHA256_HELLO);
    assert!(!hash.is_zero());
}

/// Negative-twin: hashing is case-sensitive — "a" and "A" differ by one bit in
/// the input and produce completely different digests, each pinned exactly.
#[test]
fn hash_is_case_sensitive() {
    let lower = sha256_hash("a");
    let upper = sha256_hash("A");
    assert_eq!(hex_encode(&lower), SHA256_LOWER_A);
    assert_eq!(hex_encode(&upper), SHA256_UPPER_A);
    assert_ne!(lower, upper);
}

/// Adversarial: multibyte UTF-8 is hashed by its UTF-8 BYTES, not by code
/// points. "café" is 5 bytes (é = 2 bytes) and matches the byte-oriented
/// reference digest.
#[test]
fn multibyte_utf8_hashes_by_bytes() {
    let s = "café";
    assert_eq!(s.len(), 5); // 5 UTF-8 bytes, 4 code points
    let hash = sha256_hash(s);
    assert_eq!(hex_encode(&hash), SHA256_CAFE);
}

/// Adversarial: embedded control bytes (U+0000..U+0002) are valid str content
/// and are hashed verbatim — no truncation at the NUL.
#[test]
fn control_bytes_are_hashed_verbatim() {
    let s = "\u{0}\u{1}\u{2}";
    assert_eq!(s.len(), 3);
    let hash = sha256_hash(s);
    assert_eq!(hex_encode(&hash), SHA256_CONTROL_BYTES);
}

/// Boundary: a long (1000-byte) credential hashes correctly across SHA-256
/// block boundaries to its independently-computed digest.
#[test]
fn long_credential_hashes_across_block_boundaries() {
    let cred = "x".repeat(1000);
    let hash = sha256_hash(&cred);
    assert_eq!(hex_encode(&hash), SHA256_1000_X);
}

/// Stability: hashing the same input many times yields byte-identical digests
/// every time, all equal to the pinned reference. Guards against any hidden
/// per-call state (salt, nonce, RNG).
#[test]
fn hash_is_stable_across_repeated_runs() {
    let first = sha256_hash("password123");
    assert_eq!(hex_encode(&first), SHA256_PASSWORD123);
    for _ in 0..256 {
        let again = sha256_hash("password123");
        assert_eq!(again, first);
        assert_eq!(again.into_bytes(), first.into_bytes());
    }
}

/// Negative-twin: two credentials differing by a single trailing character
/// produce different digests (avalanche), with the base digest pinned exactly.
#[test]
fn single_char_difference_changes_digest() {
    let a = sha256_hash("password123");
    let b = sha256_hash("password124");
    assert_eq!(hex_encode(&a), SHA256_PASSWORD123);
    assert_ne!(a, b);
    assert_ne!(hex_encode(&a), hex_encode(&b));
}

/// Hex encoding is always lower-case and exactly 64 characters, drawn only from
/// [0-9a-f]. Upper-case hex would break `.keyhogignore` `hash:` matching.
#[test]
fn hex_is_lowercase_and_64_chars() {
    for input in ["AKIAIOSFODNN7EXAMPLE", "", "A", "café", "password123"] {
        let hex = hex_encode(&sha256_hash(input));
        assert_eq!(hex.len(), 64, "digest hex must be 64 chars for {input:?}");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "digest hex must be lower-case hex for {input:?}: {hex}"
        );
    }
}

/// The `Debug` impl renders the exact lower-case hex — a stable, non-leaking
/// representation that must equal `hex_encode`.
#[test]
fn debug_impl_renders_exact_hex() {
    let hash = sha256_hash("AKIAIOSFODNN7EXAMPLE");
    assert_eq!(format!("{hash:?}"), SHA256_AWS_EXAMPLE);
    assert_eq!(format!("{hash:?}"), hex_encode(&hash));
}

/// Byte round-trip: `from_bytes`/`as_bytes`/`into_bytes` are lossless and the
/// hex of the raw bytes equals the hex of the hash — the digest is exactly the
/// 32 SHA-256 output bytes with no reordering.
#[test]
fn raw_bytes_round_trip_losslessly() {
    let hash = sha256_hash("hello");
    let bytes: [u8; 32] = hash.into_bytes();
    // First byte of SHA-256("hello") is 0x2c per the reference digest.
    assert_eq!(bytes[0], 0x2c);
    assert_eq!(bytes[31], 0x24);
    let rebuilt = CredentialHash::from_bytes(bytes);
    assert_eq!(rebuilt, hash);
    assert_eq!(hex_encode(bytes), SHA256_HELLO);
    assert_eq!(hash.as_bytes(), &bytes);
}

/// Serde wire shape: a `CredentialHash` serializes to its 64-hex string (the
/// documented `.credential_hash` JSON format) and deserializes back to the same
/// value.
#[test]
fn serde_round_trips_as_hex_string() {
    let hash = sha256_hash("hello");
    let json = serde_json::to_string(&hash).expect("serialize");
    assert_eq!(json, format!("\"{SHA256_HELLO}\""));
    let back: CredentialHash = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, hash);
    assert_eq!(hex_encode(&back), SHA256_HELLO);
}

/// The two known SHA-256 test vectors for "" and "a" are distinct, non-zero,
/// and equal to their pinned references — a cross-input sanity gate that would
/// catch any global digest offset.
#[test]
fn distinct_inputs_map_to_distinct_pinned_digests() {
    let empty = sha256_hash("");
    let a = sha256_hash("a");
    assert_eq!(hex_encode(&empty), SHA256_EMPTY);
    assert_eq!(hex_encode(&a), SHA256_LOWER_A);
    assert_ne!(empty, a);
    assert!(!empty.is_zero());
    assert!(!a.is_zero());
}
