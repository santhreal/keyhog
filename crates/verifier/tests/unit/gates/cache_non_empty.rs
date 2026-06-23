//! Gate `cache`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn cache_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/cache.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "cache: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "cache: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        prod.contains("use keyhog_core::{")
            && prod.contains("sha256_hash")
            && prod.contains("CredentialHash")
            && prod.contains("VerificationResult")
            && prod.contains("credential_hash: sha256_hash(credential)")
            && prod.contains("detector_id_hash: sha256_hash(detector_id)"),
        "verification cache must use core::sha256_hash for cache-key hashing"
    );
    assert!(
        !prod.contains("fn hash_credential(")
            && !prod.contains("fn cache_key_hash(")
            && !prod.contains("use sha2::{Digest, Sha256};")
            && !prod.contains("Sha256::digest(credential.as_bytes())"),
        "verification cache must not restore a verifier-local SHA-256 helper"
    );
    assert!(
        !prod.contains("detector_id: Arc<str>")
            && !prod.contains("MAX_DETECTOR_ID_BYTES")
            && !prod.contains("credential_hash: [u8; VerificationCache::HASH_BYTES]")
            && !prod.contains("detector_id_hash: [u8; VerificationCache::HASH_BYTES]")
            && !prod.contains("Arc::<str>::from(truncate_to_char_boundary("),
        "cache keys must store typed core hashes and must not allocate truncated detector-id strings"
    );
}
