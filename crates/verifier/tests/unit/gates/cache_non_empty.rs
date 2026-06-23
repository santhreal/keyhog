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
        prod.contains("use keyhog_core::{VerificationResult, sha256_hash};")
            && prod.contains("credential_hash: sha256_hash(credential)")
            && prod.contains("detector_id_hash: sha256_hash(detector_id)"),
        "verification cache must use core::sha256_hash for cache-key hashing"
    );
    assert!(
        !prod.contains("fn hash_credential(")
            && !prod.contains("use sha2::{Digest, Sha256};")
            && !prod.contains("Sha256::digest(credential.as_bytes())"),
        "verification cache must not restore a verifier-local SHA-256 helper"
    );
}
