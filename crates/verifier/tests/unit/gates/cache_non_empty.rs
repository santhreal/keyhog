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
            && prod.contains("detector_id_hash: sha256_hash(detector_id)")
            && prod.contains("companions_hash: CredentialHash::from_bytes("),
        "verification cache must hash every request-identity component"
    );
    assert!(
        !prod.contains("fn hash_credential(")
            && !prod.contains("fn cache_key_hash(")
            && !prod.contains("Sha256::digest(credential.as_bytes())"),
        "credential and detector hashing must stay on the core primitive"
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
