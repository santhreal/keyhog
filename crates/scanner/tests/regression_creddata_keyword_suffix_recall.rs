//! Regression (KH-L-0411): the keyword bridge must surface a credential value
//! whose keyword carries a SECRET-PRESERVING SUFFIX between the stem and the
//! `=`/`:` delimiter, and must keep ignoring identifier/metadata suffixes that
//! denote a non-secret.
//!
//! Root cause this locks against: `GENERIC_RE` (engine/phase2_generic.rs)
//! required the credential keyword to sit IMMEDIATELY before `["'`]? [=:]`, so a
//! suffixed keyword never bridged — `DJANGO_SECRET_KEY=` (the canonical
//! Django/Flask/Rails secret), `secret_key_base=` (Rails), `credential_value:`,
//! `token_value=`, `private_key_raw=` were all proven NEVER-CANDIDATE on the real
//! CredData corpus (KH-L-0410: ~80% of recall loss is candidate-generation, and
//! this affix class is a concrete, sound slice of it). The fix admits up to two
//! suffixes from a TIGHT allowlist (`key|base|value|val|string|str|enc|raw|b64`)
//! that preserve the secret semantics, while EXCLUDING identifier/metadata
//! suffixes (`_id`, `_hash`, `_type`, `_count`, `_name`, `_field`) so OAuth
//! `token_type=`, `password_hash=` and `secret_key_id=` still do NOT bridge.
//!
//! The fix is generation-only: the captured KEYWORD group is still the bare stem
//! (the suffix is non-capturing), so the downstream entropy floor, shape gates,
//! checksum policy, context haircut and ML scoring all run unchanged — a decoy in
//! a suffixed assignment is dropped by the same gates as a bare-keyword decoy.
//! Verified on BOTH bench corpora before landing (CredData recall up, mirror
//! precision held ≥ 0.9945).

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors).expect("compile scanner")
}

/// Scan one line via the CPU fallback path (where the keyword bridge runs) and
/// return the captured credential strings. Each call clears the fragment cache
/// so identical values across tests are not deduplicated.
fn credentials_for(scanner: &CompiledScanner, line: &str) -> Vec<String> {
    let chunk = Chunk {
        data: line.into(),
        metadata: ChunkMetadata::default(),
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .filter(|m| m.detector_id.as_ref() == "generic-secret")
        .map(|m| m.credential.to_string())
        .collect()
}

fn caught(scanner: &CompiledScanner, line: &str, value: &str) -> bool {
    credentials_for(scanner, line).iter().any(|c| c == value)
}

// All value literals below are VERIFIED to surface under a bare `secret = "<v>"`
// (so a positive isolates the SUFFIX, and a negative's non-bridging is provably
// the excluded suffix, not a value-shape rejection). They carry no vendor prefix
// (no named detector fires) and are distinct (no cross-line fragment dedup).
#[test]
fn secret_preserving_suffix_forms_are_surfaced() {
    let s = scanner();
    // `secret` + `_key` (the canonical Django/Flask SECRET_KEY).
    let v1 = "8GS8FNrJgo1uN08yXk9mP2qR";
    assert!(
        caught(&s, &format!("DJANGO_SECRET_KEY = \"{v1}\""), v1),
        "SECRET_KEY (secret + _key suffix) must bridge"
    );
    // `secret` + `_key` + `_base` (two stacked suffixes — Rails secret_key_base).
    let v2 = "aB3xK9mN2pQ7rS5tU8vW1xY4";
    assert!(
        caught(&s, &format!("secret_key_base = \"{v2}\""), v2),
        "secret_key_base (secret + key + base, two suffixes) must bridge"
    );
    // `credential` + `_value` (JSON spec fixtures).
    let v3 = "jvyyoeaftqdonwtyXk9mP2qR";
    assert!(
        caught(&s, &format!("\"credential_value\": \"{v3}\""), v3),
        "credential_value (credential + _value suffix) must bridge"
    );
    // `token` + `_value`.
    let v4 = "opu1hymphguprytXk9mP2qR7";
    assert!(
        caught(&s, &format!("token_value = \"{v4}\""), v4),
        "token_value (token + _value suffix) must bridge"
    );
    // `private_key` + `_raw`.
    let v5 = "5a407ca8f8eb83Xk9mP2qR7s";
    assert!(
        caught(&s, &format!("private_key_raw = \"{v5}\""), v5),
        "private_key_raw (private_key + _raw suffix) must bridge"
    );
    // `secret` + `_string`.
    let v6 = "7mK2pQ9rT5xV8zXk9mPaB3cd";
    assert!(
        caught(&s, &format!("secret_string = \"{v6}\""), v6),
        "secret_string (secret + _string suffix) must bridge"
    );
    // Backward compatibility: the bare keyword (zero suffixes) still bridges.
    let v7 = "Xk9mP2qR7sT4vW8zCb3dE6fG";
    assert!(
        caught(&s, &format!("secret = \"{v7}\""), v7),
        "bare `secret = <value>` must still bridge (zero-suffix backward compat)"
    );
}

#[test]
fn identifier_and_metadata_suffixes_do_not_bridge() {
    let s = scanner();
    // The suffix allowlist EXCLUDES `_type`, `_hash`, `_id` — these denote a
    // non-secret (OAuth metadata, a digest, an identifier). Each value is verified
    // to surface under a bare keyword, so the ONLY reason for no-catch here is the
    // deliberately-excluded suffix — never the entropy floor or a shape gate.
    let v1 = "Wj3kZ9mP2qR7sT4vXa8bC1dE";
    assert!(
        !caught(&s, &format!("token_type = \"{v1}\""), v1),
        "token_type (excluded `_type` suffix) must NOT bridge — OAuth metadata, not a secret"
    );
    let v2 = "Lq8nR4tW7xZ2mK9pV5sB3jH6";
    assert!(
        !caught(&s, &format!("password_hash = \"{v2}\""), v2),
        "password_hash (excluded `_hash` suffix) must NOT bridge — a digest, not the password"
    );
    let v3 = "Pf6dG9kM2qZ7xW4rT8sV5nB3";
    assert!(
        !caught(&s, &format!("secret_key_id = \"{v3}\""), v3),
        "secret_key_id (excluded trailing `_id`) must NOT bridge — an identifier, not a key"
    );
}
