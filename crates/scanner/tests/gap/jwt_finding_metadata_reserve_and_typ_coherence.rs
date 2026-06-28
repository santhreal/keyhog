//! Regression: `finding_metadata` reserves its per-finding metadata HashMap up
//! front (Law 7 — no rehash growth on the per-JWT path) and the reserve changes
//! no output (Law 6). Also pins the `logout+jwt` typ coherence: `is_standard_typ`
//! accepts it, so it must NOT be flagged as a NonStandardTyp anomaly (the doc
//! had listed only four standard typ values while the code accepts five).
//!
//! finding_metadata is the single shared bridge from the JWT analysis to a
//! finding's metadata, so pinning its exact key/value output proves the capacity
//! reserve is byte-identical (capacity is unobservable through HashMap contents).

use keyhog_scanner::jwt::finding_metadata;

// Header {"alg":"HS256","typ":"JWT"} . payload {"iss":...,"sub":...,"exp":9999999999} . sig
const HS256_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwic3ViIjoidXNlci0xMjMiLCJleHAiOjk5OTk5OTk5OTl9.AAAA";
// Header {"alg":"HS256","typ":"logout+jwt"} . payload {"sub":"s"} . sig
const LOGOUT_JWT: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6ImxvZ291dCtqd3QifQ.eyJzdWIiOiJzIn0.AAAA";
// Header {"alg":"none"} . payload {"sub":"s"} . sig
const ALGNONE_JWT: &str = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJzIn0.AAAA";

#[test]
fn finding_metadata_surfaces_exact_claims_for_real_jwt() {
    let meta = finding_metadata(HS256_JWT).expect("a structurally valid JWT yields metadata");
    assert_eq!(meta.get("jwt.alg").map(String::as_str), Some("HS256"));
    assert_eq!(
        meta.get("jwt.iss").map(String::as_str),
        Some("https://issuer.example")
    );
    assert_eq!(meta.get("jwt.sub").map(String::as_str), Some("user-123"));
    assert_eq!(meta.get("jwt.exp").map(String::as_str), Some("9999999999"));
    // HS256 is a known alg, typ=JWT is standard, exp is far future: no anomalies,
    // so exactly the four claim keys above.
    assert_eq!(meta.len(), 4, "no spurious anomaly keys for a clean HS256 JWT");
}

#[test]
fn logout_typ_is_standard_no_non_standard_anomaly() {
    let meta = finding_metadata(LOGOUT_JWT).expect("logout+jwt is a valid JWT");
    assert_eq!(meta.get("jwt.alg").map(String::as_str), Some("HS256"));
    assert_eq!(meta.get("jwt.sub").map(String::as_str), Some("s"));
    assert!(
        !meta.contains_key("jwt.non_standard_typ"),
        "logout+jwt is in the standard typ set and must not be flagged"
    );
    assert_eq!(meta.len(), 2, "only jwt.alg + jwt.sub; no anomaly keys");
}

#[test]
fn alg_none_surfaces_the_unsigned_anomaly() {
    let meta = finding_metadata(ALGNONE_JWT).expect("alg=none is a valid JWT shape");
    assert_eq!(meta.get("jwt.alg").map(String::as_str), Some("none"));
    assert_eq!(
        meta.get("jwt.alg_none").map(String::as_str),
        Some("true (unsigned token: RFC 7519 §6 risk)")
    );
    assert_eq!(meta.get("jwt.sub").map(String::as_str), Some("s"));
    assert_eq!(meta.len(), 3, "jwt.alg + jwt.sub + jwt.alg_none");
}

#[test]
fn finding_metadata_reserves_capacity_and_doc_lists_logout_typ() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/jwt.rs")).expect("jwt source readable");
    assert!(
        src.contains("HashMap::with_capacity(8)"),
        "finding_metadata must pre-reserve its per-finding map"
    );
    assert!(
        !src.contains("let mut meta = std::collections::HashMap::new();"),
        "finding_metadata must not start from a zero-capacity map"
    );
    assert!(
        src.contains("`dpop+jwt`, `logout+jwt`"),
        "the NonStandardTyp doc must list logout+jwt to match is_standard_typ"
    );
}
