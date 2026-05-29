//! GitHub code-scanning dedups alerts across runs by `partialFingerprints`.
//! Without it the same leak re-opens as a new alert every scan and fixed
//! alerts may not auto-close. keyhog keys the fingerprint on the credential
//! hash (stable across line moves / reformatting).
use keyhog_core::report::sarif_uri::credential_fingerprints;

#[test]
fn sarif_partial_fingerprints_present() {
    let fp = credential_fingerprints("01c2c0cfbc42").expect("non-empty hash yields a fingerprint");
    assert_eq!(
        fp.get("keyhog/credentialHash/v1").map(String::as_str),
        Some("01c2c0cfbc42"),
        "the credential hash must be the stable dedup key"
    );
    // An empty hash has no stable identity -> no fingerprint (omitted in SARIF).
    assert!(credential_fingerprints("").is_none());
}
