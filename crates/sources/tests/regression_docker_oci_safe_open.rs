//! Re-homed from the former inline `safe_open_tests` in
//! `crates/sources/src/docker/oci.rs`: the `docker_no_inline_tests` Santh
//! folder-contract gate forbids inline `#[cfg(test)]` under `src/docker/**`.
//!
//! Pins the OCI blob-open SECURITY behaviour of `verify_oci_blob_sha256`: it
//! routes through the crate's safe opener (O_NONBLOCK + O_NOFOLLOW), so it
//! verifies a regular blob's sha256, rejects a wrong digest, and, critically 
//! REFUSES a symlink blob that a raw `File::open` would have followed. A
//! malicious OCI layout could place a symlink where a blob belongs, pointing
//! outside the layout; the no-follow open closes that. Exercised through the
//! `verify_oci_blob_sha256_ok` test accessor so the private fn stays private.
#![cfg(feature = "docker")]

use keyhog_sources::testing::{SourceTestApi, TestApi};
use sha2::{Digest, Sha256};

fn sha256_digest_string(content: &[u8]) -> String {
    let hex: String = Sha256::digest(content)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256:{hex}")
}

#[test]
fn verifies_a_regular_blob_and_rejects_a_wrong_digest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blob");
    let content = b"oci layer bytes";
    std::fs::write(&path, content).unwrap();
    // Happy path preserved through open_file_safe: a regular blob whose digest
    // matches verifies.
    assert!(TestApi.verify_oci_blob_sha256_ok(&path, &sha256_digest_string(content)));
    let wrong = format!("sha256:{}", "0".repeat(64));
    assert!(!TestApi.verify_oci_blob_sha256_ok(&path, &wrong));
}

#[cfg(unix)]
#[test]
fn refuses_a_symlink_blob_that_raw_open_would_have_followed() {
    // A malicious OCI layout could place a SYMLINK where a blob belongs, pointing
    // outside the layout. Routing through open_file_safe (O_NOFOLLOW) refuses the
    // symlink's final component; raw File::open would follow it.
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real_blob");
    let content = b"payload";
    std::fs::write(&real, content).unwrap();
    let digest = sha256_digest_string(content);
    // Direct: verifies.
    assert!(TestApi.verify_oci_blob_sha256_ok(&real, &digest));
    // Via a symlink with the SAME content/digest: refused because the symlink
    // itself is not opened, the differential from the old raw File::open (which
    // would have followed it and returned Ok).
    let link = dir.path().join("link_blob");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(
        !TestApi.verify_oci_blob_sha256_ok(&link, &digest),
        "open_file_safe must refuse to follow a symlink blob"
    );
}
