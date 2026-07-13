//! Dashed-serial-key + prefixed-hash-digest suppression contracts
//! (`crates/scanner/src/suppression/shape/canonical.rs`).
//!
//! Two more identifier-not-secret gates:
//!   • `looks_like_dashed_serial_key`: a product/license key in the 5×5 dash shape
//!     `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` (exactly 29 chars, alnum groups, dashes at
//!     5/11/17/23).
//!   • `looks_like_prefixed_hash_digest`: a hash-algo-LABELLED digest
//!     (`sha256:<64hex>`, `md5:<32hex>`, `sha256-<b64>`, …). The label is matched
//!     case-insensitively and as a SUBSTRING (`nginx@sha256:<hex>` counts), and the
//!     stripped body must itself be a canonical-length uniform hex or base64
//!     integrity blob (the label ALONE never suppresses).

use keyhog_scanner::testing::{
    looks_like_dashed_serial_key_for_test, looks_like_prefixed_hash_digest_for_test,
};
use proptest::prelude::*;

// ── dashed serial keys ───────────────────────────────────────────────────────

#[test]
fn canonical_5x5_serial_is_recognized() {
    assert!(looks_like_dashed_serial_key_for_test(
        "ABCDE-12345-FGHIJ-67890-KLMNO"
    ));
    assert!(looks_like_dashed_serial_key_for_test(
        "aaaaa-bbbbb-ccccc-ddddd-eeeee"
    )); // lowercase
}

#[test]
fn non_serial_shapes_are_rejected() {
    assert!(!looks_like_dashed_serial_key_for_test(
        "ABCDE-12345-FGHIJ-67890-KLMN"
    )); // 28 chars
    assert!(!looks_like_dashed_serial_key_for_test(
        "ABCD-12345-FGHIJ-67890-KLMNOX"
    )); // dash misplaced
    assert!(!looks_like_dashed_serial_key_for_test(
        "ABCDE_12345_FGHIJ_67890_KLMNO"
    )); // underscores
    assert!(!looks_like_dashed_serial_key_for_test(
        "ABCDE-1234$-FGHIJ-67890-KLMNO"
    )); // non-alnum body
    assert!(!looks_like_dashed_serial_key_for_test(""));
}

// ── prefixed hash digests ────────────────────────────────────────────────────

#[test]
fn labelled_digests_are_recognized() {
    assert!(looks_like_prefixed_hash_digest_for_test(&format!(
        "sha256:{}",
        "a".repeat(64)
    )));
    assert!(looks_like_prefixed_hash_digest_for_test(&format!(
        "md5:{}",
        "a".repeat(32)
    )));
    assert!(looks_like_prefixed_hash_digest_for_test(&format!(
        "sha1:{}",
        "a".repeat(40)
    )));
    assert!(looks_like_prefixed_hash_digest_for_test(&format!(
        "sha512:{}",
        "a".repeat(128)
    )));
    // Case-insensitive label + substring match (docker image digest form).
    assert!(looks_like_prefixed_hash_digest_for_test(&format!(
        "nginx@SHA256:{}",
        "a".repeat(64)
    )));
}

#[test]
fn wrong_label_or_body_length_is_not_a_prefixed_digest() {
    // Correct label but the body length is not a canonical digest width.
    assert!(!looks_like_prefixed_hash_digest_for_test(&format!(
        "sha256:{}",
        "a".repeat(20)
    )));
    // Unknown label.
    assert!(!looks_like_prefixed_hash_digest_for_test(&format!(
        "sha999:{}",
        "a".repeat(64)
    )));
    // A bare digest with NO label is not matched here (the label is required).
    assert!(!looks_like_prefixed_hash_digest_for_test(&"a".repeat(64)));
    assert!(!looks_like_prefixed_hash_digest_for_test(""));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A serial match IMPLIES exactly 29 bytes with dashes at 5/11/17/23, the gate
    /// can never fire on any other layout.
    #[test]
    fn serial_match_implies_5x5_layout(value in "[A-Za-z0-9-]{0,40}") {
        if looks_like_dashed_serial_key_for_test(&value) {
            let b = value.as_bytes();
            prop_assert_eq!(b.len(), 29);
            prop_assert!(b[5] == b'-' && b[11] == b'-' && b[17] == b'-' && b[23] == b'-');
        }
    }

    /// Any 5 alnum groups of 5, dash-joined, are ALWAYS a serial key.
    #[test]
    fn any_5x5_alnum_is_a_serial(
        g in prop::collection::vec("[A-Za-z0-9]{5}", 5..=5),
    ) {
        let value = g.join("-");
        prop_assert_eq!(value.len(), 29);
        prop_assert!(looks_like_dashed_serial_key_for_test(&value));
    }

    /// `sha256:<64 uniform hex>` is ALWAYS a prefixed hash digest (the dominant
    /// docker/git-LFS/pip digest form).
    #[test]
    fn sha256_labelled_hex_is_always_a_digest(hex in "[0-9a-f]{64}") {
        let value = format!("sha256:{hex}");
        prop_assert!(looks_like_prefixed_hash_digest_for_test(&value));
    }

    /// A value containing NONE of the hash-algo labels is never a prefixed digest,
    /// no matter how digest-like the body.
    #[test]
    fn no_label_never_matches(value in "[0-9a-fA-F]{0,140}") {
        // Pure hex without any `sha*:`/`md5:`/`sha*-` label.
        prop_assert!(!looks_like_prefixed_hash_digest_for_test(&value));
    }
}
