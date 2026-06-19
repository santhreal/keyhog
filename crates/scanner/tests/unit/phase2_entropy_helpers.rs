use keyhog_scanner::testing::phase2_entropy_helpers::{
    entropy_path_looks_like_random_base64_blob, keyword_is_credential_anchor,
};

#[test]
fn credential_anchor_recognizes_common_keywords() {
    for keyword in [
        "api_key",
        "API_KEY",
        "apiKey",
        "apikey",
        "token",
        "password",
        "client_secret",
        "PRIVATE_KEY",
        "auth_token",
        "encryption_key",
        "signing_key",
        "license_key",
    ] {
        assert!(keyword_is_credential_anchor(keyword), "{keyword}");
    }
}

#[test]
fn credential_anchor_rejects_no_keyword_marker() {
    assert!(!keyword_is_credential_anchor("none (high-entropy)"));
}

#[test]
fn credential_anchor_rejects_unrelated_keyword() {
    assert!(!keyword_is_credential_anchor("description"));
    assert!(!keyword_is_credential_anchor("environment"));
}

#[test]
fn random_b64_blob_admits_pure_alnum_when_mult4_diverse() {
    let value = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456789++//ZZAB==";
    assert_eq!(value.len(), 56, "test invariant: string must be 56 chars");
    assert_eq!(
        value.len() % 4,
        0,
        "test invariant: valid padded base64 requires len%4==0"
    );
    assert!(entropy_path_looks_like_random_base64_blob(value));
}

#[test]
fn random_b64_blob_rejects_pure_lowercase_low_diversity() {
    let value: String = "a".repeat(50);
    assert!(!entropy_path_looks_like_random_base64_blob(&value));
}

#[test]
fn random_b64_blob_admits_real_protobuf_dump() {
    let value = "Vwqk+gg+vh6Pm9mhPgQU/wJPTbFY6cwjNNFQQVY+8jtl/RGABCDEFGHIJKLMNOPQ";
    assert_eq!(value.len(), 64);
    assert!(entropy_path_looks_like_random_base64_blob(value));
}

#[test]
fn random_b64_blob_releases_short_credential_band() {
    let value = "Hk9PqRsTuVwXyZAbCdEfGhIjKlMnOpQr0123456789ab";
    assert_eq!(value.len(), 44);
    assert!(!entropy_path_looks_like_random_base64_blob(value));
}

#[test]
fn random_b64_blob_rejects_plus_only_no_slash() {
    let value = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH+IIIJJJJKKKKLLLLMMMMNNNNOPQR";
    assert_eq!(value.len(), 60);
    assert!(!entropy_path_looks_like_random_base64_blob(value));
}
