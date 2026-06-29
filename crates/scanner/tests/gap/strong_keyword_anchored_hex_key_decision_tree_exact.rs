//! Gap test: the strong-keyword hex-key anchor's full decision tree.
//!
//! `engine::phase2_generic::keywords::is_strong_keyword_anchored_hex_key` lets a
//! generic-bridge capture of a complete 32/48-char hex value reach the scorer
//! ONLY when its keyword is a strong cryptographic-key anchor. The decision
//! tree is:
//!   1. value must be exactly 32 or 48 bytes AND all ASCII hex, else false;
//!   2. keyword (case-folded, `_`/`-`/`.` dropped) exactly equal to one of the
//!      strong family (`secret`, `apikey`, `privatekey`, `encryptionkey`,
//!      `signingkey`, `accesskey`, `clientsecret`, `appsecret`, `masterkey`)
//!      => true;
//!   3. compacted keyword == `licensekey` => false (explicit weak exclusion);
//!   4. otherwise compacted keyword ends with `key` or `secret` => that result.
//!
//! The helper is live (the generic bridge calls it) but had no direct
//! exact-value test — only a comment in the CredData recall regression. Pin the
//! whole tree, especially the `license_key` exclusion vs the `vendor_api_key`
//! ends-with generalization, and that `ends_with` is a suffix not a prefix.

use keyhog_scanner::testing::is_strong_keyword_anchored_hex_key_for_test as strong_hex;

const H32: &str = "0123456789abcdef0123456789abcdef";
const H48: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn value_must_be_thirty_two_or_forty_eight_hex() {
    // A strong keyword cannot rescue a value that fails the shape gate.
    assert!(!strong_hex("apikey", "g0123456789abcdef0123456789abcde")); // 32 len, non-hex
    assert!(!strong_hex("apikey", "deadbeef")); // 8 bytes, too short
    assert!(!strong_hex("apikey", "0123456789abcdef0123456789abcdef0")); // 33 bytes
                                                                         // The same strong keyword DOES pass once the value is valid 32/48 hex.
    assert!(strong_hex("apikey", H32));
    assert!(strong_hex("apikey", H48));
}

#[test]
fn exact_strong_family_members_anchor() {
    assert!(strong_hex("API_KEY", H32)); // -> apikey
    assert!(strong_hex("client-secret", H48)); // -> clientsecret
    assert!(strong_hex("secret", H32));
    assert!(strong_hex("private.key", H32)); // -> privatekey
    assert!(strong_hex("MASTER_KEY", H32)); // -> masterkey
    assert!(strong_hex("access-key", H48)); // -> accesskey
    assert!(strong_hex("app.secret", H32)); // -> appsecret
}

#[test]
fn vendor_prefixed_keys_anchor_via_ends_with() {
    // Not in the exact family, but the compacted keyword ends with key/secret.
    assert!(strong_hex("vendor_api_key", H32)); // ends with `key`
    assert!(strong_hex("db_secret", H48)); // ends with `secret`
}

#[test]
fn licensekey_is_explicitly_excluded_and_weak_anchors_reject() {
    // `licensekey` ends with `key` but is excluded BEFORE the suffix fallback.
    assert!(!strong_hex("license_key", H32));
    assert!(!strong_hex("LICENSE-KEY", H48));
    // Weak / non-key anchors never qualify, even with a perfect hex value.
    assert!(!strong_hex("password", H32));
    assert!(!strong_hex("auth_token", H32));
    assert!(!strong_hex("username", H32));
    // `ends_with` is a suffix, not a prefix: `keyvault` does not end with `key`.
    assert!(!strong_hex("keyvault", H32));
}
