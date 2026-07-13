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
//! exact-value test, only a comment in the CredData recall regression. Pin the
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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per node; these SWEEP the whole decision tree.
// The value gate is swept independently of the (guaranteed-strong) keyword; the
// keyword branches are swept with case + `_`/`-`/`.` separator decoration (which
// the compacting comparison folds away): exact strong-family members anchor, the
// `licensekey` exclusion fires before the suffix fallback, a compact form ending
// in `key`/`secret` anchors, and a non-`key`/`secret` suffix rejects. Traced
// against engine/phase2_generic/keywords.rs:191. No proptest before.

use proptest::prelude::*;

/// The strong cryptographic-key family (compact, lowercase). Each anchors a valid
/// 32/48-hex value regardless of case/separator spelling.
const STRONG_FAMILY: &[&str] = &[
    "secret",
    "apikey",
    "privatekey",
    "encryptionkey",
    "signingkey",
    "accesskey",
    "clientsecret",
    "appsecret",
    "masterkey",
];

/// Separators the compacting comparison drops (plus the empty joiner = no sep).
const SEPS: &[&str] = &["_", "-", ".", ""];

/// Suffixes that are NOT credential anchors (a keyword ending in one rejects).
const NON_ANCHOR_SUFFIXES: &[&str] = &["vault", "name", "id", "value", "host"];

/// Join a word's chars with `sep` (e.g. `apikey` + `_` → `a_p_i_k_e_y`).
fn sprinkle(word: &str, sep: &str) -> String {
    word.chars()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// The value gate is independent of the keyword: a hex value whose length is
    /// not 32 or 48 is rejected even under a strong-family keyword.
    #[test]
    fn wrong_length_value_is_rejected(
        ki in 0usize..STRONG_FAMILY.len(),
        value in "[0-9a-f]{0,60}",
    ) {
        prop_assume!(value.len() != 32 && value.len() != 48);
        prop_assert!(!strong_hex(STRONG_FAMILY[ki], &value));
    }

    /// A 32/48-length value containing a non-hex byte is rejected (a strong keyword
    /// cannot rescue it).
    #[test]
    fn non_hex_value_of_valid_length_is_rejected(
        ki in 0usize..STRONG_FAMILY.len(),
        prefix in "[0-9a-f]{47}",
        len48 in any::<bool>(),
    ) {
        // Take 31 or 47 hex, then append a non-hex byte → length 32 or 48.
        let base_len = if len48 { 47 } else { 31 };
        let value = format!("{}z", &prefix[..base_len]);
        prop_assert_eq!(value.len(), base_len + 1);
        prop_assert!(!strong_hex(STRONG_FAMILY[ki], &value));
    }

    /// Every strong-family member anchors, in any case and any separator spelling.
    #[test]
    fn strong_family_members_anchor(
        ki in 0usize..STRONG_FAMILY.len(),
        si in 0usize..SEPS.len(),
        upper in any::<bool>(),
        val48 in any::<bool>(),
    ) {
        let joined = sprinkle(STRONG_FAMILY[ki], SEPS[si]);
        let keyword = if upper { joined.to_uppercase() } else { joined };
        let value = if val48 { H48 } else { H32 };
        prop_assert!(strong_hex(&keyword, value));
    }

    /// `licensekey` is explicitly excluded BEFORE the suffix fallback, any
    /// case/separator spelling rejects, despite ending in `key`.
    #[test]
    fn licensekey_variants_are_excluded(si in 0usize..SEPS.len(), upper in any::<bool>()) {
        let joined = sprinkle("licensekey", SEPS[si]);
        let keyword = if upper { joined.to_uppercase() } else { joined };
        prop_assert!(!strong_hex(&keyword, H32));
    }

    /// A compact form ending in `key`/`secret` anchors (unless it is exactly
    /// `licensekey`) (the vendor-prefixed generalization).
    #[test]
    fn compact_ends_with_key_or_secret_anchors(
        pre in "[a-z]{1,10}",
        secret in any::<bool>(),
    ) {
        let suffix = if secret { "secret" } else { "key" };
        prop_assume!(!(pre == "license" && suffix == "key"));
        let keyword = format!("{pre}_{suffix}");
        prop_assert!(strong_hex(&keyword, H32));
    }

    /// A keyword whose compact form ends in a non-anchor token rejects. `ends_with`
    /// is a suffix test, and these suffixes are neither `key` nor `secret`.
    #[test]
    fn non_anchor_suffix_keywords_reject(
        body in "[a-z]{1,10}",
        ni in 0usize..NON_ANCHOR_SUFFIXES.len(),
    ) {
        let keyword = format!("{body}{}", NON_ANCHOR_SUFFIXES[ni]);
        prop_assert!(!strong_hex(&keyword, H32));
    }
}
