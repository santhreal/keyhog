//! canonical_shape_lift_allowed gates the CredData canonical-shape generation
//! lift on the keyword family. Its key-material checks compact the keyword
//! (drop `_`/`-`/`.`, ASCII-lowercase) and substring-match a fixed set of
//! key-material needles. This pins the equivalence to the old
//! `compact_keyword(keyword).contains(needle)` form after that per-candidate
//! `String` allocation was replaced with a zero-alloc skip-aware matcher:
//! the same (value, keyword) pairs lift / do not lift, including the
//! separator-skipping and substring (mid-keyword) cases.

use keyhog_scanner::testing::entropy_scanner::canonical_shape_lift_allowed;
use keyhog_scanner::testing::{
    keyword_is_crypto_key_material_for_test as is_crypto_key,
    keyword_is_key_material_for_test as is_key_material,
};

const HEX32: &str = "0123456789abcdef0123456789abcdef";
const HEX40: &str = "0123456789abcdef0123456789abcdef01234567";
const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn canonical_lift_keyword_material_matches_compacted_contains() {
    // A generic keyword cannot distinguish UUID credentials from identifiers.
    // Provider-specific UUID formats belong in their detector TOMLs.
    assert!(!canonical_shape_lift_allowed(UUID, "token"));
    assert!(!canonical_shape_lift_allowed(UUID, "client_secret"));

    // 32-hex lifts ONLY under a key-material keyword (key_material list).
    assert!(canonical_shape_lift_allowed(HEX32, "api_key")); // -> "apikey"
    assert!(canonical_shape_lift_allowed(HEX32, "access-key")); // dash sep -> "accesskey"
                                                                // Mid-keyword substring match: "my_api_key_field" -> "myapikeyfield" contains "apikey".
    assert!(canonical_shape_lift_allowed(HEX32, "my_api_key_field"));
    // `token` is NOT key material -> 32-hex stays a canonical non-secret shape.
    assert!(!canonical_shape_lift_allowed(HEX32, "token"));
    assert!(!canonical_shape_lift_allowed(HEX32, "session_id")); // "sessionid", not a needle

    // 64-hex (sha256-shaped) lifts ONLY under the NARROWER crypto-key family.
    assert!(canonical_shape_lift_allowed(HEX64, "encryption_key")); // "encryptionkey"
    assert!(canonical_shape_lift_allowed(HEX64, "session-key")); // dash -> "sessionkey"
    assert!(canonical_shape_lift_allowed(HEX64, "hmac_seed")); // "hmacseed"
                                                               // `api_key` / `access_key` are key material but NOT crypto-key material, so
                                                               // a 64-hex value under them stays suppressed (sha256 discrimination).
    assert!(!canonical_shape_lift_allowed(HEX64, "api_key"));
    assert!(!canonical_shape_lift_allowed(HEX64, "access_key"));

    // 40-hex (sha1/git SHA) and 128-hex (sha512) never lift, any keyword.
    assert!(!canonical_shape_lift_allowed(HEX40, "encryption_key"));
    assert!(!canonical_shape_lift_allowed(HEX40, "api_key"));

    // Non-hex, non-UUID value never lifts.
    assert!(!canonical_shape_lift_allowed(
        "not-a-hex-or-uuid-value!!",
        "encryption_key"
    ));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin each shape at a handful of keywords; these SWEEP the gate
// (scanner.rs:canonical_shape_lift_allowed): UUID stays suppressed for every
// generic keyword; a 32-hex value lifts iff the keyword is key material
// and a 64-hex value lifts iff the keyword is crypto-key material, both as
// cross-facade DIFFERENTIALS against the tested `is_key_material` / `is_crypto_key`
// predicates, covering positive AND negative keywords without hardcoding needles;
// and 40-hex, 128-hex, and non-hex/non-UUID values never lift under any keyword.
// No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// A UUID-shaped value never lifts through the generic entropy bridge.
    #[test]
    fn uuid_never_lifts_under_generic_keyword(kw in "[a-zA-Z0-9_.-]{0,24}") {
        prop_assert!(!canonical_shape_lift_allowed(UUID, &kw));
    }

    /// A 32-hex value lifts iff the keyword is key material. DIFFERENTIAL over any
    /// keyword against the tested `is_key_material` predicate.
    #[test]
    fn hex32_lift_matches_key_material_oracle(kw in "[a-zA-Z0-9_.-]{0,24}") {
        prop_assert_eq!(
            canonical_shape_lift_allowed(HEX32, &kw),
            is_key_material(&kw)
        );
    }

    /// A 64-hex value lifts iff the keyword is crypto-key material. DIFFERENTIAL
    /// over any keyword (the narrower sha256 discrimination).
    #[test]
    fn hex64_lift_matches_crypto_key_oracle(kw in "[a-zA-Z0-9_.-]{0,24}") {
        prop_assert_eq!(
            canonical_shape_lift_allowed(HEX64, &kw),
            is_crypto_key(&kw)
        );
    }

    /// A 40-hex (sha1/git-SHA) value never lifts, under any keyword.
    #[test]
    fn hex40_never_lifts(kw in "[a-zA-Z0-9_.-]{0,24}") {
        prop_assert!(!canonical_shape_lift_allowed(HEX40, &kw));
    }

    /// A 128-hex (sha512) value never lifts, under any keyword.
    #[test]
    fn hex128_never_lifts(kw in "[a-zA-Z0-9_.-]{0,24}") {
        let hex128 = format!("{HEX64}{HEX64}");
        prop_assert!(!canonical_shape_lift_allowed(&hex128, &kw));
    }

    /// A non-hex, non-UUID value never lifts, under any keyword (chars g-z are not
    /// hex digits, so the all-hex gate fails).
    #[test]
    fn non_hex_non_uuid_never_lifts(value in "[g-z]{16,40}", kw in "[a-zA-Z0-9_.-]{0,24}") {
        prop_assert!(!canonical_shape_lift_allowed(&value, &kw));
    }
}
