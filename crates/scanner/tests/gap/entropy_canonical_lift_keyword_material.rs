//! canonical_shape_lift_allowed gates the CredData canonical-shape generation
//! lift on the keyword family. Its key-material checks compact the keyword
//! (drop `_`/`-`/`.`, ASCII-lowercase) and substring-match a fixed set of
//! key-material needles. This pins the equivalence to the old
//! `compact_keyword(keyword).contains(needle)` form after that per-candidate
//! `String` allocation was replaced with a zero-alloc skip-aware matcher:
//! the same (value, keyword) pairs lift / do not lift, including the
//! separator-skipping and substring (mid-keyword) cases.

use keyhog_scanner::testing::entropy_scanner::canonical_shape_lift_allowed;

const HEX32: &str = "0123456789abcdef0123456789abcdef";
const HEX40: &str = "0123456789abcdef0123456789abcdef01234567";
const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const UUID: &str = "550e8400-e29b-41d4-a716-446655440000";

#[test]
fn canonical_lift_keyword_material_matches_compacted_contains() {
    // A UUID-shaped value lifts under ANY keyword (handled before the hex arms).
    assert!(canonical_shape_lift_allowed(UUID, "token"));
    assert!(canonical_shape_lift_allowed(UUID, "whatever"));

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
