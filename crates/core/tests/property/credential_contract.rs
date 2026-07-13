//! Property tier for the credential-bearing security types (`Credential`,
//! `SensitiveString`). The example-based coverage in `new_core_types.rs` /
//! `regression_sensitive_string_eq.rs` / `regression_redaction_zeroization.rs`
//! pins fixed vectors; this file generalizes each contract to arbitrary inputs
//! (proptest, 10k cases) because these types are security-critical:
//!
//!   * their `Eq`/`Hash` back the engine's credential interning (identical
//!     secrets collapse to one `Arc` in a `HashMap`/`HashSet`), a `Hash`/`Eq`
//!     inconsistency silently corrupts dedup, so it must hold for EVERY input;
//!   * their `serde` round-trip had a real corruption bug (kimi-wave2
//!     §Critical: a UTF-8 value like `b64:SGVsbG8=` was re-decoded as base64)
//!     the property `deserialize(serialize(c)) == c` over arbitrary bytes
//!     exercises BOTH the `text` and `b64` serialization branches and is the
//!     durable guard against that whole class;
//!   * their `Debug`/`Display` are leak guards, the redaction must be exact
//!     (fully determined by byte length, never containing the secret).
//!
//! Everything here goes through the STABLE PUBLIC API (`From` constructors,
//! `PartialEq`/`Ord`/`Hash`, `Deref<str>`, `Display`/`Debug`, `serde`), never a
//! crate-internal path, so it stays green across scanner-side refactors.

use keyhog_core::{Credential, CredentialHash, SensitiveString};
use proptest::prelude::*;
use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

fn hash_of<T: Hash>(t: &T) -> u64 {
    let mut h = DefaultHasher::new();
    t.hash(&mut h);
    h.finish()
}

/// Arbitrary credential payloads: any byte string up to a credential-realistic
/// length, INCLUDING non-UTF-8 (so the `b64` serialization branch is exercised)
/// and the empty slice (a boundary the constant-time compare short-circuits on).
fn bytes_strat() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..300)
}

// ---------------------------------------------------------------------------
// Credential
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Equality is the byte-string biconditional, the correctness half of the
    /// constant-time compare (the timing half is structural, held by the single
    /// `constant_time_bytes_eq` owner + its inline no-early-return loop). Covers
    /// both the equal and (far commoner) unequal branch across arbitrary bytes.
    #[test]
    fn prop_credential_eq_iff_bytes_eq(a in bytes_strat(), b in bytes_strat()) {
        let ca = Credential::from(&a[..]);
        let cb = Credential::from(&b[..]);
        prop_assert_eq!(ca == cb, a == b);
        // Reflexive on both operands (built from the same bytes twice).
        prop_assert_eq!(Credential::from(&a[..]), Credential::from(&a[..]));
    }

    /// Hash agrees with Eq for EVERY input, the invariant credential interning
    /// depends on. Equal keys (same bytes) MUST hash equal; a `HashSet` must
    /// collapse duplicates and keep distinct values, mirroring the engine's
    /// `Arc` interning at scale rather than for one fixed pair.
    #[test]
    fn prop_credential_hash_consistent_with_eq(a in bytes_strat(), b in bytes_strat()) {
        let ca = Credential::from(&a[..]);
        let ca_again = Credential::from(&a[..]);
        prop_assert_eq!(hash_of(&ca), hash_of(&ca_again));

        let mut set = HashSet::new();
        set.insert(Credential::from(&a[..]));
        set.insert(Credential::from(&a[..])); // duplicate → no growth
        prop_assert_eq!(set.len(), 1);
        set.insert(Credential::from(&b[..]));
        prop_assert_eq!(set.len(), if a == b { 1 } else { 2 });
    }

    /// Total order matches the raw byte lexicographic order (the documented
    /// `Ord` impl) AND is consistent with `Eq` (`cmp == Equal ⇔ ==`).
    #[test]
    fn prop_credential_ord_matches_byte_lex(a in bytes_strat(), b in bytes_strat()) {
        let ca = Credential::from(&a[..]);
        let cb = Credential::from(&b[..]);
        prop_assert_eq!(ca.cmp(&cb), a.cmp(&b));
        prop_assert_eq!(ca.cmp(&cb) == Ordering::Equal, ca == cb);
        // Antisymmetry.
        prop_assert_eq!(ca.cmp(&cb), cb.cmp(&ca).reverse());
    }

    /// `Clone` is a refcount bump that preserves value identity: the clone is
    /// `Eq` to and hashes identically to its source.
    #[test]
    fn prop_credential_clone_preserves_eq_and_hash(a in bytes_strat()) {
        let c = Credential::from(&a[..]);
        let cloned = c.clone();
        prop_assert_eq!(&c, &cloned);
        prop_assert_eq!(hash_of(&c), hash_of(&cloned));
    }

    /// `deserialize(serialize(c)) == c` for arbitrary bytes, the durable guard
    /// against the kimi-wave2 §Critical round-trip corruption. Arbitrary bytes
    /// drive UTF-8 payloads through the `text` tag and non-UTF-8 through `b64`,
    /// so one property covers both encoding branches.
    #[test]
    fn prop_credential_serde_roundtrip_preserves_eq(a in bytes_strat()) {
        let c = Credential::from(&a[..]);
        let json = serde_json::to_string(&c).expect("serialize");
        let back: Credential = serde_json::from_str(&json).expect("deserialize");
        prop_assert_eq!(back, c);
    }

    /// Redaction is exact and length-only: `Debug`/`Display` are fully
    /// determined by the byte count, so they cannot contain secret material.
    #[test]
    fn prop_credential_debug_and_display_redact_exactly(a in bytes_strat()) {
        let c = Credential::from(&a[..]);
        prop_assert_eq!(
            format!("{c:?}"),
            format!("Credential(<redacted {} bytes>)", a.len())
        );
        prop_assert_eq!(format!("{c}"), format!("<redacted {} bytes>", a.len()));
    }
}

// ---------------------------------------------------------------------------
// SensitiveString
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Equality is the string biconditional (constant-time under the hood, same
    /// owner as `Credential`).
    #[test]
    fn prop_sensitive_eq_iff_str_eq(s in any::<String>(), t in any::<String>()) {
        let ss = SensitiveString::from(s.as_str());
        let st = SensitiveString::from(t.as_str());
        prop_assert_eq!(ss == st, s == t);
    }

    /// Hash agrees with Eq for every input; duplicates collapse in a `HashSet`.
    #[test]
    fn prop_sensitive_hash_consistent_with_eq(s in any::<String>(), t in any::<String>()) {
        let a = SensitiveString::from(s.as_str());
        let a_again = SensitiveString::from(s.as_str());
        prop_assert_eq!(hash_of(&a), hash_of(&a_again));

        let mut set = HashSet::new();
        set.insert(SensitiveString::from(s.as_str()));
        set.insert(SensitiveString::from(s.as_str()));
        prop_assert_eq!(set.len(), 1);
        set.insert(SensitiveString::from(t.as_str()));
        prop_assert_eq!(set.len(), if s == t { 1 } else { 2 });
    }

    /// Total order matches the underlying `&str` order and is consistent with Eq.
    #[test]
    fn prop_sensitive_ord_matches_str(s in any::<String>(), t in any::<String>()) {
        let ss = SensitiveString::from(s.as_str());
        let st = SensitiveString::from(t.as_str());
        prop_assert_eq!(ss.cmp(&st), s.as_str().cmp(t.as_str()));
        prop_assert_eq!(ss.cmp(&st) == Ordering::Equal, ss == st);
    }

    /// Serde round-trips as a plain JSON string AND preserves the content
    /// (readable publicly via `Deref<str>`), so the value survives a
    /// disk/JSON hop unchanged.
    #[test]
    fn prop_sensitive_serde_roundtrip_preserves_value(s in any::<String>()) {
        let ss = SensitiveString::from(s.as_str());
        let json = serde_json::to_string(&ss).expect("serialize");
        let back: SensitiveString = serde_json::from_str(&json).expect("deserialize");
        prop_assert_eq!(back == ss, true);
        prop_assert_eq!(&*back, s.as_str());
    }

    /// The security asymmetry: `Debug` REDACTS to a length-only form (never the
    /// bytes, it backs `Chunk::data`, which can be raw secret material), while
    /// `Display` INTENTIONALLY exposes the content (the auditable surface).
    #[test]
    fn prop_sensitive_debug_redacts_but_display_exposes(s in any::<String>()) {
        let ss = SensitiveString::from(s.as_str());
        prop_assert_eq!(
            format!("{ss:?}"),
            format!("SensitiveString(<redacted {} bytes>)", s.len())
        );
        prop_assert_eq!(format!("{ss}"), s.clone());
    }
}

// ---------------------------------------------------------------------------
// Explicit regression: the exact kimi-wave2 §Critical corruption case, pinned
// as a named test so the intent is auditable even though the proptest above
// also covers it (arbitrary strings include `b64:`-prefixed values).
// ---------------------------------------------------------------------------

#[test]
fn credential_text_value_that_looks_like_b64_prefix_roundtrips_as_text() {
    // A user-typed credential whose literal value is `b64:SGVsbG8=`. Under the
    // OLD `b64:<base64>` string scheme this round-tripped as the DECODED bytes
    // "Hello" (corruption). The tagged `{"text": …}` form must preserve it
    // verbatim (equality with the original proves no silent decode happened).
    let literal = Credential::from("b64:SGVsbG8=");
    let json = serde_json::to_string(&literal).expect("serialize");
    // New writers must emit the tagged text form, not the ambiguous legacy one.
    assert!(
        json.contains("\"text\""),
        "a UTF-8 credential must serialize under the `text` tag, got {json}"
    );
    let back: Credential = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        back, literal,
        "the `b64:`-looking text value must not be decoded"
    );
}

// ---------------------------------------------------------------------------
// CredentialHash, the SHA-256 digest type findings carry for correlation /
// allowlisting. It serializes as a 64-char hex string (`serde_hash_hex`) and its
// deserializer FAILS CLOSED on any wrong-length or non-hex input (BACKLOG
// finding.rs:493). A lenient parser here would let a malformed `.keyhogignore`
// `hash:` entry or on-disk finding silently corrupt into the wrong digest.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// `deserialize(serialize(h)) == h` for any 32-byte digest, and the wire form
    /// is exactly a quoted 64-char lowercase-hex string.
    #[test]
    fn prop_credential_hash_serde_hex_roundtrips(bytes in prop::array::uniform32(any::<u8>())) {
        let h = CredentialHash::from_bytes(bytes);
        let json = serde_json::to_string(&h).expect("serialize");
        // 32 bytes → 64 hex chars, quoted.
        prop_assert_eq!(json.len(), 66);
        prop_assert!(json.starts_with('"') && json.ends_with('"'));
        prop_assert!(json[1..65].bytes().all(|b| b.is_ascii_hexdigit()));
        let back: CredentialHash = serde_json::from_str(&json).expect("deserialize");
        prop_assert_eq!(back, h);
    }
}

#[test]
fn credential_hash_deserialize_fails_closed_on_bad_input() {
    // Exact round-trip anchor: all-0xAB digest ⇒ "abab…ab" (64 chars).
    let h = CredentialHash::from_bytes([0xab; 32]);
    assert_eq!(
        serde_json::to_string(&h).unwrap(),
        format!("\"{}\"", "ab".repeat(32))
    );

    // Wrong length rejected (empty, too short, too long).
    for bad in ["\"\"", "\"abcd\"", &format!("\"{}\"", "ab".repeat(33))] {
        assert!(
            serde_json::from_str::<CredentialHash>(bad).is_err(),
            "wrong-length hex {bad} must be rejected"
        );
    }
    // Right length (64) but non-hex characters rejected.
    let non_hex = format!("\"{}\"", "zz".repeat(32));
    assert!(
        serde_json::from_str::<CredentialHash>(&non_hex).is_err(),
        "64-char non-hex must be rejected"
    );
}
