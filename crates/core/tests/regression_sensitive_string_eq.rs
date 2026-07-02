//! Regression: pin the equality / ordering / hashing / serde contracts of
//! `keyhog_core::SensitiveString`.
//!
//! Standalone integration test (external crate): only the public API is in
//! scope. `SensitiveString` is re-exported from `keyhog_core` (via `api::*`).
//! The inner `as_str()` is `pub(crate)` and therefore NOT reachable here, so
//! every content read goes through the public `Deref<Target=str>` (`&*ss`),
//! `Display` (`{}`), or `serde` surface.
//!
//! Focus is deliberately DISJOINT from
//! `regression_sensitive_string_redaction.rs` (which owns the `redact()`
//! boundaries and the Debug/Display exposure split) and from
//! `regression_chunk_metadata.rs`: this file pins `PartialEq`/`Eq`,
//! `Ord`/`PartialOrd`, `Hash`, `Borrow<str>`, and `Serialize`/`Deserialize`.
//!
//! Source contracts verified against `crates/core/src/credential.rs`:
//!   * `eq`  -> `self.as_str() == other.as_str()` (by CONTENT, not `Arc` ptr)
//!   * `cmp` -> `self.as_str().cmp(other.as_str())` (lexicographic by bytes)
//!   * `partial_cmp` -> `Some(self.cmp(other))` (total order)
//!   * `hash` -> `self.as_str().hash(state)` (str-consistent, enables
//!               `Borrow<str>` map lookup)
//!   * `Serialize`   -> `self.as_str().serialize(..)` (bare JSON string;
//!                      the content IS exposed on this surface, by contract)
//!   * `Deserialize` -> `String::deserialize(..)` (a JSON string, nothing else)

use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::{Hash, Hasher};

use keyhog_core::SensitiveString;

fn hash_of(ss: &SensitiveString) -> u64 {
    let mut h = DefaultHasher::new();
    ss.hash(&mut h);
    h.finish()
}

fn hash_str(s: &str) -> u64 {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

// ------------------------------------------------------------------
// PartialEq / Eq  (by content, never by Arc identity)
// ------------------------------------------------------------------

#[test]
fn eq_two_independent_equal_secrets_compare_equal() {
    // Two SEPARATE allocations (distinct Arcs) with identical content must be
    // equal: eq() compares `as_str()`, not the Arc pointer.
    let a = SensitiveString::from("ghp_abc123XYZ");
    let b = SensitiveString::from(String::from("ghp_abc123XYZ"));
    assert_eq!(a, b);
    assert!(a == b);
    assert!(!(a != b));
}

#[test]
fn eq_negative_twin_differing_by_one_byte_is_not_equal() {
    // Negative twin: single trailing-byte difference must break equality.
    let a = SensitiveString::from("secretvalue");
    let b = SensitiveString::from("secretvaluE");
    assert_ne!(a, b);
    assert!(a != b);
    assert!(!(a == b));
}

#[test]
fn eq_empty_strings_are_equal_and_reflexive() {
    let e1 = SensitiveString::from("");
    let e2 = SensitiveString::default(); // Default is empty inner String
    assert_eq!(e1, e2);
    // Reflexivity.
    assert_eq!(e1, e1);
    // Empty is NOT equal to a one-char secret.
    let one = SensitiveString::from(" ");
    assert_ne!(e1, one);
}

#[test]
fn eq_clone_shares_arc_but_stays_content_equal() {
    // Clone bumps the Arc refcount (shared buffer); equality must still hold
    // and the content must be byte-identical through Deref.
    let a = SensitiveString::from("shared-secret");
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(&*a, &*b);
    assert_eq!(&*b, "shared-secret");
}

#[test]
fn eq_is_symmetric_for_distinct_values() {
    let a = SensitiveString::from("alpha");
    let b = SensitiveString::from("beta");
    // Symmetry of inequality.
    assert!(a != b);
    assert!(b != a);
    assert_eq!(a == b, b == a);
}

// ------------------------------------------------------------------
// Ord / PartialOrd  (lexicographic by underlying str bytes)
// ------------------------------------------------------------------

#[test]
fn ord_lexicographic_matches_str_ordering() {
    let a = SensitiveString::from("apple");
    let b = SensitiveString::from("banana");
    assert_eq!(a.cmp(&b), Ordering::Less);
    assert_eq!(b.cmp(&a), Ordering::Greater);
    assert!(a < b);
    assert!(b > a);
    // Equal content -> Ordering::Equal.
    let a2 = SensitiveString::from("apple");
    assert_eq!(a.cmp(&a2), Ordering::Equal);
}

#[test]
fn ord_prefix_is_less_than_extension() {
    // Boundary: a strict prefix orders BEFORE its extension ("abc" < "abcd").
    let short = SensitiveString::from("abc");
    let long = SensitiveString::from("abcd");
    assert_eq!(short.cmp(&long), Ordering::Less);
    assert!(short < long);
    // Empty is the minimum.
    let empty = SensitiveString::from("");
    assert_eq!(empty.cmp(&short), Ordering::Less);
    assert!(empty < short);
}

#[test]
fn ord_partial_cmp_is_total_and_consistent_with_cmp() {
    let a = SensitiveString::from("m1");
    let b = SensitiveString::from("m2");
    // partial_cmp returns Some(cmp) for every pair -> total order.
    assert_eq!(a.partial_cmp(&b), Some(Ordering::Less));
    assert_eq!(b.partial_cmp(&a), Some(Ordering::Greater));
    assert_eq!(a.partial_cmp(&a), Some(Ordering::Equal));
    assert_eq!(a.partial_cmp(&b), Some(a.cmp(&b)));
}

#[test]
fn ord_sorts_in_btreeset_deterministically() {
    // BTreeSet exercises Ord end-to-end and dedups content-equal values.
    let mut set = BTreeSet::new();
    set.insert(SensitiveString::from("gamma"));
    set.insert(SensitiveString::from("alpha"));
    set.insert(SensitiveString::from("beta"));
    set.insert(SensitiveString::from("alpha")); // duplicate -> collapses
    assert_eq!(set.len(), 3);
    // Deref each to &str for a concrete ordered assertion.
    let ordered: Vec<&str> = set.iter().map(|s| &**s).collect();
    assert_eq!(ordered, vec!["alpha", "beta", "gamma"]);
}

#[test]
fn ord_multibyte_orders_by_utf8_bytes_not_char_value() {
    // "z" (0x7A) sorts BEFORE "é" (0xC3 0xA9) because Ord is over UTF-8 bytes,
    // exactly matching &str's own Ord.
    let ascii_z = SensitiveString::from("z");
    let e_acute = SensitiveString::from("é");
    assert_eq!(ascii_z.cmp(&e_acute), Ordering::Less);
    assert_eq!(ascii_z.cmp(&e_acute), "z".cmp("é"));
}

// ------------------------------------------------------------------
// Hash  (str-consistent; enables Borrow<str> lookups)
// ------------------------------------------------------------------

#[test]
fn hash_equal_values_hash_equal_and_differ_from_others() {
    // The Eq/Hash invariant: equal values MUST hash equal.
    let a = SensitiveString::from("token-A");
    let b = SensitiveString::from("token-A");
    assert_eq!(hash_of(&a), hash_of(&b));
    // A different value should (with DefaultHasher) hash differently.
    let c = SensitiveString::from("token-B");
    assert_ne!(hash_of(&a), hash_of(&c));
}

#[test]
fn hash_matches_underlying_str_hash() {
    // `hash` forwards to `self.as_str().hash(state)`, so the SensitiveString
    // hash equals the raw &str hash for the same bytes and seed.
    let ss = SensitiveString::from("consistent");
    assert_eq!(hash_of(&ss), hash_str("consistent"));
}

#[test]
fn hash_in_hashset_dedups_content_equal_values() {
    let mut set = HashSet::new();
    assert!(set.insert(SensitiveString::from("dup")));
    // Second, independently-allocated equal value is a duplicate.
    assert!(!set.insert(SensitiveString::from("dup")));
    assert!(set.insert(SensitiveString::from("other")));
    assert_eq!(set.len(), 2);
    assert!(set.contains(&SensitiveString::from("dup")));
}

#[test]
fn hash_borrow_str_enables_lookup_by_plain_str_key() {
    // Borrow<str> + Hash consistency means a HashMap<SensitiveString, _> can be
    // probed with a bare &str. This is the load-bearing dedup-map contract.
    let mut map: HashMap<SensitiveString, u32> = HashMap::new();
    map.insert(SensitiveString::from("api-key"), 7);
    // Lookup via &str (goes through Borrow<str> + str's Hash/Eq).
    assert_eq!(map.get("api-key").copied(), Some(7));
    assert_eq!(map.get("missing").copied(), None);
}

// ------------------------------------------------------------------
// Serialize / Deserialize  (bare JSON string; content exposed by contract)
// ------------------------------------------------------------------

#[test]
fn serialize_emits_bare_json_string_exposing_content() {
    // Serialize forwards to `as_str().serialize` -> a plain JSON string.
    // This surface INTENTIONALLY exposes the bytes (mirrors Display); pin it so
    // a future "redact on serialize" change is a deliberate, reviewed decision.
    let ss = SensitiveString::from("ghp_secretvalue");
    let json = serde_json::to_string(&ss).unwrap();
    assert_eq!(json, "\"ghp_secretvalue\"");
    // Special characters are JSON-escaped, not mangled.
    let quoted = SensitiveString::from("a\"b\\c");
    assert_eq!(serde_json::to_string(&quoted).unwrap(), "\"a\\\"b\\\\c\"");
}

#[test]
fn deserialize_from_json_string_roundtrips_exactly() {
    let ss = SensitiveString::from("café-π-secret");
    let json = serde_json::to_string(&ss).unwrap();
    let back: SensitiveString = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ss);
    assert_eq!(&*back, "café-π-secret");
}

#[test]
fn deserialize_rejects_non_string_json_failing_closed() {
    // Deserialize uses `String::deserialize`, so a JSON number/bool/null is a
    // hard type error (fail closed), never a lossy coercion.
    let num: Result<SensitiveString, _> = serde_json::from_str("12345");
    assert!(num.is_err());
    let boolean: Result<SensitiveString, _> = serde_json::from_str("true");
    assert!(boolean.is_err());
    let null: Result<SensitiveString, _> = serde_json::from_str("null");
    assert!(null.is_err());
    // And a well-formed JSON string still succeeds with exact content.
    let ok: SensitiveString = serde_json::from_str("\"ok\"").unwrap();
    assert_eq!(&*ok, "ok");
}

// ------------------------------------------------------------------
// Cross-check: Debug still redacts even as Eq/Ord expose nothing textual
// ------------------------------------------------------------------

#[test]
fn debug_redacts_while_eq_and_deref_use_full_content() {
    // Distinct-from-redaction-file angle: prove Eq operates on the FULL content
    // (so redaction can't be "cheating" by comparing masked forms) while Debug
    // still leaks nothing. Two 20-byte equal secrets: equal, yet Debug shows
    // only the byte count.
    let a = SensitiveString::from("0123456789abcdefghij"); // 20 bytes
    let b = SensitiveString::from("0123456789abcdefghij");
    assert_eq!(a, b);
    assert_eq!(&*a, "0123456789abcdefghij");
    let dbg = format!("{a:?}");
    assert_eq!(dbg, "SensitiveString(<redacted 20 bytes>)");
    assert!(
        !dbg.contains("123456789abcdefghi"),
        "Debug must not leak the interior of the secret: {dbg}"
    );
}
