//! Lock the verification cache's metadata-sanitization bounds.
//!
//! `VerificationCache::put` runs every metadata map through `sanitize_metadata`
//! before it is stored, capping it three ways (mirrors the private consts in
//! `crates/verifier/src/cache.rs`):
//!   - `MAX_METADATA_ENTRIES   = 16`  entries retained per finding,
//!   - `MAX_METADATA_KEY_BYTES  = 64` bytes per key,
//!   - `MAX_METADATA_VALUE_BYTES = 256` bytes per value.
//!
//! These are real memory/DoS bounds (Law-15 OOM/amplification): a hostile
//! detector spec or a malicious upstream verification response could otherwise
//! stuff unbounded metadata into the long-lived in-memory cache, multiplied
//! across every cached finding. The truncation routine
//! (`truncate_to_char_boundary`) is ALSO a panic-safety primitive, slicing a
//! `&str` at a non-char boundary panics, so a multibyte value cut at the byte
//! cap must walk back to a valid boundary.
//!
//! Nothing exercised these caps before this file (the existing `unit/cache.rs`
//! covers hit/miss, TTL, eviction, and key collisions, but never oversized
//! metadata). Every assertion here drives the real production `put -> get`
//! round trip through the test facade, so it pins the SHIPPED sanitize path,
//! not a reimplementation.
//!
//! The literal `16` / `64` / `256` below intentionally mirror the source
//! consts: if a refactor changes a cap, these break and force the change to be
//! deliberate (and the bound re-justified), instead of silently regressing the
//! DoS posture.

use keyhog_core::VerificationResult;
use keyhog_verifier::testing::{TestVerificationCache as VerificationCache, VerifierTestCache};
use std::collections::HashMap;
use std::time::Duration;

const MAX_ENTRIES: usize = 16;
const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 256;

/// Put `metadata` under a fixed key, read it back, and return the sanitized map
/// the cache actually stored. A 1-hour TTL keeps the entry live across the call.
fn round_trip(metadata: HashMap<String, String>) -> HashMap<String, String> {
    let cache = VerificationCache::new(Duration::from_secs(3600));
    cache.put("cred", "detector", VerificationResult::Live, metadata);
    let (_result, stored) = cache
        .get("cred", "detector")
        .expect("a freshly-put entry must be retrievable");
    stored
}

/// Build a metadata map with `n` distinct short keys (`k000`, `k001`, …), each
/// mapped to the same small value.
fn many_entries(n: usize, value: &str) -> HashMap<String, String> {
    (0..n)
        .map(|i| (format!("k{i:03}"), value.to_string()))
        .collect()
}

// ===========================================================================
// GROUP A (entry-count cap (16)).
// ===========================================================================

#[test]
fn entry_count_capped_at_sixteen_when_far_over() {
    let stored = round_trip(many_entries(50, "v"));
    assert!(
        stored.len() <= MAX_ENTRIES,
        "50 entries must be capped to <= {MAX_ENTRIES}, got {}",
        stored.len()
    );
}

#[test]
fn entry_count_is_exactly_sixteen_when_just_over() {
    // 17 distinct short keys -> take(16) keeps 16 distinct (none collide after
    // the no-op key truncation), so the surviving count is exactly the cap.
    let stored = round_trip(many_entries(17, "v"));
    assert_eq!(stored.len(), MAX_ENTRIES);
}

#[test]
fn entry_count_at_exactly_cap_keeps_all_sixteen() {
    let stored = round_trip(many_entries(16, "v"));
    assert_eq!(stored.len(), 16, "exactly 16 entries are all retained");
    for i in 0..16 {
        assert_eq!(
            stored.get(&format!("k{i:03}")).map(String::as_str),
            Some("v")
        );
    }
}

#[test]
fn entry_count_under_cap_is_preserved_whole() {
    let stored = round_trip(many_entries(5, "v"));
    assert_eq!(stored.len(), 5);
    for i in 0..5 {
        assert_eq!(
            stored.get(&format!("k{i:03}")).map(String::as_str),
            Some("v")
        );
    }
}

#[test]
fn empty_metadata_round_trips_empty() {
    let stored = round_trip(HashMap::new());
    assert!(stored.is_empty());
}

#[test]
fn entry_cap_and_value_cap_apply_together() {
    // 30 entries, each value oversized: count must cap AND every survivor's
    // value must be byte-capped.
    let stored = round_trip(many_entries(30, &"a".repeat(300)));
    assert!(stored.len() <= MAX_ENTRIES);
    for (_k, v) in &stored {
        assert_eq!(v.len(), MAX_VALUE_BYTES, "each surviving value is capped");
    }
}

// ===========================================================================
// GROUP B (value-byte cap (256)).
// ===========================================================================

#[test]
fn oversized_value_truncated_to_256_bytes() {
    let stored = round_trip(HashMap::from([("k".to_string(), "a".repeat(300))]));
    assert_eq!(stored["k"].len(), MAX_VALUE_BYTES);
}

#[test]
fn value_exactly_256_bytes_is_preserved() {
    let value = "a".repeat(256);
    let stored = round_trip(HashMap::from([("k".to_string(), value.clone())]));
    assert_eq!(
        stored["k"], value,
        "a value at exactly the cap is kept whole"
    );
}

#[test]
fn value_one_under_cap_is_preserved() {
    let value = "a".repeat(255);
    let stored = round_trip(HashMap::from([("k".to_string(), value.clone())]));
    assert_eq!(stored["k"], value);
}

#[test]
fn value_one_over_cap_is_truncated_to_256() {
    let stored = round_trip(HashMap::from([("k".to_string(), "a".repeat(257))]));
    assert_eq!(stored["k"].len(), MAX_VALUE_BYTES);
}

#[test]
fn truncated_value_keeps_the_head_not_the_tail() {
    // Distinct head bytes prove truncation drops the tail, not the prefix.
    let value = format!("{}{}", "HEAD", "a".repeat(300));
    let stored = round_trip(HashMap::from([("k".to_string(), value)]));
    assert_eq!(stored["k"].len(), MAX_VALUE_BYTES);
    assert!(stored["k"].starts_with("HEAD"));
    assert_eq!(&stored["k"][..4], "HEAD");
}

// ===========================================================================
// GROUP C (key-byte cap (64)).
// ===========================================================================

#[test]
fn oversized_key_truncated_to_64_bytes() {
    let key = "k".repeat(100);
    let stored = round_trip(HashMap::from([(key, "v".to_string())]));
    assert_eq!(stored.len(), 1);
    let only_key = stored.keys().next().expect("one entry stored");
    assert_eq!(only_key.len(), MAX_KEY_BYTES);
}

#[test]
fn key_exactly_64_bytes_is_preserved() {
    let key = "k".repeat(64);
    let stored = round_trip(HashMap::from([(key.clone(), "v".to_string())]));
    assert!(stored.contains_key(&key), "a 64-byte key is kept whole");
}

#[test]
fn key_one_over_cap_is_truncated_to_64() {
    let key = "k".repeat(65);
    let stored = round_trip(HashMap::from([(key, "v".to_string())]));
    let only_key = stored.keys().next().expect("one entry stored");
    assert_eq!(only_key.len(), MAX_KEY_BYTES);
}

#[test]
fn oversized_key_and_value_capped_independently() {
    let stored = round_trip(HashMap::from([("k".repeat(100), "a".repeat(300))]));
    assert_eq!(stored.len(), 1);
    let (key, value) = stored.iter().next().expect("one entry stored");
    assert_eq!(key.len(), MAX_KEY_BYTES);
    assert_eq!(value.len(), MAX_VALUE_BYTES);
}

// ===========================================================================
// GROUP D, multibyte char-boundary safety (truncate must not split a char,
//           and must not panic). UTF-8 widths: é=2, €=3, 😀=4 bytes.
// ===========================================================================

#[test]
fn two_byte_value_truncation_lands_on_boundary() {
    // 200 × 'é' = 400 bytes; cap 256 = 128 × 2 falls on a boundary.
    let stored = round_trip(HashMap::from([("k".to_string(), "é".repeat(200))]));
    let value = &stored["k"];
    assert!(value.len() <= MAX_VALUE_BYTES);
    assert_eq!(value.len(), 256, "256 is an exact 2-byte boundary");
    assert_eq!(value.chars().count(), 128);
    assert!(value.chars().all(|c| c == 'é'), "no replacement / no split");
}

#[test]
fn three_byte_value_truncation_walks_back_to_boundary() {
    // 100 × '€' = 300 bytes; byte 256 is mid-char (255 = 85×3 is the boundary),
    // so the cut must walk back to 255 bytes / 85 chars rather than panic.
    let stored = round_trip(HashMap::from([("k".to_string(), "€".repeat(100))]));
    let value = &stored["k"];
    assert!(value.len() <= MAX_VALUE_BYTES);
    assert_eq!(value.len(), 255, "walks back from 256 to the 85×3 boundary");
    assert_eq!(value.chars().count(), 85);
    assert!(value.chars().all(|c| c == '€'));
}

#[test]
fn four_byte_value_truncation_lands_on_boundary() {
    // 100 × '😀' = 400 bytes; cap 256 = 64 × 4 falls on a boundary.
    let stored = round_trip(HashMap::from([("k".to_string(), "😀".repeat(100))]));
    let value = &stored["k"];
    assert_eq!(value.len(), 256);
    assert_eq!(value.chars().count(), 64);
    assert!(value.chars().all(|c| c == '😀'));
}

#[test]
fn four_byte_value_with_ascii_prefix_walks_back_mid_char() {
    // "x" + 100×'😀': byte 256 lands inside the 64th emoji (starts at byte 253),
    // so the cut walks back to 253 bytes = "x" + 63 emoji.
    let value = format!("x{}", "😀".repeat(100));
    let stored = round_trip(HashMap::from([("k".to_string(), value)]));
    let value = &stored["k"];
    assert!(value.len() <= MAX_VALUE_BYTES);
    assert_eq!(value.len(), 253, "walk back to the 'x' + 63×4 boundary");
    assert_eq!(value.chars().count(), 64, "one ASCII + 63 emoji");
    assert!(value.starts_with('x'));
}

#[test]
fn multibyte_key_truncation_lands_on_boundary() {
    // 50 × 'ü' = 100 bytes; cap 64 = 32 × 2 falls on a boundary.
    let stored = round_trip(HashMap::from([("ü".repeat(50), "v".to_string())]));
    let only_key = stored.keys().next().expect("one entry stored");
    assert!(only_key.len() <= MAX_KEY_BYTES);
    assert_eq!(only_key.len(), 64);
    assert_eq!(only_key.chars().count(), 32);
    assert!(only_key.chars().all(|c| c == 'ü'));
}

#[test]
fn three_byte_key_truncation_walks_back_to_boundary() {
    // 30 × '€' = 90 bytes; byte 64 is mid-char (63 = 21×3 is the boundary).
    let stored = round_trip(HashMap::from([("€".repeat(30), "v".to_string())]));
    let only_key = stored.keys().next().expect("one entry stored");
    assert!(only_key.len() <= MAX_KEY_BYTES);
    assert_eq!(
        only_key.len(),
        63,
        "walks back from 64 to the 21×3 boundary"
    );
    assert_eq!(only_key.chars().count(), 21);
}

// ===========================================================================
// GROUP E (round-trip integrity of the common (non-oversized) path + replace).
// ===========================================================================

#[test]
fn normal_metadata_is_returned_verbatim() {
    let metadata = HashMap::from([
        ("arn".to_string(), "arn:aws:iam::123:user/x".to_string()),
        ("account_id".to_string(), "123456789012".to_string()),
    ]);
    let stored = round_trip(metadata.clone());
    assert_eq!(
        stored, metadata,
        "small metadata is not altered by sanitize"
    );
}

#[test]
fn caps_apply_on_replace_not_just_first_insert() {
    // Put small metadata, then overwrite the SAME key with oversized metadata.
    let cache = VerificationCache::new(Duration::from_secs(3600));
    cache.put(
        "cred",
        "detector",
        VerificationResult::Live,
        HashMap::from([("k".to_string(), "small".to_string())]),
    );
    cache.put(
        "cred",
        "detector",
        VerificationResult::Dead,
        HashMap::from([("k".to_string(), "a".repeat(300))]),
    );
    let (result, stored) = cache.get("cred", "detector").expect("entry present");
    assert!(
        matches!(result, VerificationResult::Dead),
        "replace took effect"
    );
    assert_eq!(
        stored["k"].len(),
        MAX_VALUE_BYTES,
        "replacing value is capped too"
    );
}

#[test]
fn ascii_value_at_cap_is_not_off_by_one_truncated() {
    // Guards the `value.len() <= max_bytes` boundary: exactly-256 must stay 256,
    // and a single byte more must become exactly 256 (never 255 or 257).
    let at_cap = round_trip(HashMap::from([("k".to_string(), "a".repeat(256))]));
    let over_cap = round_trip(HashMap::from([("k".to_string(), "a".repeat(257))]));
    assert_eq!(at_cap["k"].len(), 256);
    assert_eq!(over_cap["k"].len(), 256);
}
