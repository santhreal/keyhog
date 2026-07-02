//! Regression: `merkle_index` incremental-scan contract.
//!
//! These pin the exact behavior the incremental scanner depends on for
//! correctness AND speed:
//!   * BLAKE3 content hashing is deterministic (stable across calls) and is
//!     the real BLAKE3 of the bytes, so a stored fingerprint identifies the
//!     same content forever.
//!   * An unchanged chunk is recognized as unchanged (`true`); a single-byte
//!     edit flips it to changed (`false`) so a freshly injected secret can
//!     never be skipped.
//!   * `(mtime, size)` fast-path and `lookup` return exact stored tuples.
//!   * The JSON cache round-trips save -> load with byte-identical entries,
//!     including the spec-hash gate and the entry cap.
//!
//! Every assertion is a CONCRETE value (exact bool / count / byte tuple /
//! digest), never a shape check. Access is through the crate's doc(hidden)
//! `testing::CoreTestApi` facade plus the type's own `pub` methods; no
//! production visibility is widened for these tests.

use keyhog_core::testing::{CoreTestApi, TestApi};

/// Lowercase hex of a byte slice, for exact-string digest assertions.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Canonical BLAKE3 digest of the empty input (published reference test
/// vector for `input_len = 0`). Pins the algorithm so a swap to a different
/// hash is caught by an exact string compare, not just internal consistency.
const BLAKE3_EMPTY_HEX: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

// ── hashing: deterministic, real BLAKE3, 32 bytes ─────────────────────────

#[test]
fn hash_content_is_blake3_and_matches_empty_test_vector() {
    let api = TestApi;
    let empty = api.merkle_hash_content(b"");
    // 32-byte output.
    assert_eq!(empty.len(), 32, "BLAKE3 output must be 32 bytes");
    // Exact published empty-input vector.
    assert_eq!(
        to_hex(&empty),
        BLAKE3_EMPTY_HEX,
        "hash_content(b\"\") must equal the canonical BLAKE3 empty digest"
    );
    // And equal to the reference crate on a non-empty input.
    let probe = b"keyhog-incremental-scan-probe";
    assert_eq!(
        api.merkle_hash_content(probe),
        *blake3::hash(probe).as_bytes(),
        "hash_content must be BLAKE3 of the exact bytes"
    );
}

#[test]
fn hash_is_stable_across_repeated_calls() {
    let api = TestApi;
    let content = b"the same forty-two bytes hashed three separate times!!";
    let a = api.merkle_hash_content(content);
    let b = api.merkle_hash_content(content);
    let c = api.merkle_hash_content(content);
    // Byte-for-byte identical every call.
    assert_eq!(a, b, "hash call 1 vs 2 must be identical");
    assert_eq!(b, c, "hash call 2 vs 3 must be identical");
    // A different input yields a different digest.
    let other = api.merkle_hash_content(b"the same forty-two bytes hashed three separate times?!");
    assert_ne!(a, other, "distinct content must hash differently");
}

#[test]
fn single_byte_edit_changes_the_hash() {
    let api = TestApi;
    let before = api.merkle_hash_content(b"password = hunter2");
    let after = api.merkle_hash_content(b"password = hunter3"); // one byte flipped
    assert_ne!(
        before, after,
        "a one-byte edit must produce a different BLAKE3 digest"
    );
    // Avalanche: the flip must perturb many bytes, not one.
    let differing = before
        .iter()
        .zip(after.iter())
        .filter(|(x, y)| x != y)
        .count();
    assert!(
        differing >= 16,
        "one-byte input edit must change at least half the digest bytes, changed {differing}"
    );
}

// ── unchanged detection: exact bool on first vs repeat vs edit ────────────

#[test]
fn record_chunk_first_is_new_then_unchanged() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("src/config.rs");
    let content = b"api_key placeholder line";

    // First observation: never seen => NOT unchanged.
    let first = api.merkle_record_chunk_at_offset_and_check_unchanged(
        &idx,
        path.clone(),
        0,
        1_000,
        content.len() as u64,
        content,
    );
    assert!(!first, "first record of a path must return false (new)");

    // Re-observe identical content => unchanged.
    let second = api.merkle_record_chunk_at_offset_and_check_unchanged(
        &idx,
        path.clone(),
        0,
        1_000,
        content.len() as u64,
        content,
    );
    assert!(second, "re-recording identical content must return true");

    // Exactly one entry retained.
    assert_eq!(api.merkle_len(&idx), 1, "one path => one entry");
}

#[test]
fn byte_edit_flips_unchanged_back_to_changed() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("src/secret.rs");

    let v1 = b"token = AKIA0000000000000000";
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, path.clone(), 0, 5, 27, v1),
        "initial content is new"
    );
    assert!(
        api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, path.clone(), 0, 5, 27, v1),
        "unchanged content is recognized"
    );

    // Edit one byte at the same path/offset: must be seen as changed.
    let v2 = b"token = AKIA0000000000000001";
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, path.clone(), 0, 5, 27, v2),
        "edited content must return false (changed)"
    );
    // And now the NEW content is the cached one.
    assert!(
        api.merkle_record_chunk_at_offset_and_check_unchanged(&idx, path.clone(), 0, 5, 27, v2),
        "the edited content becomes the new baseline"
    );
    assert_eq!(
        api.merkle_len(&idx),
        1,
        "edit updates in place, no new entry"
    );
}

#[test]
fn unchanged_by_stored_hash_is_exact() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("a/b/c.txt");
    let h = api.merkle_hash_content(b"the cached content");
    api.merkle_record_with_metadata(&idx, path.clone(), 10, 18, h);

    assert!(
        api.merkle_unchanged(&idx, &path, &h),
        "matching hash => unchanged true"
    );
    let other = api.merkle_hash_content(b"different content");
    assert!(
        !api.merkle_unchanged(&idx, &path, &other),
        "non-matching hash => unchanged false"
    );
    // A path never recorded is not unchanged under any hash.
    assert!(
        !api.merkle_unchanged(&idx, std::path::Path::new("never/seen"), &h),
        "unknown path => unchanged false"
    );
}

// ── metadata fast-path: exact + boundary ──────────────────────────────────

#[test]
fn metadata_unchanged_exact_and_boundaries() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("src/main.rs");
    let h = api.merkle_hash_content(b"fn main() {}");
    api.merkle_record_with_metadata(&idx, path.clone(), 42, 7, h);

    assert!(
        api.merkle_metadata_unchanged(&idx, &path, 42, 7),
        "exact (mtime,size) match => true"
    );
    assert!(
        !api.merkle_metadata_unchanged(&idx, &path, 42, 8),
        "size drift by one => false"
    );
    assert!(
        !api.merkle_metadata_unchanged(&idx, &path, 43, 7),
        "mtime drift by one => false"
    );
    assert!(
        !api.merkle_metadata_unchanged(&idx, std::path::Path::new("other.rs"), 42, 7),
        "unknown path => false"
    );
}

#[test]
fn metadata_match_does_not_imply_content_match() {
    // The (mtime,size) fast-path is a heuristic; the stored hash remains the
    // authority. Pin that a metadata match coexists with a content mismatch.
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("racy.rs");
    let stored = api.merkle_hash_content(b"AAA");
    api.merkle_record_with_metadata(&idx, path.clone(), 5, 3, stored);

    assert!(
        api.merkle_metadata_unchanged(&idx, &path, 5, 3),
        "metadata matches"
    );
    let actual = api.merkle_hash_content(b"BBB");
    assert!(
        !api.merkle_unchanged(&idx, &path, &actual),
        "yet the content hash differs, so content is NOT unchanged"
    );
    assert_eq!(
        api.merkle_lookup(&idx, &path),
        Some((5, 3, stored)),
        "lookup still returns the originally stored fingerprint"
    );
}

// ── lookup: exact tuple / None ────────────────────────────────────────────

#[test]
fn lookup_returns_exact_tuple_or_none() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("dir/file.env");
    let h = api.merkle_hash_content(b"KEY=value");
    api.merkle_record_with_metadata(&idx, path.clone(), 123, 9, h);

    assert_eq!(
        api.merkle_lookup(&idx, &path),
        Some((123, 9, h)),
        "lookup returns the exact (mtime,size,hash) tuple"
    );
    assert_eq!(
        api.merkle_lookup(&idx, std::path::Path::new("dir/missing.env")),
        None,
        "unknown path => None"
    );
}

// ── save/load round-trip: exact entries ───────────────────────────────────

#[test]
fn save_load_roundtrips_exact_entries() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("merkle.idx");

    let idx = api.merkle_empty();
    let ha = api.merkle_hash_content(b"alpha");
    let hb = api.merkle_hash_content(b"bravo");
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("a.rs"), 11, 5, ha);
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("b.rs"), 22, 5, hb);
    assert_eq!(api.merkle_len(&idx), 2, "two entries before save");

    api.merkle_save(&idx, &cache).expect("save must succeed");

    let loaded = api.merkle_load(&cache);
    assert_eq!(
        api.merkle_len(&loaded),
        2,
        "both entries survive the round-trip"
    );
    assert_eq!(
        api.merkle_lookup(&loaded, std::path::Path::new("a.rs")),
        Some((11, 5, ha)),
        "entry a.rs round-trips byte-identically"
    );
    assert_eq!(
        api.merkle_lookup(&loaded, std::path::Path::new("b.rs")),
        Some((22, 5, hb)),
        "entry b.rs round-trips byte-identically"
    );
    assert_eq!(
        api.merkle_lookup(&loaded, std::path::Path::new("c.rs")),
        None,
        "a path never stored is absent after load"
    );
}

#[test]
fn empty_index_save_load_is_zero_entries() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("empty.idx");

    let idx = api.merkle_empty();
    assert!(api.merkle_is_empty(&idx), "fresh index is empty");
    api.merkle_save(&idx, &cache)
        .expect("saving an empty index must succeed");

    let loaded = api.merkle_load(&cache);
    assert_eq!(
        api.merkle_len(&loaded),
        0,
        "loaded empty cache has 0 entries"
    );
    assert!(api.merkle_is_empty(&loaded), "loaded empty cache is empty");
}

#[test]
fn load_missing_file_is_cold_empty() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.idx");
    let loaded = api.merkle_load(&missing);
    assert_eq!(
        api.merkle_len(&loaded),
        0,
        "loading a nonexistent cache cold-starts to 0 entries"
    );
    assert!(api.merkle_is_empty(&loaded), "cold-start index is empty");
}

#[test]
fn save_load_with_spec_gate_matches_and_invalidates() {
    let api = TestApi;
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("spec.idx");

    let spec_a: [u8; 32] = [7u8; 32];
    let spec_b: [u8; 32] = [9u8; 32];

    let idx = api.merkle_empty();
    let h = api.merkle_hash_content(b"gated content");
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("g.rs"), 33, 13, h);
    // `save_with_spec` is a `pub` method on the index value.
    idx.save_with_spec(&cache, &spec_a)
        .expect("spec-tagged save must succeed");

    // Same spec => cache trusted, entry present.
    let same = api.merkle_load_with_spec(&cache, &spec_a);
    assert_eq!(api.merkle_len(&same), 1, "matching spec keeps the entry");
    assert_eq!(
        api.merkle_lookup(&same, std::path::Path::new("g.rs")),
        Some((33, 13, h)),
        "matching spec preserves the exact tuple"
    );

    // Different spec => whole cache invalidated (cold start).
    let changed = api.merkle_load_with_spec(&cache, &spec_b);
    assert_eq!(
        api.merkle_len(&changed),
        0,
        "a changed detector spec invalidates the entire cache"
    );
    assert!(
        api.merkle_is_empty(&changed),
        "spec mismatch cold-starts to an empty index"
    );
}

// ── forget + cap: invalidation and bounded growth ─────────────────────────

#[test]
fn forget_removes_entry_and_reexposes_as_new() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("has/secret.rs");
    let content = b"AWS_SECRET_ACCESS_KEY=xxxxxxxx";

    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            1,
            content.len() as u64,
            content
        ),
        "first sighting is new"
    );
    assert_eq!(api.merkle_len(&idx), 1, "one cached entry");

    // A file that produced a finding is forgotten so it is always re-scanned.
    idx.forget(&path);
    assert_eq!(api.merkle_len(&idx), 0, "forget drops the entry");
    assert!(api.merkle_is_empty(&idx), "index empty after forget");
    assert_eq!(
        api.merkle_lookup(&idx, &path),
        None,
        "forgotten path is absent"
    );

    // Re-observing it is treated as brand new (not silently skipped).
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            1,
            content.len() as u64,
            content
        ),
        "after forget the same content is once again NEW"
    );
}

#[test]
fn entry_cap_blocks_new_paths_but_allows_updates() {
    let api = TestApi;
    let idx = api.merkle_with_max_entries(2);
    assert_eq!(
        api.merkle_max_entries(&idx),
        2,
        "cap is honored on construction"
    );

    let h0 = api.merkle_hash_content(b"zero");
    let h1 = api.merkle_hash_content(b"one");
    let h2 = api.merkle_hash_content(b"two");
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("p0"), 1, 4, h0);
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("p1"), 2, 3, h1);
    assert_eq!(api.merkle_len(&idx), 2, "cap reached at two entries");

    // A THIRD new path is dropped (cap reached), not cached.
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("p2"), 3, 3, h2);
    assert_eq!(api.merkle_len(&idx), 2, "new path over cap is dropped");
    assert_eq!(
        api.merkle_lookup(&idx, std::path::Path::new("p2")),
        None,
        "the over-cap path was not cached"
    );

    // Updating an EXISTING path always succeeds (does not grow the set).
    let h0b = api.merkle_hash_content(b"zero-updated");
    api.merkle_record_with_metadata(&idx, std::path::PathBuf::from("p0"), 5, 12, h0b);
    assert_eq!(api.merkle_len(&idx), 2, "update does not add an entry");
    assert_eq!(
        api.merkle_lookup(&idx, std::path::Path::new("p0")),
        Some((5, 12, h0b)),
        "existing entry updated in place even at cap"
    );
}

#[test]
fn distinct_chunk_offsets_are_independent_entries() {
    let api = TestApi;
    let idx = api.merkle_empty();
    let path = std::path::PathBuf::from("big/blob.bin");
    let chunk0 = b"first 4KiB worth of bytes";
    let chunk1 = b"second 4KiB worth of bytes";

    // Two chunks of the SAME path at different offsets are separate rows.
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            9,
            8_192,
            chunk0
        ),
        "chunk @0 is new"
    );
    assert!(
        !api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            4_096,
            9,
            8_192,
            chunk1
        ),
        "chunk @4096 is new (independent of @0)"
    );
    assert_eq!(api.merkle_len(&idx), 2, "one path, two chunk rows");

    // Re-recording chunk @0 unchanged returns true without disturbing @4096.
    assert!(
        api.merkle_record_chunk_at_offset_and_check_unchanged(
            &idx,
            path.clone(),
            0,
            9,
            8_192,
            chunk0
        ),
        "chunk @0 recognized unchanged"
    );
    assert_eq!(api.merkle_len(&idx), 2, "still two chunk rows");

    // forget(path) evicts ALL chunks of the file at once.
    idx.forget(&path);
    assert_eq!(
        api.merkle_len(&idx),
        0,
        "forget removes every chunk row for the path"
    );
}
