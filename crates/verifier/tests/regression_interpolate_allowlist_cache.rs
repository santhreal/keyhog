//! Regression coverage for the verifier's template-interpolation expansion and
//! the verification (allowlist) cache, deliberately DISTINCT from
//! `new_verifier_interpolate.rs` and `new_verifier_allowlist_cache.rs`.
//!
//! Focus areas the sibling files do NOT cover:
//!   - a `{{var}}` template expanding to the EXACT outbound URL, including
//!     percent-encoding of structural bytes and repeated tokens,
//!   - an *undefined* placeholder: unrecognized tokens preserved verbatim,
//!     unterminated `{{` preserved verbatim, missing companion rendered empty,
//!   - the one-pass inertness guarantee: a credential whose scanned value is
//!     itself a `{{companion.*}}` token is NOT re-expanded (no cross-companion
//!     secret leak),
//!   - the `{{interactsh.id}}` token and no-scheme / hostile-scheme OOB URL,
//!   - the exact allowlist rejection error string,
//!   - the cache returning the EXACT cached verdict on repeat, overwrite
//!     (in-place invalidation), FIFO queue accounting, and metadata caps.
//!
//! Every assertion pins a concrete value: an exact rendered string, an exact
//! `VerificationResult` variant, an exact count, or a specific error substring.

use keyhog_core::{VerificationResult, VerifySpec};
use keyhog_verifier::testing::{
    TestApi, TestVerificationCache as VerificationCache, VerifierTestApi, VerifierTestCache,
};
use std::collections::HashMap;
use std::time::Duration;

const OOB_COMPANION_URL: &str = <TestApi as VerifierTestApi>::OOB_COMPANION_URL;
const OOB_COMPANION_ID: &str = <TestApi as VerifierTestApi>::OOB_COMPANION_ID;

fn companions(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn spec(service: &str, allowed: &[&str]) -> VerifySpec {
    VerifySpec {
        service: service.to_string(),
        allowed_domains: allowed.iter().map(|s| s.to_string()).collect(),
        ..VerifySpec::default()
    }
}

// ===========================================================================
// {{var}} -> exact URL expansion (percent-encoding + repeated tokens)
// ===========================================================================

#[test]
fn interpolate_url_var_expands_to_exact_encoded_url() {
    let c = companions(&[]);
    // Space -> %20, colon -> %3A, slash -> %2F under NON_ALPHANUMERIC encoding.
    assert_eq!(
        TestApi.interpolate_url("https://api.svc.example/verify/{{match}}", "tok en:v/1", &c),
        "https://api.svc.example/verify/tok%20en%3Av%2F1",
        "embedded {{match}} in a URL must percent-encode every structural byte"
    );
}

#[test]
fn interpolate_url_repeated_match_encodes_each_occurrence() {
    let c = companions(&[]);
    assert_eq!(
        TestApi.interpolate_url("https://h/{{match}}/x/{{match}}", "a b", &c),
        "https://h/a%20b/x/a%20b",
        "each {{match}} occurrence is independently encoded in one pass"
    );
}

// ===========================================================================
// undefined placeholders, verbatim / empty, never an expansion or a panic
// ===========================================================================

#[test]
fn interpolate_unrecognized_token_is_preserved_verbatim() {
    let c = companions(&[]);
    // Not match / interactsh / companion.* -> emitted exactly as written.
    assert_eq!(
        TestApi.interpolate("a{{totally_undefined}}b", "cred", &c),
        "a{{totally_undefined}}b"
    );
    assert_eq!(
        TestApi.interpolate("{{no_such_var}}", "cred", &c),
        "{{no_such_var}}"
    );
}

#[test]
fn interpolate_unterminated_open_brace_is_preserved_verbatim() {
    let c = companions(&[]);
    // No closing `}}` after the last `{{`: the entire remainder is copied as-is.
    assert_eq!(
        TestApi.interpolate_url("https://h/path {{match", "TOK", &c),
        "https://h/path {{match"
    );
    // A valid token followed by an unterminated one: first expands, tail verbatim.
    assert_eq!(
        TestApi.interpolate_url("{{match}} then {{oops", "TOK", &c),
        "TOK then {{oops"
    );
}

#[test]
fn interpolate_undefined_companion_renders_empty_in_url() {
    let c = companions(&[("present", "x")]);
    assert_eq!(
        TestApi.interpolate_url("https://h/?k={{companion.absent}}&z=1", "cred", &c),
        "https://h/?k=&z=1",
        "an undefined companion must render to the empty string, never leak another value"
    );
}

// ===========================================================================
// one-pass inertness, a credential that IS a {{companion.*}} token must not
// be re-expanded into a *different* companion secret.
// ===========================================================================

#[test]
fn interpolate_http_value_credential_carrying_token_is_inert() {
    let c = companions(&[("leak", "OTHER_SECRET")]);
    // The scanned credential literally equals a companion token. The single
    // left-to-right pass substitutes it once and never re-reads it, so the
    // braces survive as inert text. OTHER_SECRET is NOT exfiltrated.
    assert_eq!(
        TestApi.interpolate_http_value("X-Auth: {{match}}", "{{companion.leak}}", &c),
        "X-Auth: {{companion.leak}}",
        "a substituted value must never be re-expanded (cross-companion leak guard)"
    );
}

// ===========================================================================
// OOB tokens, id token + no-scheme / hostile-scheme URL sanitization
// ===========================================================================

#[test]
fn interpolate_interactsh_id_token_substituted_and_dns_sanitized() {
    let mut c = companions(&[]);
    c.insert(OOB_COMPANION_ID.to_string(), "Corr-ID_9/9".to_string());
    // Uppercase folded, underscore + slash (outside [a-z0-9.-]) dropped.
    assert_eq!(
        TestApi.interpolate("id={{interactsh.id}}", "cred", &c),
        "id=corr-id99"
    );
}

#[test]
fn interpolate_oob_url_without_scheme_is_sanitized_whole() {
    let mut c = companions(&[]);
    c.insert(OOB_COMPANION_URL.to_string(), "ABC.OOB.Example".to_string());
    assert_eq!(
        TestApi.interpolate("{{interactsh.url}}", "cred", &c),
        "abc.oob.example",
        "a URL companion with no scheme is DNS-charset sanitized in full"
    );
}

#[test]
fn interpolate_oob_url_non_alphabetic_scheme_is_collapsed() {
    let mut c = companions(&[]);
    // `ht9tp` is not purely alphabetic -> not treated as a scheme; the whole
    // value (including the `://`) is DNS-charset filtered, so the delimiters die.
    c.insert(
        OOB_COMPANION_URL.to_string(),
        "ht9tp://Evil.Com".to_string(),
    );
    assert_eq!(
        TestApi.interpolate("{{interactsh.url}}", "cred", &c),
        "ht9tpevil.com",
        "a fake numeric scheme must not smuggle `://` structural bytes through"
    );
}

// ===========================================================================
// allowlist rejection, exact error string
// ===========================================================================

#[test]
fn check_url_offlist_host_reports_exact_error() {
    let s = spec("gitlab", &[]);
    let err = TestApi
        .check_url_against_spec("https://exfil.attacker.example/steal", &s)
        .expect_err("off-allowlist host must be blocked");
    assert!(err.starts_with("blocked: host "), "err: {err}");
    assert!(err.contains("exfil.attacker.example"), "err: {err}");
    assert!(err.contains("not in the allowlist"), "err: {err}");
    assert!(err.contains("service 'gitlab'"), "err: {err}");
    assert!(
        err.contains("gitlab.com"),
        "must list the allowed apex: {err}"
    );
}

#[test]
fn check_url_allows_builtin_subdomain_exactly_ok() {
    let s = spec("gitlab", &[]);
    // api.gitlab.com is a subdomain of the builtin gitlab.com -> Ok(()).
    assert_eq!(
        TestApi.check_url_against_spec("https://api.gitlab.com/api/v4/user", &s),
        Ok(())
    );
}

// ===========================================================================
// verification cache, exact cached verdict, overwrite invalidation, queue,
// metadata caps.
// ===========================================================================

#[test]
fn cache_returns_exact_verdict_on_repeat_reads() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    cache.put(
        "cred-A",
        "det-A",
        VerificationResult::Revoked,
        HashMap::new(),
    );

    let first = cache.get("cred-A", "det-A").expect("first hit");
    let second = cache.get("cred-A", "det-A").expect("second hit");
    assert_eq!(first.0, VerificationResult::Revoked);
    assert_eq!(second.0, VerificationResult::Revoked);
    // A non-expired read never removes the entry.
    assert_eq!(cache.len(), 1);
}

#[test]
fn cache_overwrite_same_key_updates_verdict_in_place() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    cache.put("cred", "det", VerificationResult::Live, HashMap::new());
    // Re-verify: the credential is now revoked. Overwrite must replace, not add.
    cache.put("cred", "det", VerificationResult::Dead, HashMap::new());

    assert_eq!(
        cache.get("cred", "det").map(|(r, _)| r),
        Some(VerificationResult::Dead),
        "the newest verdict wins for the same (credential, detector) key"
    );
    assert_eq!(cache.len(), 1, "overwrite must not grow the map");
    assert_eq!(
        cache.queue_len(),
        2,
        "overwrite refreshes recency: a new generation marker is enqueued and \
         the old marker becomes stale (skipped lazily by eviction, swept by \
         reconcile), the MAP must not grow, the queue may hold one stale marker"
    );
}

#[test]
fn capacity_eviction_prefers_stale_slot_over_refreshed_entry() {
    // THE eviction-order bug this queue design fixes: a re-verified credential
    // used to keep its ORIGINAL queue position, so capacity eviction dropped
    // the freshest entry first and forced a redundant live re-verification.
    let cache = VerificationCache::with_max_entries(Duration::from_secs(60), 2);
    cache.put("refreshed", "det", VerificationResult::Live, HashMap::new());
    cache.put("stale", "det", VerificationResult::Live, HashMap::new());
    // Refresh the first key: its recency moves BEHIND "stale".
    cache.put("refreshed", "det", VerificationResult::Dead, HashMap::new());
    // Capacity 2 exceeded: the oldest CURRENT marker is now "stale".
    cache.put("newest", "det", VerificationResult::Live, HashMap::new());

    assert_eq!(cache.len(), 2, "capacity bound enforced");
    assert_eq!(
        cache.get("refreshed", "det").map(|(r, _)| r),
        Some(VerificationResult::Dead),
        "the refreshed entry must SURVIVE capacity eviction (its stale marker \
         is skipped; its refreshed verdict is the one retained)"
    );
    assert!(
        cache.get("stale", "det").is_none(),
        "the genuinely oldest entry is the one evicted"
    );
    assert!(
        cache.get("newest", "det").is_some(),
        "the newest insert is retained"
    );
}

#[test]
fn cache_queue_tracks_distinct_inserts() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    cache.put("c0", "d", VerificationResult::Live, HashMap::new());
    cache.put("c1", "d", VerificationResult::Dead, HashMap::new());
    cache.put("c2", "d", VerificationResult::RateLimited, HashMap::new());
    assert_eq!(cache.len(), 3);
    assert_eq!(cache.queue_len(), 3, "each distinct insert enqueues once");
}

#[test]
fn cache_metadata_entry_count_capped_at_sixteen() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    let mut md = HashMap::new();
    for i in 0..20 {
        md.insert(format!("k{i}"), format!("v{i}"));
    }
    cache.put("cred", "det", VerificationResult::Live, md);
    let (_, meta) = cache.get("cred", "det").expect("hit");
    assert_eq!(
        meta.len(),
        16,
        "metadata must be capped at MAX_METADATA_ENTRIES = 16"
    );
}

#[test]
fn cache_metadata_value_truncated_to_256_bytes() {
    let cache = VerificationCache::new(Duration::from_secs(60));
    let mut md = HashMap::new();
    md.insert("k".to_string(), "a".repeat(300));
    cache.put("cred", "det", VerificationResult::Live, md);
    let (_, meta) = cache.get("cred", "det").expect("hit");
    assert_eq!(
        meta.get("k").map(String::len),
        Some(256),
        "an over-long metadata value must be truncated to 256 bytes"
    );
    assert_eq!(
        meta.get("k").map(String::as_str),
        Some("a".repeat(256).as_str())
    );
}

#[test]
fn cache_evict_expired_reconciles_queue_to_zero() {
    // Zero TTL: entries are born already expired.
    let cache = VerificationCache::new(Duration::from_secs(0));
    cache.put("a", "d", VerificationResult::Live, HashMap::new());
    cache.put("b", "d", VerificationResult::Dead, HashMap::new());
    assert_eq!(cache.queue_len(), 2, "both inserts enqueue before eviction");

    cache.evict_expired();
    assert_eq!(cache.len(), 0, "expired entries dropped from the map");
    assert_eq!(
        cache.queue_len(),
        0,
        "the FIFO queue must be reconciled so it never dangles past the map"
    );
}
