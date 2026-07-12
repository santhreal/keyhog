//! Recall contract for the credential-keyword UNION (task #125).
//!
//! The multiline-fragment and structural reassembly paths decide whether an
//! assignment's variable name is "credential-like" via the UNION of two
//! predicate sets:
//!   * COMPACT  (`normalized_assignment_keyword_is_credential`): exact membership
//!     in a curated compact list (password/token/secret/apikey/privatekey/…)
//!     PLUS the bare entropy anchors `salt`/`nonce`/`seed`/`bearer`/`passphrase`,
//!     PLUS a `*_key`/`*_secret`/`*_token`/`*_password` separated-suffix branch.
//!   * SUFFIX   (`normalized_assignment_keyword_has_secret_suffix`): ANY name
//!     ending in `key`/`secret`/`token`/`password` (so `webhookkey`,
//!     `idempotencytoken` qualify even though they are not in the compact list).
//!
//! Neither set subsumes the other, so the scan must OR them — dropping EITHER
//! silently regresses recall (the SIMD-trigger-union class of bug:
//! backend-parity tests can't catch a missing keyword family). This suite pins:
//!   1. each set recognizes keywords the OTHER misses (both are load-bearing),
//!   2. the real scan-facing union (`fragment_assignment_name_is_credential_like`)
//!      returns true for BOTH sets' unique keywords,
//!   3. the union's deliberate STRICTER exclusions hold: a bare ambiguous owner
//!      (`secret`/`token`/`key`/`password`) and a public-metadata owner
//!      (`*_dedup_key`) are NOT credential-like even though a raw predicate
//!      matches them, while a fragment suffix (`secret_part2`) RE-enables them.

use keyhog_scanner::testing::{
    fragment_assignment_name_is_credential_like_for_test as union,
    normalized_assignment_keyword_has_secret_suffix_for_test as suffix_set,
    normalized_assignment_keyword_is_credential_for_test as compact_set,
};

// ── COMPACT-set unique keywords (SUFFIX set misses them) ────────────────────
// These entropy anchors have no `key`/`secret`/`token`/`password` suffix, so
// only the compact list recognizes them. If the compact predicate were dropped
// from the union, these would silently stop reassembling.

#[test]
fn compact_unique_salt() {
    assert!(compact_set("salt"));
    assert!(
        !suffix_set("salt"),
        "salt has no secret-suffix; only the compact set catches it"
    );
}
#[test]
fn compact_unique_nonce() {
    assert!(compact_set("nonce"));
    assert!(!suffix_set("nonce"));
}
#[test]
fn compact_unique_seed() {
    assert!(compact_set("seed"));
    assert!(!suffix_set("seed"));
}
#[test]
fn compact_unique_bearer() {
    assert!(compact_set("bearer"));
    assert!(!suffix_set("bearer"));
}
#[test]
fn compact_unique_passphrase() {
    assert!(compact_set("passphrase"));
    assert!(!suffix_set("passphrase"));
}

// ── SUFFIX-set unique keywords (COMPACT set misses them) ────────────────────
// Compound names ending in a credential word but absent from the compact list:
// only the suffix predicate recognizes them.

#[test]
fn suffix_unique_webhookkey() {
    assert!(suffix_set("webhookkey"));
    assert!(
        !compact_set("webhookkey"),
        "webhookkey is not in the compact list"
    );
}
#[test]
fn suffix_unique_idempotencytoken() {
    assert!(suffix_set("idempotencytoken"));
    assert!(!compact_set("idempotencytoken"));
}
#[test]
fn suffix_unique_mypassword() {
    assert!(suffix_set("mypassword"));
    assert!(!compact_set("mypassword"));
}
#[test]
fn suffix_unique_foosecret() {
    assert!(suffix_set("foosecret"));
    assert!(!compact_set("foosecret"));
}
#[test]
fn suffix_unique_randomtoken() {
    assert!(suffix_set("randomtoken"));
    assert!(!compact_set("randomtoken"));
}

// ── the real union wires BOTH sets ─────────────────────────────────────────

#[test]
fn union_includes_compact_only_salt() {
    assert!(
        union("salt"),
        "compact-only keyword must reach the scan via the union"
    );
}
#[test]
fn union_includes_compact_only_nonce() {
    assert!(union("nonce"));
}
#[test]
fn union_includes_compact_only_bearer() {
    assert!(union("bearer"));
}
#[test]
fn union_includes_suffix_only_webhookkey() {
    assert!(
        union("webhookkey"),
        "suffix-only keyword must reach the scan via the union"
    );
}
#[test]
fn union_includes_suffix_only_mypassword() {
    assert!(union("mypassword"));
}
#[test]
fn union_includes_suffix_only_foosecret() {
    assert!(union("foosecret"));
}

// ── neither predicate: plain non-credential names stay out ──────────────────

#[test]
fn neither_predicate_host() {
    assert!(!compact_set("host") && !suffix_set("host") && !union("host"));
}
#[test]
fn neither_predicate_region() {
    assert!(!compact_set("region") && !suffix_set("region") && !union("region"));
}
#[test]
fn neither_predicate_version() {
    assert!(!compact_set("version") && !suffix_set("version") && !union("version"));
}
#[test]
fn neither_predicate_count() {
    assert!(!compact_set("count") && !suffix_set("count") && !union("count"));
}
#[test]
fn neither_predicate_endpoint() {
    assert!(!compact_set("endpoint") && !suffix_set("endpoint") && !union("endpoint"));
}

// ── union is STRICTER: bare ambiguous owners are excluded ───────────────────
// A bare `secret`/`token`/`key`/`password` as a FRAGMENT variable name is too
// ambiguous to drive reassembly, so the union drops it even though a raw
// predicate matches the word.

#[test]
fn union_excludes_bare_secret_though_compact_matches() {
    assert!(
        compact_set("secret"),
        "the raw compact predicate matches the word `secret`"
    );
    assert!(
        !union("secret"),
        "but a BARE `secret` var name is too ambiguous for the union"
    );
}
#[test]
fn union_excludes_bare_password_though_both_match() {
    assert!(compact_set("password") && suffix_set("password"));
    assert!(!union("password"));
}
#[test]
fn union_excludes_bare_token_though_compact_matches() {
    assert!(compact_set("token"));
    assert!(!union("token"));
}
#[test]
fn union_excludes_bare_key_though_suffix_matches() {
    assert!(suffix_set("key"));
    assert!(!union("key"));
}

// ── union is STRICTER: public-metadata owners are excluded ──────────────────
// A `*_dedup_key` is a cache-bookkeeping field, not a credential, even though the
// `_key` separated suffix makes the raw compact predicate match it.

#[test]
fn union_excludes_dedup_key_metadata_though_compact_matches() {
    assert!(
        compact_set("cache_dedup_key"),
        "the `_key` separated suffix matches"
    );
    assert!(
        !union("cache_dedup_key"),
        "but `*_dedup_key` is public metadata, not a secret"
    );
}
#[test]
fn union_excludes_digest_suffixed_owner() {
    // `*_digest` is a public integrity field.
    assert!(!union("payload_digest"));
}

// ── fragment suffix RE-enables a bare credential word ───────────────────────
// `secret_part2` / `token_prefix` are split-fragment variable names whose base
// IS a credential word: the union strips the fragment suffix and re-accepts the
// base, so the split secret reassembles (the bare-ambiguous exclusion is lifted
// once a fragment suffix proves intent).

#[test]
fn union_reenables_bare_secret_under_fragment_suffix() {
    assert!(!union("secret"), "bare `secret` is excluded");
    assert!(
        union("secret_part2"),
        "but `secret_part2` is a fragment of a real secret"
    );
}
#[test]
fn union_reenables_bare_token_under_fragment_suffix() {
    assert!(!union("token"));
    assert!(union("token_prefix"));
}

// ── meta: each predicate is INDIVIDUALLY load-bearing for the union ─────────

#[test]
fn dropping_compact_predicate_would_regress_recall() {
    // `salt` reaches the union ONLY through the compact set (the suffix set
    // misses it). If the compact predicate were removed from the union, `salt`
    // assignments would stop reassembling.
    assert!(!suffix_set("salt"));
    assert!(union("salt"));
}
#[test]
fn dropping_suffix_predicate_would_regress_recall() {
    // `webhookkey` reaches the union ONLY through the suffix set (the compact set
    // misses it). Removing the suffix predicate would silently drop the entire
    // `*key`/`*secret`/`*token`/`*password` long-tail.
    assert!(!compact_set("webhookkey"));
    assert!(union("webhookkey"));
}
