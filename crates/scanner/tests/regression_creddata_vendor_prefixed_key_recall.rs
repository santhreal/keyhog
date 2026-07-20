//! Regression contract for KH-L-0416: the vendor-prefixed `*_key` / `*_secret`
//! / `*_token` keyword-bridge generation arm (close-recall lane, task #24).
//!
//! ROOT GAP (measured on the shipped v0.5.40 release binary BEFORE this change):
//! the detector-owned generic keyword bridge (`engine::phase2_generic` +
//! `KEYWORD_AC` prefilter) enumerated a FIXED stem list, so the dominant CredData
//! "Key" anchor shape, a `<vendor>_<noun>_key`-style identifier whose stem is
//! NOT one of the enumerated literals, never produced a candidate even on a
//! high-entropy RANDOM value. Proven never-candidate on the release binary:
//!   app_key=          -> 0 findings
//!   consumer_key:     -> 0 findings
//!   aes_key =         -> 0 findings   (not even bridged for a random value)
//!   application_key=  -> 0 findings
//! while the enumerated siblings (`api_key=`, `access_key=`, `secret_key=`,
//! `encryption_key=`) surfaced. The CredData "Key" class is the LARGEST positive
//! category (3802 labeled positives) and is anchored overwhelmingly by this
//! `*_key` family (`ovh_consumer_key`, `kubeadm_certificate_key`,
//! `github_enterprise_org_key`, `app_key`, `consumer_key`, …).
//!
//! THE FIX (candidate generation only, no scoring/suppression internals
//! touched): a trailing `GENERIC_RE` alternation arm admits a 1..=3-segment
//! lowercase identifier ending in a `[._-](?:key|secret|token)` suffix, plus a
//! local bare-`key` literal in the generic-bridge `KEYWORD_AC` prefilter so the
//! line reaches the regex. Group 1 still captures the FULL keyword, so the
//! whole-word boundary, the `pass`-guard, and the strong-keyword hex-key
//! exemption all see a coherent token. Precision is carried downstream by the
//! UNCHANGED shape gauntlet (entropy floor / identifier / prose / placeholder /
//! base64-blob / hash-digest gates).
//!
//! These are PASSING regression tests: each new class surfaces on a
//! representative RANDOM positive and does NOT surface on its dictionary /
//! placeholder / no-separator negative twin. Assertions check the exact
//! detector_id AND the exact surfaced credential bytes (never `!is_empty`).

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// All surfaced (detector_id, credential, confidence) triples for `text`.
fn matches(s: &CompiledScanner, chunk: &Chunk) -> Vec<(String, String, f64)> {
    s.clear_fragment_cache();
    s.scan(chunk)
        .into_iter()
        .map(|m| {
            (
                m.detector_id.to_string(),
                m.credential.as_str().to_string(),
                m.confidence.unwrap_or(0.0),
            )
        })
        .collect()
}

/// True iff SOME surfaced match carries exactly `credential` (whole value, not a
/// substring) under the `generic-secret` detector (the bridge's emit id).
fn generic_secret_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    matches(&s, &chunk)
        .iter()
        .any(|(id, cred, _)| id == "generic-secret" && cred == credential)
}

/// True iff NOTHING surfaces the exact `credential` value (under any detector).
fn nothing_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    !matches(&s, &chunk)
        .iter()
        .any(|(_, cred, _)| cred == credential)
}

// ── POSITIVES: the vendor-prefixed `*_key` family now generates a candidate ──

#[test]
fn aes_key_random_value_surfaces() {
    // `aes_key = <random>` was proven never-candidate on the release binary
    // (the keyword hit NO prefilter literal). A random base62 value clears the
    // entropy floor and every shape gate.
    let cred = "Xy9KmPq2LvWnB7tRsYz3BcDe";
    assert!(
        generic_secret_surfaces(&format!("aes_key = \"{cred}\""), cred),
        "aes_key=<random> must surface as generic-secret (CredData Key anchor family)"
    );
}

#[test]
fn app_key_random_value_surfaces() {
    let cred = "p2Qw7RtVy1Bn6Kc4mLp9qL2";
    assert!(
        generic_secret_surfaces(&format!("app_key={cred}"), cred),
        "app_key=<random> must surface (Laravel/Pusher APP_KEY shape)"
    );
}

#[test]
fn consumer_key_random_value_surfaces() {
    let cred = "zK4mP9qL2vW7nB3tR8sY1cDe";
    assert!(
        generic_secret_surfaces(&format!("consumer_key: {cred}"), cred),
        "consumer_key:<random> must surface (OAuth1 / WooCommerce CONSUMER_KEY)"
    );
}

#[test]
fn vendor_prefixed_application_key_surfaces() {
    // Multi-segment vendor prefix: use a non-service-owned application key so
    // this isolates the generic bridge instead of a named detector's OVH owner.
    let cred = "h84mLpQw7RtVy1Bn6Kc4Dd";
    assert!(
        generic_secret_surfaces(&format!("internal_application_key={cred}"), cred),
        "internal_application_key=<random> must surface (multi-segment vendor _key)"
    );
}

#[test]
fn rotation_key_random_value_surfaces() {
    // A pure `*_key` name with NO enumerated-stem substring: `rotation_key`
    // (canon `rotationkey`) contains none of `secret`/`token`/`apikey`/
    // `accesskey`/`encryptionkey`/…, so it reached NO prefilter literal before
    // the local bare-`key` augment + the new alternation arm. It is the cleanest
    // proof that the new arm, not a pre-existing substring match, adds the
    // candidate. (`*_secret` names were already covered by the `secret`
    // substring arm, so they do not isolate the new behaviour.)
    let cred = "Rt8Vy3Bn6Kc4mLp9qL2vW7n";
    assert!(
        generic_secret_surfaces(&format!("rotation_key = \"{cred}\""), cred),
        "rotation_key=<random> must surface (pure new-arm _key, no enumerated substring)"
    );
}

// ── NEGATIVE TWINS: precision held, the gap closes WITHOUT new FPs ──

#[test]
fn dictionary_word_value_does_not_surface() {
    // A dictionary value under the same new anchor must stay suppressed: the
    // bridge generates the candidate but the prose/identifier gauntlet drops it.
    assert!(
        nothing_surfaces(
            "app_key=correcthorsebatterystaple",
            "correcthorsebatterystaple"
        ),
        "a dictionary-word value under app_key must NOT surface (gauntlet drops it)"
    );
}

#[test]
fn placeholder_value_does_not_surface() {
    assert!(
        nothing_surfaces("consumer_key: changeme", "changeme"),
        "a placeholder value under consumer_key must NOT surface"
    );
}

#[test]
fn no_separator_before_key_does_not_surface() {
    // `monkey`/`keyboard` reach the prefilter (bare `key` literal) but the regex
    // arm requires a `[._-]` separator immediately before `key`, so they produce
    // NO candidate (the precision guard that makes the bare-`key` prefilter safe).
    assert!(
        nothing_surfaces("monkey=Xy9KmPq2LvWnB7tRsYz3", "Xy9KmPq2LvWnB7tRsYz3"),
        "`monkey=` (no separator before `key`) must NOT generate a candidate"
    );
    assert!(
        nothing_surfaces("keyboard=Xy9KmPq2LvWnB7tRsYz3", "Xy9KmPq2LvWnB7tRsYz3"),
        "`keyboard=` (no separator before `key`) must NOT generate a candidate"
    );
}

// ── hex32/48 AES-key exemption now reaches the vendor-prefixed family ──

#[test]
fn aes_key_hex32_surfaces_via_generalized_exemption() {
    // hex32 AES-128 key under `aes_key`: the active detector's
    // `canonical_hex_key_material` suffix policy releases the bare-hex-digest
    // shape gate for length 32 (the mirror plants NO hex32 hash decoy).
    let cred = "200cbbe4d5f76059b65ce82c10484863"; // 32 hex
    assert_eq!(cred.len(), 32);
    assert!(
        generic_secret_surfaces(&format!("aes_key = {cred}"), cred),
        "aes_key=<hex32> must surface like encryption_key=<hex32> already does"
    );
}

#[test]
fn vendor_key_hex64_stays_suppressed_sha256_trap() {
    // hex64 == sha256 length: the documented v31 catastrophe (the mirror plants
    // `TOKEN=<64hex>` as BOTH positive AND sha256/git-sha/k8s-uid negative). The
    // exemption is length-gated to 32|48 ONLY, so a 64-hex value under the new
    // anchor MUST stay dropped by the bare-hex-digest gate (precision floor).
    let cred = "200cbbe4d5f76059b65ce82c10484863200cbbe4d5f76059b65ce82c10484863"; // 64 hex
    assert_eq!(cred.len(), 64);
    assert!(
        nothing_surfaces(&format!("aes_key = {cred}"), cred),
        "aes_key=<hex64> must STAY suppressed (sha256 shape trap, not lifted)"
    );
}
