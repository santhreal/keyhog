//! Precision/recall contract for the CredData "Key" + "UUID" anchor classes.
//!
//! Measured on the cached full-field CredData run (2026-06-21) the two largest
//! recall sinks are `Key` (3795 positives, recall 0.02) and `UUID` (2267
//! positives, recall 0.00). A naive "boost recall" change would chase both and
//! crater precision. This file pins WHY the current behaviour is correct, with
//! examples drawn from the real corpus, so a future change cannot quietly
//! reopen the v31-class catastrophe.
//!
//! Empirically verified (single-file scans of the shipped pipeline):
//!   * STRONG, unambiguous anchors (`secret_key`, `private_key`,
//!     `encryption_key`, `client_secret`, `apikey`, `masterkey`,
//!     `signing_key`, `access_key`) carrying a canonical hex32/hex48 key DO
//!     surface — keyhog's credential detection works; these are the recall we
//!     hold and must not regress.
//!   * BARE, standalone `key`/`Key` (no `[._-]` vendor prefix) does NOT promote
//!     a hex value: a bare `key = <32hex>` is indistinguishable from an MD5
//!     digest / map key / ETag, so admitting it would flood real code with FPs.
//!     This is the precision boundary that separates `secret_key = <hex>`
//!     (real) from `Key = <hex>` (ambiguous) — the dominant CredData `Key`
//!     key-dump shape, deliberately declined.
//!   * hex64 (sha256) and hex128 (sha512) lengths stay suppressed even under a
//!     strong anchor — hash-shape traps the mirror plants as negatives.
//!   * The CredData `UUID` class is NOT credentials: the labelled positives are
//!     `X-Request-Id`, `session_id`, record `id`, `collectionId`,
//!     `client-request-id` — identifiers, not secrets. keyhog correctly
//!     declines every one; flagging them would devastate precision on real
//!     code. The benchmark's `UUID` recall sink is ground-truth pollution, not
//!     a keyhog gap.
//!
//! Every assertion checks the exact surfaced/absent credential bytes via the
//! shared `generic_secret_surfaces` / `nothing_surfaces` helpers — never
//! `!is_empty`.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// All surfaced (detector_id, credential) pairs for `text`.
fn matches(s: &CompiledScanner, chunk: &Chunk) -> Vec<(String, String)> {
    s.clear_fragment_cache();
    s.scan(chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}

/// True iff SOME surfaced match carries exactly `credential` (whole value).
fn surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    matches(&s, &chunk)
        .iter()
        .any(|(_, cred)| cred == credential)
}

/// True iff NOTHING surfaces the exact `credential` value (under any detector).
fn nothing_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    !matches(&s, &chunk)
        .iter()
        .any(|(_, cred)| cred == credential)
}

// ── POSITIVES: strong, unambiguous anchors carry canonical hex keys ──────────
// Distinct high-entropy hex per test so nothing dedupes; lengths 32 (AES-128)
// and 48 (AES-192) are the canonical key sizes the mirror plants no hash decoy
// for, so the strong-keyword hex exemption admits them.

#[test]
fn secret_key_hex32_surfaces() {
    let cred = "1868845451a4c85adb078195b768135b"; // 32 hex
    assert_eq!(cred.len(), 32);
    assert!(
        surfaces(&format!("secret_key = {cred}"), cred),
        "secret_key=<hex32> is a real AES-128 key and must surface"
    );
}

#[test]
fn secret_key_hex48_surfaces() {
    let cred = "13c1aec76ef653d331bec431e9adbdc9ecaa2101b770789c"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        surfaces(&format!("secret_key = {cred}"), cred),
        "secret_key=<hex48> is a real AES-192 key and must surface"
    );
}

#[test]
fn private_key_hex48_surfaces() {
    let cred = "a44abd716dcf62625c3179b5a54a80057ca3ecf068b12517"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        surfaces(&format!("private_key = {cred}"), cred),
        "private_key=<hex48> must surface"
    );
}

#[test]
fn encryption_key_hex48_surfaces() {
    let cred = "a00f9523e086f674244524b2fb5fda7b11fb178807d8f31b"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        surfaces(&format!("encryption_key = {cred}"), cred),
        "encryption_key=<hex48> must surface"
    );
}

#[test]
fn client_secret_hex48_surfaces() {
    let cred = "57849c3a6e66d5aa5a093e668281c83c7ae56413157bf221"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        surfaces(&format!("client_secret = {cred}"), cred),
        "client_secret=<hex48> must surface"
    );
}

#[test]
fn apikey_hex32_surfaces() {
    let cred = "3481e3edd3faed0d84d122b98641e99c"; // 32 hex
    assert_eq!(cred.len(), 32);
    assert!(
        surfaces(&format!("apikey = {cred}"), cred),
        "apikey=<hex32> must surface"
    );
}

#[test]
fn masterkey_hex32_surfaces() {
    let cred = "cfe4686f15cc9c31aebe89fb7923b0f5"; // 32 hex
    assert_eq!(cred.len(), 32);
    assert!(
        surfaces(&format!("masterkey = {cred}"), cred),
        "masterkey=<hex32> must surface"
    );
}

#[test]
fn signing_key_hex48_surfaces() {
    let cred = "2fe21a6c1bac6df7d2931af2dc00b6acb8a19cc50133e558"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        surfaces(&format!("signing_key = {cred}"), cred),
        "signing_key=<hex48> must surface"
    );
}

#[test]
fn access_key_hex48_surfaces() {
    let cred = "7d2931af2dc00b6acb8a19cc50133e5582fe21a6c1bac6df"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        surfaces(&format!("access_key = {cred}"), cred),
        "access_key=<hex48> must surface"
    );
}

// ── NEGATIVE: bare standalone `key`/`Key` is too ambiguous to promote a hex ──
// The dominant CredData `Key` key-dump shape is a bare `Key = <hex>`. A bare
// `key`/`Key` has no `[._-]key` vendor prefix and is not an enumerated strong
// stem, so it must NOT promote a hex value — a 32-hex bare `key` is
// indistinguishable from an MD5 digest, an ETag, or a map key.

#[test]
fn bare_lowercase_key_hex32_stays_suppressed() {
    let cred = "5de7d7b8d870bd5c0bce613f491b34e1"; // 32 hex, real CredData Key miss
    assert_eq!(cred.len(), 32);
    assert!(
        nothing_surfaces(&format!("key = {cred}"), cred),
        "bare `key = <hex32>` must STAY suppressed (MD5/ETag/map-key collision)"
    );
}

#[test]
fn bare_capitalized_key_hex32_stays_suppressed() {
    let cred = "8a407737dcc56329d82ef722d5ab0591"; // 32 hex, real CredData Key miss
    assert_eq!(cred.len(), 32);
    assert!(
        nothing_surfaces(&format!("Key = {cred}"), cred),
        "bare `Key = <hex32>` (the CredData key-dump shape) must STAY suppressed"
    );
}

#[test]
fn bare_lowercase_key_hex48_stays_suppressed() {
    let cred = "6d038fcf5ec379c918ae0b00c0ab7a81614a16796329cd09"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        nothing_surfaces(&format!("key = {cred}"), cred),
        "bare `key = <hex48>` must STAY suppressed — bare `key` is ambiguous at \
         any length, unlike the `*_key` vendor family"
    );
}

#[test]
fn bare_capitalized_key_hex48_stays_suppressed() {
    let cred = "1db3a6923b02eda467ac2b3310822ae002648ee2124bab67"; // 48 hex
    assert_eq!(cred.len(), 48);
    assert!(
        nothing_surfaces(&format!("Key = {cred}"), cred),
        "bare `Key = <hex48>` must STAY suppressed"
    );
}

// ── NEGATIVE: hash-length traps stay suppressed even under a strong anchor ──

#[test]
fn strong_anchor_hex64_stays_suppressed_sha256_trap() {
    let cred = "61af0357c77fc447770acc7575b97e6b4d9c4d521f07c93c9c24db811f9d0825"; // 64 hex
    assert_eq!(cred.len(), 64);
    assert!(
        nothing_surfaces(&format!("secret_key = {cred}"), cred),
        "secret_key=<hex64> must STAY suppressed (sha256/git-sha shape trap)"
    );
}

#[test]
fn strong_anchor_hex128_stays_suppressed_sha512_trap() {
    let cred = "b2f2f39ef216130a60a0b5e6a143bea42a541f9e1b1896026c45ddbbf161b26c\
                a28aaf4867c27e9e8549dbdf3adf7e95ac06028a75f1935a21100159d55cba7b"; // 128 hex
    assert_eq!(cred.len(), 128);
    assert!(
        nothing_surfaces(&format!("secret_key = {cred}"), cred),
        "secret_key=<hex128> must STAY suppressed (sha512 shape trap)"
    );
}

// ── NEGATIVE: the CredData `UUID` class is identifiers, not credentials ──────
// Every value below is a verbatim shape from the corpus's UUID positives. A
// UUID is a non-secret identifier; promoting any of these would devastate
// precision on real code (every request id, session id, record id flagged).

const UUID_A: &str = "b15decee-d2f0-15f2-0f1c-fcbb05d0bb15";
const UUID_B: &str = "40177189-bd87-30a9-c157-d92d35a65163";
const UUID_C: &str = "816e0fc4-13d7-eb52-82d0-213b56b477c4";

#[test]
fn uuid_under_bare_id_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("id = {UUID_A}"), UUID_A),
        "a record `id = <uuid>` is not a secret and must STAY suppressed"
    );
}

#[test]
fn uuid_under_session_id_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("session_id={UUID_A}"), UUID_A),
        "`session_id=<uuid>` is a session identifier, not a credential"
    );
}

#[test]
fn uuid_under_client_id_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("client_id: {UUID_B}"), UUID_B),
        "`client_id:<uuid>` is a public client identifier, not a secret"
    );
}

#[test]
fn uuid_request_id_header_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("X-Request-Id: {UUID_B}"), UUID_B),
        "an `X-Request-Id` header value is a trace id, not a credential"
    );
}

#[test]
fn uuid_collection_id_field_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("\"collectionId\": \"{UUID_C}\""), UUID_C),
        "a `collectionId` field value is a record id, not a secret"
    );
}

#[test]
fn bare_uuid_array_element_stays_suppressed() {
    assert!(
        nothing_surfaces(&format!("        \"{UUID_C}\","), UUID_C),
        "a bare UUID array element is an identifier, not a credential"
    );
}

#[test]
fn uuid_under_strong_secret_anchor_stays_suppressed() {
    // Even under a strong `client_secret` anchor, a UUID-SHAPED value is not a
    // hex key (dashes fail the hex gate) and is not a real secret here — the
    // shape gauntlet declines it. Pins that the strong-anchor recall lane does
    // NOT become a UUID promoter.
    assert!(
        nothing_surfaces(&format!("client_secret = {UUID_A}"), UUID_A),
        "a UUID-shaped value under client_secret must STAY suppressed"
    );
}
