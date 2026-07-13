//! #104 CredData strong-anchor hex-key boundary, grounded in the live miss
//! profiler (`benchmarks/bench/creddata_miss_analysis.py keywords`).
//!
//! That job buckets every CredData hex32/hex48 value by canonical assignment
//! keyword and reports the precision a surfacing rule would inherit:
//!   key          POS 2266  NEG 30   prec 0.987   (the dominant headroom)
//!   sharedsecret POS   84  NEG  0   prec 1.000
//!   apikey       POS   14  NEG  0   prec 1.000
//!   secret/token POS  ~10  NEG ~1
//!
//! keyhog's `is_strong_keyword_anchored_hex_key` exempts a 32/48-hex value from
//! the hash-digest suppression ONLY under a strong cryptographic anchor, any
//! `*key`/`*secret`-suffixed keyword (so `shared_secret`, `app_secret`,
//! `webhook_secret` are all captured via the suffix rule), plus an enumerated
//! exact set, EXCLUDING `licensekey`. It deliberately declines the bare `key`
//! class (98.7% precision on the curated corpus, but `key = <32hex>` is
//! indistinguishable from an MD5/ETag/cache-key in real code, the v31-class
//! catastrophe) and the ambiguous `token`/`salt`/`auth` anchors.
//!
//! This locks that boundary end to end so a future change can neither silently
//! drop the captured `*secret`/`*key` headroom (recall regression) nor admit the
//! declined bare-`key`/`token`/`salt`/`licensekey` classes (precision blowup).
//! Every assertion checks the exact surfaced/absent credential bytes.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

/// Deterministic, near-uniform lowercase hex of length `n` (a seeded LCG so the
/// nibble distribution is flat → entropy ~4.0 bits/char, well above the generic
/// per-length floor). A miss is then a real keyword/length gap, never a value
/// the entropy gate legitimately drops.
fn hex(n: usize, seed: usize) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut state = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x1234_5678_9ABC_DEF1);
    (0..n)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            H[((state >> 33) & 0xF) as usize] as char
        })
        .collect()
}

fn matches(s: &CompiledScanner, chunk: &Chunk) -> Vec<String> {
    s.clear_fragment_cache();
    s.scan(chunk)
        .into_iter()
        .map(|m| m.credential.to_string())
        .collect()
}

fn surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    matches(&s, &chunk).iter().any(|cred| cred == credential)
}

fn nothing_surfaces(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.conf");
    !matches(&s, &chunk).iter().any(|cred| cred == credential)
}

// ── POSITIVES: `*secret` / `*key`-suffixed anchors carry hex32/48 (captured) ──

#[test]
fn shared_secret_hex48_surfaces() {
    let v = hex(48, 1);
    assert!(
        surfaces(&format!("shared_secret = {v}"), &v),
        "shared_secret=<hex48> must surface"
    );
}

#[test]
fn shared_secret_hex32_surfaces() {
    let v = hex(32, 2);
    assert!(
        surfaces(&format!("shared_secret = {v}"), &v),
        "shared_secret=<hex32> must surface"
    );
}

#[test]
fn sharedsecret_compact_hex48_surfaces() {
    let v = hex(48, 3);
    assert!(
        surfaces(&format!("sharedsecret = {v}"), &v),
        "sharedsecret (no separator) must surface"
    );
}

#[test]
fn shared_secret_uppercase_hex48_surfaces() {
    let v = hex(48, 4);
    assert!(
        surfaces(&format!("SHARED_SECRET={v}"), &v),
        "SHARED_SECRET=<hex48> must surface"
    );
}

#[test]
fn shared_secret_dash_hex32_surfaces() {
    let v = hex(32, 5);
    assert!(
        surfaces(&format!("shared-secret: {v}"), &v),
        "shared-secret:<hex32> must surface"
    );
}

#[test]
fn webhook_secret_suffix_rule_hex48_surfaces() {
    let v = hex(48, 6);
    assert!(
        surfaces(&format!("webhook_secret = {v}"), &v),
        "webhook_secret (not in the exact set) must surface via the *secret suffix rule"
    );
}

#[test]
fn hmac_secret_suffix_rule_hex32_surfaces() {
    let v = hex(32, 7);
    assert!(
        surfaces(&format!("hmac_secret = {v}"), &v),
        "hmac_secret must surface via *secret suffix"
    );
}

#[test]
fn db_encryption_key_suffix_rule_hex48_surfaces() {
    let v = hex(48, 8);
    assert!(
        surfaces(&format!("db_encryption_key = {v}"), &v),
        "db_encryption_key must surface via the *key suffix rule"
    );
}

#[test]
fn app_secret_exact_anchor_hex32_surfaces() {
    let v = hex(32, 9);
    assert!(
        surfaces(&format!("app_secret = {v}"), &v),
        "app_secret=<hex32> must surface"
    );
}

// ── NEGATIVES: declined classes stay suppressed (precision protection) ────────

#[test]
fn bare_key_hex32_stays_suppressed() {
    let v = hex(32, 10);
    assert!(
        nothing_surfaces(&format!("key = {v}"), &v),
        "bare key=<hex32> is the declined v31 class (MD5/ETag/cache-key collision)"
    );
}

#[test]
fn bare_key_hex48_stays_suppressed() {
    let v = hex(48, 11);
    assert!(
        nothing_surfaces(&format!("key = {v}"), &v),
        "bare key=<hex48> must stay suppressed"
    );
}

#[test]
fn bare_capitalized_key_hex32_stays_suppressed() {
    let v = hex(32, 12);
    assert!(
        nothing_surfaces(&format!("Key = {v}"), &v),
        "bare Key=<hex32> must stay suppressed"
    );
}

#[test]
fn licensekey_carveout_hex32_stays_suppressed() {
    let v = hex(32, 13);
    assert!(
        nothing_surfaces(&format!("license_key = {v}"), &v),
        "license_key is the explicit *key carve-out, a product license, not a crypto key"
    );
}

#[test]
fn token_hex48_stays_suppressed() {
    let v = hex(48, 14);
    assert!(
        nothing_surfaces(&format!("token = {v}"), &v),
        "token=<hex48> is a deliberately-excluded ambiguous anchor"
    );
}

#[test]
fn salt_hex32_stays_suppressed() {
    let v = hex(32, 15);
    assert!(
        nothing_surfaces(&format!("salt = {v}"), &v),
        "salt=<hex32> is a public cryptographic salt, not a secret"
    );
}

// ── BOUNDARY: the exemption is for hex32/hex48 ONLY (hash-shape traps) ─────────

#[test]
fn shared_secret_hex40_git_sha_length_stays_suppressed() {
    let v = hex(40, 16);
    assert!(
        nothing_surfaces(&format!("shared_secret = {v}"), &v),
        "a 40-hex (git-SHA length) under shared_secret is not an AES key, stays suppressed"
    );
}

#[test]
fn shared_secret_hex64_sha256_length_stays_suppressed() {
    let v = hex(64, 17);
    assert!(
        nothing_surfaces(&format!("shared_secret = {v}"), &v),
        "a 64-hex (sha256 length) under shared_secret stays suppressed (hash-shape trap)"
    );
}

#[test]
fn shared_secret_hex128_sha512_length_stays_suppressed() {
    // 32/48 are the only key-canonical hex lengths the exemption admits; the
    // hash-canonical lengths (40 git-SHA, 64 sha256, 128 sha512) stay suppressed
    // even under a strong anchor. (A NON-hash length like 31 is not a hash trap
    // and correctly surfaces as an ordinary high-entropy secret, so the boundary
    // that matters here is the hash lengths, tested 40/64/128.)
    let v = hex(128, 18);
    assert!(
        nothing_surfaces(&format!("shared_secret = {v}"), &v),
        "a 128-hex (sha512 length) under shared_secret stays suppressed (hash-shape trap)"
    );
}

// ── precision: placeholder / repetitive hex under a strong anchor suppressed ──

#[test]
fn shared_secret_repetitive_hex_stays_suppressed() {
    let v = "00000000000000000000000000000000"; // 32 zeros
    assert!(
        nothing_surfaces(&format!("shared_secret = {v}"), v),
        "an all-zero 32-hex value under shared_secret is a mask, not a key"
    );
}

#[test]
fn shared_secret_deadbeef_mask_stays_suppressed() {
    let v = "deadbeefdeadbeefdeadbeefdeadbeef"; // 32 hex, low-diversity repeating mask
    assert!(
        nothing_surfaces(&format!("shared_secret = {v}"), v),
        "a repeating deadbeef mask under shared_secret is a placeholder, not a key"
    );
}
