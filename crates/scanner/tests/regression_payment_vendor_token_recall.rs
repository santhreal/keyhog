//! Payment/fintech vendor credential recall + precision lock: Razorpay
//! (`rzp_test_`/`rzp_live_` key ids + key secret), Plaid (context-anchored
//! client-id / secret hex), Braintree (`8_8_8` public key), and Dwolla
//! (client id / secret). These leak via CI env and SDK config and had only
//! adversarial-level coverage. None is checksum-gated. This pins each form
//! across context plus the precision floors of the variable segments.

mod support;
use support::contracts::{make_chunk, scanner};

use keyhog_core::Chunk;
use keyhog_scanner::CompiledScanner;

fn gen(n: usize, seed: usize, charset: &[u8]) -> String {
    let m = charset.len() as u64;
    let mut s = (seed as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x44A1_07C9);
    (0..n)
        .map(|_| {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            charset[((s >> 33) % m) as usize] as char
        })
        .collect()
}
fn alnum(n: usize, seed: usize) -> String {
    gen(
        n,
        seed,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}
fn lcnum(n: usize, seed: usize) -> String {
    gen(n, seed, b"abcdefghijklmnopqrstuvwxyz0123456789")
}
fn hex(n: usize, seed: usize) -> String {
    gen(n, seed, b"0123456789abcdef")
}
fn braintree_pub(seed: usize) -> String {
    format!(
        "{}_{}_{}",
        lcnum(8, seed),
        lcnum(8, seed + 1),
        lcnum(8, seed + 2)
    )
}

fn scan(text: &str) -> Vec<(String, String)> {
    let s: &CompiledScanner = &scanner();
    let chunk: Chunk = make_chunk(text, "source", "payments.env");
    s.clear_fragment_cache();
    s.scan(&chunk)
        .into_iter()
        .map(|m| (m.detector_id.to_string(), m.credential.to_string()))
        .collect()
}
fn surfaces_under(text: &str, detector: &str, needle: &str) -> bool {
    scan(text)
        .iter()
        .any(|(id, cred)| id == detector && cred.contains(needle))
}
fn fires(text: &str, detector: &str) -> bool {
    scan(text).iter().any(|(id, _)| id == detector)
}

// ── Razorpay: rzp_test_ / rzp_live_ key ids + secret ──────────────────────────

#[test]
fn razorpay_test_key_id_surfaces() {
    let t = format!("rzp_test_{}", alnum(14, 1));
    assert!(
        surfaces_under(&t, "razorpay-key-id", &t),
        "rzp_test_ key id must surface"
    );
}

#[test]
fn razorpay_live_key_id_surfaces() {
    let t = format!("rzp_live_{}", alnum(14, 2));
    assert!(
        surfaces_under(&t, "razorpay-key-id", &t),
        "rzp_live_ key id must surface"
    );
}

#[test]
fn razorpay_test_key_longer_body_surfaces() {
    let t = format!("rzp_test_{}", alnum(24, 3)); // {14,} is open-ended
    assert!(surfaces_under(&t, "razorpay-key-id", &t));
}

#[test]
fn razorpay_key_id_env_anchor_surfaces() {
    let t = format!("rzp_live_{}", alnum(18, 4));
    assert!(surfaces_under(
        &format!("RAZORPAY_KEY_ID={t}"),
        "razorpay-key-id",
        &t
    ));
}

#[test]
fn razorpay_test_key_13_body_does_not_fire() {
    // The key-id pattern needs {14,}; the key-secret rzp_ pattern needs exactly 14.
    let t = format!("rzp_test_{}", alnum(13, 5));
    assert!(!fires(&t, "razorpay-key-id"));
}

#[test]
fn razorpay_wrong_prefix_does_not_fire() {
    let t = format!("rzp_prod_{}", alnum(20, 6)); // rzp_prod_ is not a keyword
    assert!(!fires(&t, "razorpay-key-id"));
}

#[test]
fn razorpay_key_secret_with_companion_key_id_surfaces() {
    // `razorpay-key-secret` has a REQUIRED companion: an `rzp_(test|live)_` key id
    // within 5 lines. That is a precision feature — a bare secret is noise; a
    // secret paired with its key id is a real credential. Exercise that path.
    let secret = alnum(28, 7);
    let key_id = format!("rzp_live_{}", alnum(14, 30));
    let text = format!("RAZORPAY_KEY_ID={key_id}\nRAZORPAY_KEY_SECRET={secret}\n");
    assert!(
        surfaces_under(&text, "razorpay-key-secret", &secret),
        "razorpay secret must surface when its companion key id is present"
    );
}

#[test]
fn razorpay_key_secret_without_companion_does_not_fire() {
    // The required companion is missing, so the bare secret is correctly withheld.
    let secret = alnum(28, 31);
    assert!(!fires(
        &format!("RAZORPAY_KEY_SECRET={secret}"),
        "razorpay-key-secret"
    ));
}

// ── Plaid: context-anchored hex client-id / secret ────────────────────────────

#[test]
fn plaid_secret_env_surfaces() {
    let h = hex(32, 8);
    assert!(surfaces_under(
        &format!("PLAID_SECRET={h}"),
        "plaid-secret",
        &h
    ));
}

#[test]
fn plaid_secret_min_30_surfaces() {
    let h = hex(30, 9); // 30 = secret minimum
    assert!(surfaces_under(
        &format!("PLAID_SECRET={h}"),
        "plaid-secret",
        &h
    ));
}

#[test]
fn plaid_secret_max_40_surfaces() {
    let h = hex(40, 10); // 40 = secret maximum
    assert!(surfaces_under(
        &format!("PLAID_SECRET={h}"),
        "plaid-secret",
        &h
    ));
}

#[test]
fn plaid_client_id_env_surfaces() {
    let h = hex(24, 11); // client id is exactly 24 hex
    assert!(surfaces_under(
        &format!("PLAID_CLIENT_ID={h}"),
        "plaid-client-id",
        &h
    ));
}

#[test]
fn plaid_secret_below_24_does_not_fire() {
    // 23 < the 24 client-id length AND < the 30 secret minimum: neither plaid
    // pattern matches under the PLAID_SECRET anchor.
    let h = hex(23, 12);
    assert!(!fires(&format!("PLAID_SECRET={h}"), "plaid-secret"));
}

// ── Braintree: public_key = 8_8_8 ─────────────────────────────────────────────

#[test]
fn braintree_public_key_surfaces() {
    let k = braintree_pub(13);
    assert!(surfaces_under(
        &format!("public_key={k}"),
        "braintree-api-key",
        &k
    ));
}

#[test]
fn braintree_public_key_branded_anchor_surfaces() {
    let k = braintree_pub(14);
    assert!(surfaces_under(
        &format!("braintree public_key={k}"),
        "braintree-api-key",
        &k
    ));
}

#[test]
fn braintree_two_segment_shape_does_not_fire() {
    // 8_8 (two segments) is not the 8_8_8 public-key shape.
    let k = format!("{}_{}", lcnum(8, 15), lcnum(8, 16));
    assert!(!fires(&format!("public_key={k}"), "braintree-api-key"));
}

// ── Dwolla: client id / secret ────────────────────────────────────────────────

#[test]
fn dwolla_client_id_surfaces() {
    let v = alnum(30, 17);
    assert!(surfaces_under(
        &format!("DWOLLA_CLIENT_ID={v}"),
        "dwolla-client-credentials",
        &v
    ));
}

#[test]
fn dwolla_client_secret_surfaces() {
    let v = alnum(40, 18);
    assert!(surfaces_under(
        &format!("DWOLLA_CLIENT_SECRET={v}"),
        "dwolla-client-credentials",
        &v
    ));
}

#[test]
fn dwolla_client_id_min_20_surfaces() {
    let v = alnum(20, 19); // 20 = client-id minimum
    assert!(surfaces_under(
        &format!("DWOLLA_CLIENT_ID={v}"),
        "dwolla-client-credentials",
        &v
    ));
}

#[test]
fn dwolla_client_secret_below_30_does_not_fire() {
    // 29 < the 30 secret minimum; the client-id pattern needs an `ID` anchor that
    // `CLIENT_SECRET` does not provide, so neither pattern matches.
    let v = alnum(29, 20);
    assert!(!fires(
        &format!("DWOLLA_CLIENT_SECRET={v}"),
        "dwolla-client-credentials"
    ));
}

// ── cross: several payment tokens co-surface ──────────────────────────────────

#[test]
fn multiple_payment_tokens_cosurface() {
    let r = format!("rzp_live_{}", alnum(16, 21));
    let p = hex(32, 22);
    let d = alnum(36, 23);
    let text = format!("RAZORPAY_KEY_ID={r}\nPLAID_SECRET={p}\nDWOLLA_CLIENT_SECRET={d}\n");
    assert!(surfaces_under(&text, "razorpay-key-id", &r));
    assert!(surfaces_under(&text, "plaid-secret", &p));
    assert!(surfaces_under(&text, "dwolla-client-credentials", &d));
}
