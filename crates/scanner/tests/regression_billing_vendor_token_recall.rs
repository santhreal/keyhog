//! Payment/billing vendor credential recall + precision lock (distinct from the
//! fintech set in regression_payment_vendor_token_recall.rs): Square
//! (`sq0atp-`/`sq0csp-`), Coinbase (`organizations/…/apiKeys/…`), Checkout.com
//! (`sk_sbox_`/`pk_sbox_`/`ack_sbox_`), GoCardless (context token), Paddle
//! (`pdl_live/sdbx_apikey_`), Recurly (context 32-hex), Wise (context token),
//! and Squarespace (context key). Money-moving credentials, so recall here is
//! high-value. Built on the shared `support::vendorgen` harness; none is
//! checksum-gated.

mod support;
use support::vendorgen::{alnum, fires, hex, lcnum, surfaces_under, uuid};

// ── Square: sq0atp-<22> access / sq0csp-<43> client secret ───────────────────

#[test]
fn square_access_token_surfaces() {
    let k = format!("sq0atp-{}", alnum(22, 1));
    assert!(
        surfaces_under(&k, "square-access-token", &k),
        "sq0atp- token must surface"
    );
}

#[test]
fn square_access_token_env_anchor_surfaces() {
    let k = format!("sq0atp-{}", alnum(22, 2));
    assert!(surfaces_under(
        &format!("SQUARE_ACCESS_TOKEN={k}"),
        "square-access-token",
        &k
    ));
}

#[test]
fn square_client_secret_surfaces() {
    let k = format!("sq0csp-{}", alnum(43, 3));
    assert!(
        surfaces_under(&k, "square-access-token", &k),
        "sq0csp- secret must surface"
    );
}

#[test]
fn square_access_token_21_body_does_not_fire() {
    let k = format!("sq0atp-{}", alnum(21, 4)); // 21 < the required 22
    assert!(!fires(&k, "square-access-token"));
}

// ── Coinbase: organizations/<id>/apiKeys/<id> ────────────────────────────────

#[test]
fn coinbase_api_key_surfaces() {
    let k = format!("organizations/{}/apiKeys/{}", uuid(5), uuid(6));
    assert!(
        surfaces_under(&k, "coinbase-api-key", &k),
        "coinbase key path must surface"
    );
}

#[test]
fn coinbase_missing_apikeys_segment_does_not_fire() {
    // Without the literal `apiKeys/` segment there is no keyword to trigger and
    // no pattern match.
    let k = format!("organizations/{}/keys/{}", uuid(7), uuid(8));
    assert!(!fires(&k, "coinbase-api-key"));
}

// ── Checkout.com: sk_sbox_ / pk_sbox_ / ack_sbox_ ────────────────────────────

#[test]
fn checkout_secret_key_surfaces() {
    let k = format!("sk_sbox_{}", lcnum(30, 9));
    assert!(
        surfaces_under(&k, "checkout-com-api-key", &k),
        "sk_sbox_ key must surface"
    );
}

#[test]
fn checkout_public_key_surfaces() {
    let k = format!("pk_sbox_{}", lcnum(30, 10));
    assert!(surfaces_under(&k, "checkout-com-api-key", &k));
}

#[test]
fn checkout_ack_key_surfaces() {
    let k = format!("ack_sbox_{}", lcnum(15, 11));
    assert!(surfaces_under(&k, "checkout-com-api-key", &k));
}

#[test]
fn checkout_secret_key_23_body_does_not_fire() {
    let k = format!("sk_sbox_{}", lcnum(23, 12)); // 23 < the required 24
    assert!(!fires(&k, "checkout-com-api-key"));
}

// ── GoCardless: context 30..60 token ─────────────────────────────────────────

#[test]
fn gocardless_access_token_surfaces() {
    let k = alnum(40, 13);
    assert!(surfaces_under(
        &format!("GOCARDLESS_ACCESS_TOKEN={k}"),
        "gocardless-access-token",
        &k
    ));
}

#[test]
fn gocardless_min_length_surfaces() {
    let k = alnum(30, 14); // 30 = minimum
    assert!(surfaces_under(
        &format!("GOCARDLESS_ACCESS_TOKEN={k}"),
        "gocardless-access-token",
        &k
    ));
}

#[test]
fn gocardless_29_body_does_not_fire() {
    let k = alnum(29, 15); // 29 < the required 30
    assert!(!fires(
        &format!("GOCARDLESS_ACCESS_TOKEN={k}"),
        "gocardless-access-token"
    ));
}

// ── Paddle: pdl_live/sdbx_apikey_<30+> ───────────────────────────────────────

#[test]
fn paddle_live_api_key_surfaces() {
    let k = format!("pdl_live_apikey_{}", alnum(35, 16));
    assert!(
        surfaces_under(&k, "paddle-api-key", &k),
        "pdl_live_apikey_ must surface"
    );
}

#[test]
fn paddle_sandbox_api_key_surfaces() {
    let k = format!("pdl_sdbx_apikey_{}", alnum(35, 17));
    assert!(surfaces_under(&k, "paddle-api-key", &k));
}

#[test]
fn paddle_29_body_does_not_fire() {
    let k = format!("pdl_live_apikey_{}", alnum(29, 18)); // 29 < the required 30
    assert!(!fires(&k, "paddle-api-key"));
}

// ── Recurly: context 32-hex ──────────────────────────────────────────────────

#[test]
fn recurly_api_key_surfaces() {
    let k = hex(32, 19);
    assert!(surfaces_under(
        &format!("RECURLY_API_KEY={k}"),
        "recurly-api-key",
        &k
    ));
}

#[test]
fn recurly_31_hex_does_not_fire() {
    let k = hex(31, 20); // 31 < the required 32
    assert!(!fires(&format!("RECURLY_API_KEY={k}"), "recurly-api-key"));
}

// ── Wise: context 22+ token ──────────────────────────────────────────────────

#[test]
fn wise_api_token_surfaces() {
    let k = alnum(30, 21);
    assert!(surfaces_under(
        &format!("WISE_API_TOKEN={k}"),
        "wise-api-token",
        &k
    ));
}

// ── Squarespace: context key ─────────────────────────────────────────────────

#[test]
fn squarespace_api_key_surfaces() {
    let k = alnum(45, 22);
    assert!(surfaces_under(
        &format!("squarespace api_key: {k}"),
        "squarespace-api-key",
        &k
    ));
}

// ── cross: several billing tokens co-surface ─────────────────────────────────

#[test]
fn square_checkout_paddle_cosurface() {
    let sq = format!("sq0atp-{}", alnum(22, 23));
    let ck = format!("sk_sbox_{}", lcnum(30, 24));
    let pd = format!("pdl_live_apikey_{}", alnum(35, 25));
    let text = format!("SQUARE_ACCESS_TOKEN={sq}\nCHECKOUT_KEY={ck}\nPADDLE_API_KEY={pd}\n");
    assert!(surfaces_under(&text, "square-access-token", &sq));
    assert!(surfaces_under(&text, "checkout-com-api-key", &ck));
    assert!(surfaces_under(&text, "paddle-api-key", &pd));
}

#[test]
fn coinbase_gocardless_recurly_cosurface() {
    let cb = format!("organizations/{}/apiKeys/{}", uuid(26), uuid(27));
    let gc = alnum(40, 28);
    let rc = hex(32, 29);
    let text = format!("COINBASE_KEY={cb}\nGOCARDLESS_ACCESS_TOKEN={gc}\nRECURLY_API_KEY={rc}\n");
    assert!(surfaces_under(&text, "coinbase-api-key", &cb));
    assert!(surfaces_under(&text, "gocardless-access-token", &gc));
    assert!(surfaces_under(&text, "recurly-api-key", &rc));
}
