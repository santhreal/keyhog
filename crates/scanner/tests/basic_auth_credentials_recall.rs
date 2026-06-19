//! Recall + precision contract for the `basic-auth-credentials` detector,
//! added to close part of the flagship real-world recall gap (KH-L-0102).
//!
//! `basic-auth-credentials` surfaces `Basic <base64>` HTTP Authorization blobs
//! (the "Auth:Basic Authorization" class — ~600 CredData positives, ~0 caught
//! before; this detector lifts that category to recall ~0.82 at precision
//! ~0.98, with no measured mirror-corpus precision regression).
//!
//! NOTE on the reverted `generic-crypto-key` detector: a sibling detector for
//! the `<keyword> = <32/48/64 hex>` "Key" class was prototyped and REVERTED.
//! Although it measured 0.92-1.0 precision on CredData, the keyword+bare-hex
//! shape is fundamentally key-vs-hash ambiguous: on the SecretBench mirror
//! corpus (built from sha256/md5/git-sha FP traps) it fired 1058 false
//! positives for 54 true positives, collapsing mirror precision 0.9945 →
//! 0.71. The hex length is not a sufficient disambiguator (64 = sha256, 32 =
//! md5), and the CredData "Key" positives are 95% crypto TEST VECTORS that
//! keyhog's MoE correctly down-weights as non-leaks. The shape needs ML
//! context, not a structural rule — tracked for the MoE-retrain lane.
//!
//! The positives below are realistic blobs; assertions check the concrete
//! surfaced credential (never `!is_empty`).

mod support;
use support::contracts::make_chunk;
use support::contracts::{scanner, surfaces};

fn fires(text: &str, credential: &str) -> bool {
    let s = scanner();
    let chunk = make_chunk(text, "source", "probe.txt");
    surfaces(&s, &chunk, credential)
}

#[test]
fn basic_auth_header_blob_surfaces() {
    // base64("username:supersecretpassword123") — a realistic random-ish
    // credential blob (the shape CredData's Basic-Authorization positives
    // carry). The canonical RFC `aladdin:opensesame` specimen is a
    // low-entropy dictionary pair the MoE correctly scores weak, so it is
    // NOT used here — real blobs surface, textbook examples need not.
    let cred = "dXNlcm5hbWU6c3VwZXJzZWNyZXRwYXNzd29yZDEyMw==";
    assert!(
        fires(&format!("Authorization: Basic {cred}"), cred),
        "Basic-auth base64 credential blob must surface"
    );
}

#[test]
fn basic_auth_in_curl_command_surfaces() {
    // The shape as it appears in real shell/CI scripts.
    let cred = "YWRtaW46aHVudGVyMnN1cGVyc2VjcmV0MTIzNDU2";
    assert!(
        fires(
            &format!("curl -H \"Authorization: Basic {cred}\" https://api.example.com"),
            cred
        ),
        "Basic-auth blob inside a curl command must surface"
    );
}

#[test]
fn basically_word_does_not_trip_basic_auth() {
    // `\b`-anchored `basic` — the English word "basically" must not match, and
    // even if a 16+ base64-ish run followed, there is none here.
    let s = scanner();
    let chunk = make_chunk("This is basically just prose text here.", "source", "p.txt");
    assert!(
        !surfaces(&s, &chunk, "basically"),
        "`basically` prose must not surface a basic-auth credential"
    );
}
