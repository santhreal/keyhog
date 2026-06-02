//! Regression: bare-`Authorization` header detectors must not false-positive on
//! an unrelated service's token.
//!
//! Five detectors shipped a second pattern that matched a *bare*
//! `Authorization: Bearer <value>` (or, for cryptocompare, a bare
//! `Authorization: <value>`) with NO service-specific co-occurrence anchor:
//!
//!   * `linode-pat`        `Authorization:\s*[Bb]earer\s+([0-9a-f]{64})`
//!   * `mistral-api-key`   `Authorization:\s*[Bb]earer\s+([a-zA-Z0-9]{32})`
//!   * `fusionauth-api-key``Authorization:\s*[A-Za-z]+\s+(<uuid>)`  (any scheme!)
//!   * `cryptocompare-api-key` `Authorization[=:\s"']+(?:Apikey\s+)?([a-zA-Z0-9]{20,})`
//!   * `magiceden-api-key` `Authorization[\s]*:[\s]*Bearer[\s]+([a-f0-9-]{36,})`
//!
//! Because keyword-gating is per-detector and scoped to the whole chunk, any
//! file that merely *mentions* the service (its keyword in a comment, an import,
//! a doc line) and *also* contains some other service's `Authorization: Bearer`
//! header would mis-attribute that unrelated token to Linode / Mistral /
//! FusionAuth / CryptoCompare / Magic Eden. A bearer token alone is not
//! service-attributable.
//!
//! Root-cause fix (in `detectors/*.toml`): require the service token to
//! co-occur on the SAME logical line as the credential, mirroring the
//! established convention already used by directus / pingdom / statuscake /
//! strapi / cerebrium (`...([cred])[^\n]*<service>`). This file pins both
//! halves of the contract:
//!
//!   1. NEGATIVE (the bug): an unrelated `Authorization: Bearer` whose only
//!      tie to the service is a keyword on a *different* line MUST NOT be
//!      attributed to that detector. Fails against the pre-fix TOMLs.
//!   2. POSITIVE (recall preserved): a genuine same-line
//!      `Authorization: <scheme> <cred> ... <service-host>` MUST still fire,
//!      capturing the exact credential bytes.
//!
//! The fixtures put the service keyword on its own line so the per-detector
//! keyword GATE is active either way - proving it is the regex anchor (the
//! fix), not the gate, that silences the false positive.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;

// High-entropy, structurally-valid credential bodies. High entropy guarantees
// the pre-fix scanner would actually surface the false positive (a low-entropy
// `aaaa...` body could be dropped for an unrelated reason), so the negative
// assertions below isolate the regex anchor as the sole cause of suppression.
const LINODE_HEX64: &str = "9f3c1a7e2b8d4056c1e9a7b3f0d6428e5a1c9b7e3f2d8064a5c1e9b7f3d20486";
const MISTRAL_ALNUM32: &str = "Xk7Qp2Vb9Tz4Hy1Rc6Mf8Wj3Dg5Es0Lu"; // 32 chars below
const UUID: &str = "3f2a9c7e-1b4d-4e8a-9c0f-7a2b6d8e1c3f"; // 36 chars, fusionauth + magiceden shape
const CC_ALNUM23: &str = "Zk7Qp2Vb9Tz4Hy1Rc6Mf8Wj"; // 23 alnum, >= the {20,} floor

fn make_chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "bare-auth-fp".into(),
            // Neutral, non-test filename so no test-path confidence penalty
            // skews the positive (recall) assertions.
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

fn build_scanner() -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors loadable");
    CompiledScanner::compile(detectors).expect("scanner compile")
}

/// True if ANY surfaced match was attributed to `detector_id`.
fn detector_fired(scanner: &CompiledScanner, text: &str, path: &str, detector_id: &str) -> bool {
    let chunk = make_chunk(text, path);
    let matches = scanner.scan(&chunk);
    matches
        .iter()
        .any(|m| m.detector_id.as_ref() == detector_id)
}

/// Return the credential captured by `detector_id`, if it fired.
fn detector_credential(
    scanner: &CompiledScanner,
    text: &str,
    path: &str,
    detector_id: &str,
) -> Option<String> {
    let chunk = make_chunk(text, path);
    let matches = scanner.scan(&chunk);
    matches
        .iter()
        .find(|m| m.detector_id.as_ref() == detector_id)
        .map(|m| m.credential.to_string())
}

// ---------------------------------------------------------------------------
// NEGATIVE TWINS: the bug. Unrelated service's bearer token + a keyword that
// sits on a DIFFERENT line. Each MUST NOT be attributed to the named detector.
// ---------------------------------------------------------------------------

#[test]
fn linode_does_not_claim_unrelated_bearer() {
    let scanner = build_scanner();
    let text = format!(
        "# linode access is provisioned separately\n\
         Authorization: Bearer {LINODE_HEX64} https://api.openai.com/v1/chat\n"
    );
    assert!(
        !detector_fired(&scanner, &text, "deploy.sh", "linode-pat"),
        "linode-pat fired on an unrelated bearer token whose only tie to Linode \
         is the word `linode` on a separate comment line. A bare \
         `Authorization: Bearer <64hex>` is not a Linode PAT; the regex must \
         require `linode` on the same line as the credential."
    );
}

#[test]
fn mistral_does_not_claim_unrelated_bearer() {
    // The Mistral body shape is exactly `[a-zA-Z0-9]{32}`; assert the fixture
    // body length so the test stays a faithful reproduction of the shape.
    assert_eq!(
        MISTRAL_ALNUM32.len(),
        32,
        "mistral fixture must be 32 chars"
    );
    let scanner = build_scanner();
    let text = format!(
        "# mistral is unrelated to this call\n\
         Authorization: Bearer {MISTRAL_ALNUM32} https://api.openai.com/v1/chat\n"
    );
    assert!(
        !detector_fired(&scanner, &text, "deploy.sh", "mistral-api-key"),
        "mistral-api-key fired on an unrelated 32-char bearer token. A bare \
         `Authorization: Bearer <32alnum>` is not a Mistral key."
    );
}

#[test]
fn fusionauth_does_not_claim_unrelated_bearer() {
    let scanner = build_scanner();
    let text = format!(
        "# fusionauth runs in another service\n\
         Authorization: Bearer {UUID} https://api.github.com/user\n"
    );
    assert!(
        !detector_fired(&scanner, &text, "deploy.sh", "fusionauth-api-key"),
        "fusionauth-api-key fired on an unrelated bearer UUID. A bare \
         `Authorization` header carrying any UUID is not a FusionAuth key."
    );
}

#[test]
fn cryptocompare_does_not_claim_unrelated_authorization() {
    let scanner = build_scanner();
    let text = format!(
        "# cryptocompare key lives in vault\n\
         Authorization: {CC_ALNUM23} https://api.github.com/user\n"
    );
    assert!(
        !detector_fired(&scanner, &text, "deploy.sh", "cryptocompare-api-key"),
        "cryptocompare-api-key fired on an unrelated `Authorization: <value>` \
         header. A bare header value is not a CryptoCompare key."
    );
}

#[test]
fn magiceden_does_not_claim_unrelated_bearer() {
    let scanner = build_scanner();
    let text = format!(
        "# magiceden integration is optional\n\
         Authorization: Bearer {UUID} https://api.opensea.io/v2\n"
    );
    assert!(
        !detector_fired(&scanner, &text, "deploy.sh", "magiceden-api-key"),
        "magiceden-api-key fired on an unrelated bearer UUID destined for \
         OpenSea. A bare `Authorization: Bearer <uuid>` is not a Magic Eden key."
    );
}

// ---------------------------------------------------------------------------
// POSITIVES: recall preserved. A genuine same-line
// `Authorization: <scheme> <cred> ... <service-host>` MUST still fire and
// capture the EXACT credential bytes.
// ---------------------------------------------------------------------------

#[test]
fn linode_still_fires_with_same_line_anchor() {
    let scanner = build_scanner();
    let text = format!(
        "curl -H \"Authorization: Bearer {LINODE_HEX64}\" https://api.linode.com/v4/account\n"
    );
    assert_eq!(
        detector_credential(&scanner, &text, "deploy.sh", "linode-pat").as_deref(),
        Some(LINODE_HEX64),
        "linode-pat must still fire on a real same-line Linode bearer header and \
         capture the exact 64-hex token."
    );
}

#[test]
fn mistral_still_fires_with_same_line_anchor() {
    let scanner = build_scanner();
    let text = format!(
        "curl -H \"Authorization: Bearer {MISTRAL_ALNUM32}\" https://api.mistral.ai/v1/models\n"
    );
    assert_eq!(
        detector_credential(&scanner, &text, "deploy.sh", "mistral-api-key").as_deref(),
        Some(MISTRAL_ALNUM32),
        "mistral-api-key must still fire on a real same-line Mistral bearer header."
    );
}

#[test]
fn fusionauth_still_fires_with_same_line_anchor() {
    let scanner = build_scanner();
    let text = format!(
        "curl -H \"Authorization: Bearer {UUID}\" https://fusionauth.example.com/api/user\n"
    );
    assert_eq!(
        detector_credential(&scanner, &text, "deploy.sh", "fusionauth-api-key").as_deref(),
        Some(UUID),
        "fusionauth-api-key must still fire when `fusionauth` appears on the same \
         line (here, in the request host)."
    );
}

#[test]
fn cryptocompare_still_fires_with_same_line_anchor() {
    let scanner = build_scanner();
    let text = format!(
        "curl -H \"Authorization: Apikey {CC_ALNUM23}\" https://min-api.cryptocompare.com/data/price\n"
    );
    assert_eq!(
        detector_credential(&scanner, &text, "deploy.sh", "cryptocompare-api-key").as_deref(),
        Some(CC_ALNUM23),
        "cryptocompare-api-key must still fire on the documented \
         `Authorization: Apikey <key>` shape when the cryptocompare host is on \
         the same line."
    );
}

#[test]
fn magiceden_still_fires_with_same_line_anchor() {
    let scanner = build_scanner();
    let text = format!(
        "curl -H \"Authorization: Bearer {UUID}\" https://api-mainnet.magiceden.dev/v2/collections\n"
    );
    assert_eq!(
        detector_credential(&scanner, &text, "deploy.sh", "magiceden-api-key").as_deref(),
        Some(UUID),
        "magiceden-api-key must still fire when `magiceden` appears on the same \
         line (here, in the request host)."
    );
}

// ---------------------------------------------------------------------------
// ADVERSARIAL / property-style sweep: for each detector, an unrelated bearer
// token sitting on a line with the keyword present elsewhere must never be
// attributed, across many random shape-valid token bodies. This guards against
// a future regression that re-broadens any of the five anchors.
// ---------------------------------------------------------------------------

/// Tiny deterministic xorshift PRNG - no external rand dependency, fully
/// reproducible so a failure is replayable.
fn next_rng(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn random_hex(state: &mut u64, len: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    (0..len)
        .map(|_| HEX[(next_rng(state) % 16) as usize] as char)
        .collect()
}

fn random_alnum(state: &mut u64, len: usize) -> String {
    const ALNUM: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| ALNUM[(next_rng(state) % 62) as usize] as char)
        .collect()
}

fn random_uuid(state: &mut u64) -> String {
    let h = random_hex(state, 32);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[test]
fn no_detector_claims_random_unrelated_bearer_tokens() {
    let scanner = build_scanner();
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let iters = 256;

    for _ in 0..iters {
        // linode: random 64-hex, keyword on a separate line.
        let hex = random_hex(&mut state, 64);
        let t = format!("// linode\nAuthorization: Bearer {hex} https://api.openai.com\n");
        assert!(
            !detector_fired(&scanner, &t, "client.go", "linode-pat"),
            "linode-pat mis-attributed a random unrelated 64-hex bearer token: {hex}"
        );

        // mistral: random 32-alnum, keyword on a separate line.
        let a32 = random_alnum(&mut state, 32);
        let t = format!("// mistral\nAuthorization: Bearer {a32} https://api.openai.com\n");
        assert!(
            !detector_fired(&scanner, &t, "client.go", "mistral-api-key"),
            "mistral-api-key mis-attributed a random unrelated 32-alnum bearer token: {a32}"
        );

        // fusionauth + magiceden: random UUID, keyword on a separate line.
        let uuid = random_uuid(&mut state);
        let t = format!("// fusionauth\nAuthorization: Bearer {uuid} https://api.github.com\n");
        assert!(
            !detector_fired(&scanner, &t, "client.go", "fusionauth-api-key"),
            "fusionauth-api-key mis-attributed a random unrelated bearer UUID: {uuid}"
        );
        let t = format!("// magiceden\nAuthorization: Bearer {uuid} https://api.opensea.io\n");
        assert!(
            !detector_fired(&scanner, &t, "client.go", "magiceden-api-key"),
            "magiceden-api-key mis-attributed a random unrelated bearer UUID: {uuid}"
        );

        // cryptocompare: random 20+ alnum bare Authorization value.
        let cc = random_alnum(&mut state, 28);
        let t = format!("// cryptocompare\nAuthorization: {cc} https://api.github.com\n");
        assert!(
            !detector_fired(&scanner, &t, "client.go", "cryptocompare-api-key"),
            "cryptocompare-api-key mis-attributed a random unrelated Authorization value: {cc}"
        );
    }
}
