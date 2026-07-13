//! Regression gate for the new-prefix recall gap:
//!   - Azure Service Bus connection string (`Endpoint=sb://…servicebus.windows.net`)
//!   - Slack app-level token (`xapp-`)
//!   - Slack app-configuration access/refresh token (`xoxe.xoxp-` / `xoxe-`)
//!   - GitLab runner authentication token (`glrt-`)
//!   - Postman API key (`PMAK-`)
//!
//! Before the fix, NONE of these five detectors existed in `detectors/`, so a
//! real credential of each shape produced ZERO findings on the production
//! `CompiledScanner::compile(load_detectors(...)).scan(...)` path, a pure
//! recall hole. (`glrt-` was even listed in the scanner's KNOWN_PREFIXES
//! confidence floor, yet no detector ever captured it.)
//!
//! Each positive test FAILS against the old behavior (no detector → no match)
//! and PASSES once the TOML detectors are added. The assertions pin concrete
//! truth: the exact detector id, the exact captured credential bytes, the
//! declared severity, and a confidence at/above the CLI's `min_confidence`
//! floor (so the orchestrator does not silently drop the finding). Negative
//! twins, a boundary case, an adversarial wrong-prefix case, and a seeded
//! generative loop guard against over- and under-matching.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch, Severity};
use keyhog_scanner::CompiledScanner;
use std::sync::OnceLock;

/// The CLI orchestrator drops scanner findings below this confidence
/// (`crates/cli` default `min_confidence`). A detector with a real recall
/// target must clear it. Two distinct mechanisms get a detector past the
/// floor; this suite asserts whichever one each detector actually relies on:
///
///  - Tokens whose literal prefix is in the scanner's `KNOWN_PREFIXES`
///    (e.g. `glrt-`) have their STORED `RawMatch.confidence` lifted to ≥ 0.8
///    in `scan_postprocess` (`known_prefix_confidence_floor(...).max(floor)`),
///    so we assert `hit.confidence >= 0.5` directly.
///  - Tokens whose prefix is NOT in `KNOWN_PREFIXES` (`PMAK-`, `xapp-`,
///    `xoxe-`, `Endpoint=sb://`) instead self-declare `min_confidence = 0.5`
///    in their TOML. That value is applied as a FILTER floor by the CLI
///    orchestrator, not as a lift of the scanner-layer confidence, so for
///    those we assert the loaded `DetectorSpec::min_confidence` carries the
///    floor (see `new_prefix_detectors_declare_min_confidence_floor`), which
///    is the load-bearing fact that keeps the finding in production output.
const CLI_FLOOR_HEADROOM: f64 = 0.5;

/// Compile the real on-disk detector corpus exactly once for the whole test
/// binary (the corpus is ~900 TOMLs; recompiling per-test is wasteful).
fn shared_scanner() -> &'static CompiledScanner {
    static SCANNER: OnceLock<CompiledScanner> = OnceLock::new();
    SCANNER.get_or_init(|| {
        let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
        CompiledScanner::compile(detectors).expect("compile scanner")
    })
}

/// Scan `text` as a `.env`-shaped filesystem chunk and return all raw matches.
fn scan(text: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.env".into()),
            ..Default::default()
        },
    };
    let scanner = shared_scanner();
    scanner.clear_fragment_cache();
    scanner.scan(&chunk)
}

/// Find the single match for `detector_id`, or fail with the full set of
/// detector ids the scanner actually produced (so a regression reads clearly).
fn require_hit<'a>(matches: &'a [RawMatch], detector_id: &str, text: &str) -> &'a RawMatch {
    matches
        .iter()
        .find(|m| m.detector_id.as_ref() == detector_id)
        .unwrap_or_else(|| {
            panic!(
                "RECALL GAP: detector `{detector_id}` did NOT fire on a canonical \
                 credential. Input: {text:?}. Scanner produced: {:?}",
                matches
                    .iter()
                    .map(|m| m.detector_id.as_ref())
                    .collect::<Vec<_>>()
            )
        })
}

fn assert_no_hit(detector_id: &str, text: &str) {
    let matches = scan(text);
    assert!(
        !matches
            .iter()
            .any(|m| m.detector_id.as_ref() == detector_id),
        "FALSE POSITIVE: detector `{detector_id}` fired on a non-credential: {text:?}. \
         Matches: {:?}",
        matches
            .iter()
            .map(|m| m.detector_id.as_ref())
            .collect::<Vec<_>>()
    );
}

// ----------------------------------------------------------------------------
// Positive truth: each new detector fires, captures the right bytes, carries
// the declared severity, and clears the CLI confidence floor.
// ----------------------------------------------------------------------------

#[test]
fn postman_api_key_fires_with_exact_capture() {
    let secret = "PMAK-606a8c2da5c08a004dfd060f-c7cdd622c690177cce465538021e349288";
    let text = format!("POSTMAN_API_KEY={secret}\n");
    let matches = scan(&text);
    let hit = require_hit(&matches, "postman-api-key", &text);

    assert_eq!(
        hit.credential.as_ref(),
        secret,
        "postman-api-key must capture the full PMAK- token, got {:?}",
        hit.credential.as_ref()
    );
    assert_eq!(hit.service.as_ref(), "postman");
    assert_eq!(hit.severity, Severity::High);
    // `postman-api-key` clears the CLI floor via its self-declared
    // `min_confidence` (PMAK- is not in KNOWN_PREFIXES), asserted in
    // `new_prefix_detectors_declare_min_confidence_floor`.
}

#[test]
fn gitlab_runner_auth_token_fires_with_exact_capture() {
    // glrt- standard runner authentication token (20-char base64url body).
    let secret = "glrt-2CR8_eVxiioB1QmzPZwa";
    let text = format!("CI_RUNNER_TOKEN={secret}\n");
    let matches = scan(&text);
    let hit = require_hit(&matches, "gitlab-runner-authentication-token", &text);

    assert_eq!(
        hit.credential.as_ref(),
        secret,
        "gitlab-runner-authentication-token must capture the full glrt- token, got {:?}",
        hit.credential.as_ref()
    );
    assert_eq!(hit.service.as_ref(), "gitlab");
    assert_eq!(hit.severity, Severity::High);
    // glrt- is in the scanner's KNOWN_PREFIXES floor (0.8), so this clears the
    // CLI floor without a self-declared min_confidence.
    let conf = hit.confidence.unwrap_or(0.0);
    assert!(
        conf >= CLI_FLOOR_HEADROOM,
        "gitlab-runner-authentication-token confidence {conf:.3} below {CLI_FLOOR_HEADROOM}"
    );
}

#[test]
fn gitlab_runner_routable_token_fires() {
    // glrt-t<digit>_<body>.<9-char suffix> routable variant.
    let secret = "glrt-t1_AbCdEfGhIjKlMnOpQrStUvWxYz0.9z8y7x6w5";
    let text = format!("runner_token = \"{secret}\"\n");
    let matches = scan(&text);
    let hit = require_hit(&matches, "gitlab-runner-authentication-token", &text);
    assert_eq!(hit.service.as_ref(), "gitlab");
    // The captured credential must START with the routable prefix (the
    // standard 20-char pattern in the same detector may capture a shorter
    // prefix; either way the detector fires and reports a glrt- token).
    assert!(
        hit.credential.as_ref().starts_with("glrt-t1_"),
        "routable runner token capture should start with `glrt-t1_`, got {:?}",
        hit.credential.as_ref()
    );
}

#[test]
fn slack_app_token_fires_with_exact_capture() {
    let secret = "xapp-1-A012B3CDEFG-1234567890123-1f9a0b7c4e2d6a8b3c5f7e9d0a1b2c3d";
    let text = format!("SLACK_APP_TOKEN={secret}\n");
    let matches = scan(&text);
    let hit = require_hit(&matches, "slack-app-token", &text);

    assert_eq!(
        hit.credential.as_ref(),
        secret,
        "slack-app-token must capture the full xapp- token, got {:?}",
        hit.credential.as_ref()
    );
    assert_eq!(hit.service.as_ref(), "slack");
    assert_eq!(hit.severity, Severity::Critical);
    // Clears the CLI floor via self-declared `min_confidence` (xapp- not in
    // KNOWN_PREFIXES); asserted in
    // `new_prefix_detectors_declare_min_confidence_floor`.
}

#[test]
fn slack_config_refresh_token_fires() {
    // xoxe- refresh token: digit + 146 upper-alphanumeric chars.
    let body = "HBRPOIG8F1CBFNO6B9M80O2RAK1VRJNVGFYGWWQC38HYF9SXMECOSFOGYR3XKXWNREK8PK3YR9OUDOCUZRENUN5Z3JQIP98Q1ZXOI65FDHJK1EYY37Q9AH8RVHS1K3AQ6L6GT6MJXK87AU5BHX";
    assert_eq!(body.len(), 146, "fixture must be exactly 146 body chars");
    let secret = format!("xoxe-1-{body}");
    let text = format!("SLACK_REFRESH_TOKEN={secret}\n");
    let matches = scan(&text);
    let hit = require_hit(&matches, "slack-config-token", &text);

    assert_eq!(
        hit.credential.as_ref(),
        secret,
        "slack-config-token must capture the full xoxe- refresh token, got {:?}",
        hit.credential.as_ref()
    );
    assert_eq!(hit.service.as_ref(), "slack");
    assert_eq!(hit.severity, Severity::Critical);
    // Clears the CLI floor via self-declared `min_confidence` (xoxe- not in
    // KNOWN_PREFIXES); asserted in
    // `new_prefix_detectors_declare_min_confidence_floor`.
}

#[test]
fn slack_config_access_token_fires() {
    // xoxe.xoxp- access token: digit + 163-166 upper-alphanumeric chars.
    // Body is varied (not uniform/monotonic) so the sequential-placeholder
    // suppression does not fire (a real rotation token is high-entropy).
    let body = "PTGZ4JFEBZ9SDO78XRLGQNBQRMKTSXFVY6PLP4RF9TAST6M01S12KOTQCFC3R784VJME0M2RLW1U9MUGDORPHVLS3BCWFSUBUSUJ0ESM2SIQYKVAXC3KXXSG2N1NHDDDKJC85PUCH7S0M4MP205CO02P1N5MCCQQP7NO0";
    assert_eq!(
        body.len(),
        165,
        "access-token fixture must be 165 body chars (163-166 band)"
    );
    let secret = format!("xoxe.xoxp-1-{body}");
    let text = format!("SLACK_ACCESS_TOKEN={secret}\n");
    let matches = scan(&text);
    let hit = require_hit(&matches, "slack-config-token", &text);
    assert!(
        hit.credential.as_ref().starts_with("xoxe.xoxp-1-"),
        "slack-config access token capture should start with `xoxe.xoxp-1-`, got {:?}",
        hit.credential.as_ref()
    );
    assert_eq!(hit.service.as_ref(), "slack");
}

#[test]
fn azure_service_bus_connection_string_fires_and_captures_key() {
    let key = "NB8zVq3F7pXm2kJdR9sLtY6wEoQa1uHcZbVgXn4MiP0=";
    let secret = format!(
        "Endpoint=sb://contoso-ns.servicebus.windows.net/;\
         SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={key}"
    );
    let text = format!("SERVICEBUS_CONNECTION_STRING=\"{secret}\"\n");
    let matches = scan(&text);
    let hit = require_hit(&matches, "azure-service-bus-connection-string", &text);

    // Two detector patterns overlap on this line, the SharedAccessKey-form
    // pattern captures just the key (group 1), the env-anchor pattern captures
    // the whole connection string, and overlap resolution keeps one. Either
    // way the reported credential MUST contain the actual SharedAccessKey
    // secret; that is the load-bearing fact, independent of resolver tie-break.
    assert!(
        hit.credential.as_ref().contains(key),
        "azure-service-bus detector must capture (or include) the SharedAccessKey \
         value `{key}`, got {:?}",
        hit.credential.as_ref()
    );
    assert_eq!(hit.service.as_ref(), "azure-service-bus");
    assert_eq!(hit.severity, Severity::Critical);
    // Clears the CLI floor via self-declared `min_confidence` (the captured
    // base64 key has no KNOWN_PREFIXES prefix); asserted in
    // `new_prefix_detectors_declare_min_confidence_floor`.
}

#[test]
fn azure_service_bus_does_not_collide_with_iot_host() {
    // An azure-devices.net (IoT Hub) host must NOT be claimed by the Service
    // Bus detector, the two share the `Endpoint=`/`SharedAccessKey` shape but
    // are distinguished by host. Guards against the Service Bus regex being
    // loosened to swallow IoT strings.
    let iot = "Endpoint=sb://my-hub.azure-devices.net/;\
               SharedAccessKeyName=iothubowner;\
               SharedAccessKey=NB8zVq3F7pXm2kJdR9sLtY6wEoQa1uHcZbVgXn4MiP0=";
    let text = format!("IOTHUB_CONNECTION_STRING=\"{iot}\"\n");
    assert_no_hit("azure-service-bus-connection-string", &text);
}

/// The four new detectors whose prefix is NOT in the scanner's
/// `KNOWN_PREFIXES` floor list rely on a self-declared `min_confidence` to
/// survive the CLI orchestrator's filter. Assert each loads with exactly the
/// declared floor, the load-bearing fact that keeps their findings in
/// production output. (Pre-fix the detectors did not exist at all, so this
/// also fails on the old corpus.)
#[test]
fn new_prefix_detectors_declare_min_confidence_floor() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    let floored = [
        "postman-api-key",
        "slack-app-token",
        "slack-config-token",
        "azure-service-bus-connection-string",
    ];
    for id in floored {
        let spec = detectors
            .iter()
            .find(|d| d.id == id)
            .unwrap_or_else(|| panic!("detector `{id}` is missing from the corpus"));
        assert_eq!(
            spec.min_confidence,
            Some(0.5),
            "detector `{id}` must self-declare `min_confidence = 0.5` so the CLI \
             orchestrator's filter does not drop its findings (its prefix is not \
             in the scanner's KNOWN_PREFIXES floor list)."
        );
    }
    // glrt- relies on the KNOWN_PREFIXES scanner-layer floor instead, so it
    // correctly does NOT self-declare one.
    let glrt = detectors
        .iter()
        .find(|d| d.id == "gitlab-runner-authentication-token")
        .expect("gitlab-runner-authentication-token present");
    assert_eq!(
        glrt.min_confidence, None,
        "gitlab-runner-authentication-token gets its floor from KNOWN_PREFIXES \
         (glrt-), so it should not self-declare a redundant min_confidence."
    );
}

// ----------------------------------------------------------------------------
// Negative twins: structurally-similar non-credentials must NOT fire.
// ----------------------------------------------------------------------------

#[test]
fn negative_twins_do_not_fire() {
    // Postman: PMAK- with too-short hex segments (not 24+34).
    assert_no_hit("postman-api-key", "key = PMAK-deadbeef-cafef00d\n");
    // GitLab PAT prefix must not be claimed as a *runner* token.
    assert_no_hit(
        "gitlab-runner-authentication-token",
        "glpat-AbCdEfGhIjKlMnOpQrSt12\n",
    );
    // glrt- with a too-short (19-char) body (below the {20} floor).
    assert_no_hit(
        "gitlab-runner-authentication-token",
        "token=glrt-abcdefghijklmnopqrs\n", // 19 chars after glrt-
    );
    // xapp- missing the trailing secret segment.
    assert_no_hit("slack-app-token", "xapp-1-A012B3CDEFG-1234567890123\n");
    // xoxe- refresh token with a too-short body (not 146 chars).
    assert_no_hit("slack-config-token", "xoxe-1-ABCDEF1234567890\n");
    // Service Bus connection string with the key segment absent.
    assert_no_hit(
        "azure-service-bus-connection-string",
        "Endpoint=sb://x.servicebus.windows.net/;SharedAccessKeyName=RootKey\n",
    );
    // A benign assignment that merely contains the substring "servicebus".
    assert_no_hit(
        "azure-service-bus-connection-string",
        "let servicebus_client = new ServiceBusClient(opts);\n",
    );
}

// ----------------------------------------------------------------------------
// Boundary: exact minimum-length bodies must fire; one-below must not.
// ----------------------------------------------------------------------------

#[test]
fn glrt_body_length_boundary() {
    // Exactly 20 chars after `glrt-` must fire (varied body so the
    // sequential-placeholder suppression cannot interfere, the boundary
    // under test is the regex length floor, not entropy).
    let body20 = "Ik2zwEQHfwcepYyNGfB5";
    assert_eq!(body20.len(), 20);
    let ok = format!("t = glrt-{body20}\n");
    let hit = scan(&ok);
    assert!(
        hit.iter()
            .any(|m| m.detector_id.as_ref() == "gitlab-runner-authentication-token"),
        "glrt- with exactly 20-char body must fire"
    );
    // 19 chars must not (one below the {20} floor → the regex cannot match).
    let body19 = "Ik2zwEQHfwcepYyNGfB"; // 19 chars
    assert_eq!(body19.len(), 19);
    assert_no_hit(
        "gitlab-runner-authentication-token",
        &format!("t = glrt-{body19}\n"),
    );
}

#[test]
fn postman_hex_segment_boundary() {
    // Canonical 24-hex + 34-hex fires (varied hex bodies).
    let seg1 = "122b598615dcbe810beacd55"; // 24 hex
    let seg2 = "74bf20f876ffc474c0251908fcdce4b314"; // 34 hex
    assert_eq!((seg1.len(), seg2.len()), (24, 34));
    let ok = format!("PMAK-{seg1}-{seg2}\n");
    let hit = scan(&ok);
    assert!(
        hit.iter()
            .any(|m| m.detector_id.as_ref() == "postman-api-key"),
        "PMAK- with 24+34 hex must fire"
    );
    // 23-hex first segment must not (one below the {24} floor).
    let short1 = "122b598615dcbe810beacd5"; // 23 hex
    assert_eq!(short1.len(), 23);
    assert_no_hit("postman-api-key", &format!("PMAK-{short1}-{seg2}\n"));
}

// ----------------------------------------------------------------------------
// Adversarial / evasion: a credential split across realistic surrounding text
// (JSON, YAML, shell export) must still be detected, these prefixes are
// distinctive enough that surrounding noise must not suppress them.
// ----------------------------------------------------------------------------

#[test]
fn prefixes_fire_inside_realistic_surroundings() {
    let cases: &[(&str, &str)] = &[
        (
            "postman-api-key",
            "{\n  \"apiKey\": \"PMAK-606a8c2da5c08a004dfd060f-c7cdd622c690177cce465538021e349288\"\n}",
        ),
        (
            "slack-app-token",
            "  app_token: xapp-1-A012B3CDEFG-1234567890123-1f9a0b7c4e2d6a8b3c5f7e9d0a1b2c3d",
        ),
        (
            "gitlab-runner-authentication-token",
            "export RUNNER_TOKEN='glrt-2CR8_eVxiioB1QmzPZwa'",
        ),
    ];
    for (id, text) in cases {
        let matches = scan(text);
        assert!(
            matches.iter().any(|m| m.detector_id.as_ref() == *id),
            "{id} must fire inside realistic surroundings: {text:?}. Got: {:?}",
            matches
                .iter()
                .map(|m| m.detector_id.as_ref())
                .collect::<Vec<_>>()
        );
    }
}

// ----------------------------------------------------------------------------
// Generative (proptest-style) loop: deterministically synthesize many valid
// tokens of each shape and assert the matching detector fires on every one.
// A regression that re-narrows a charset or length band trips this.
// ----------------------------------------------------------------------------

/// Tiny deterministic xorshift PRNG, keeps the test self-contained (no
/// external proptest/rand dep) while still exercising a broad token space.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn pick(&mut self, alphabet: &[u8]) -> u8 {
        alphabet[(self.next_u64() as usize) % alphabet.len()]
    }
    fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| self.pick(alphabet) as char)
            .collect::<String>()
    }
}

#[test]
fn generative_postman_keys_all_fire() {
    let hex = b"0123456789abcdef";
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    for i in 0..200 {
        let seg1 = rng.string(hex, 24);
        let seg2 = rng.string(hex, 34);
        let secret = format!("PMAK-{seg1}-{seg2}");
        let text = format!("POSTMAN_API_KEY={secret}\n");
        let matches = scan(&text);
        let hit = matches
            .iter()
            .find(|m| m.detector_id.as_ref() == "postman-api-key");
        assert!(
            hit.is_some(),
            "iter {i}: postman-api-key failed to fire on a valid PMAK token {secret:?}"
        );
        assert_eq!(
            hit.unwrap().credential.as_ref(),
            secret,
            "iter {i}: capture mismatch for {secret:?}"
        );
    }
}

#[test]
fn generative_glrt_tokens_all_fire() {
    let b64url = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut rng = Rng(0x5eed_dead_beef_0002);
    for i in 0..200 {
        let body = rng.string(b64url, 20);
        let secret = format!("glrt-{body}");
        let text = format!("RUNNER_TOKEN={secret}\n");
        let matches = scan(&text);
        assert!(
            matches
                .iter()
                .any(|m| m.detector_id.as_ref() == "gitlab-runner-authentication-token"),
            "iter {i}: gitlab runner detector failed on valid glrt token {secret:?}"
        );
    }
}

#[test]
fn generative_xapp_tokens_all_fire() {
    let appid = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let hexl = b"0123456789abcdef";
    let mut rng = Rng(0x5eed_cafe_f00d_0003);
    for i in 0..200 {
        // Hoist each length draw before the `rng.string(...)` call: a nested
        // `rng.string(_, rng.next_u64()…)` borrows `rng` mutably twice in one
        // expression (receiver + arg) and is rejected by the borrow checker.
        let app_len = 9 + (rng.next_u64() as usize % 4);
        let app = format!("A{}", rng.string(appid, app_len));
        let inst_len = 12 + (rng.next_u64() as usize % 3);
        let inst = rng.string(b"0123456789", inst_len);
        let body_len = 32 + (rng.next_u64() as usize % 33);
        let secret_body = rng.string(hexl, body_len);
        let secret = format!("xapp-1-{app}-{inst}-{secret_body}");
        let text = format!("SLACK_APP_TOKEN={secret}\n");
        let matches = scan(&text);
        assert!(
            matches
                .iter()
                .any(|m| m.detector_id.as_ref() == "slack-app-token"),
            "iter {i}: slack-app-token failed on valid xapp token {secret:?}"
        );
    }
}
