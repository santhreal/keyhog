//! Gap-closure integration tests for keyhog-verifier OOB + rate-limit surfaces.
//!
//! Coverage area `oob_ratelimit`:
//!   - OOB interaction protocol parse (`InteractionProtocol::parse`) and the
//!     `OobAccept` filter + its `From<keyhog_core::OobProtocol>` mapping.
//!   - Transport-error redaction (`redact_interactsh_error`) — exact Display
//!     bytes for every non-Transport variant, asserting the URL/secret never
//!     leaks.
//!   - Rate limiter: per-service override independence, NaN/inf/zero/negative/
//!     subnormal/huge clamps (via the observable `default_interval()`), the
//!     exact `rps_to_nanos` rounding/fallback boundaries, `set_default_rps`
//!     hot-swap, `update_limit` slot reset, and the >50-error backpressure
//!     floor boundary.
//!   - OOB session observation plumbing: `mint`/`mint_url` shape, `wait_for`
//!     protocol filtering, earliest-match-wins, NotObserved on timeout, and
//!     Disabled after shutdown.
//!
//! Every expected value is derived by reading crates/verifier/src/rate_limit.rs,
//! crates/verifier/src/oob/{client,session,decrypt}.rs and
//! crates/core/src/spec.rs (OobProtocol).

use std::sync::Arc;
use std::time::{Duration, Instant};

use keyhog_verifier::oob::{
    redact_interactsh_error, Interaction, InteractionProtocol, InteractshClient, InteractshError,
    OobAccept, OobConfig, OobObservation, OobSession,
};
use keyhog_verifier::rate_limit::{get_rate_limiter, set_global_default_rps, RateLimiter};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

// ------------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------------

/// Construct a `for_test` client against a server string; unwrap the Result.
fn test_client(server: &str) -> Arc<InteractshClient> {
    Arc::new(
        TestApi
            .interactsh_client_for_test(server)
            .expect("for_test RSA keygen must succeed"),
    )
}

/// Build a session with the default OOB config and a `for_test` client.
fn test_session(server: &str) -> Arc<OobSession> {
    TestApi.oob_session_for_test(test_client(server), OobConfig::default())
}

fn interaction(id: &str, proto: InteractionProtocol, remote: &str) -> Interaction {
    Interaction {
        unique_id: id.into(),
        protocol: proto,
        remote_address: remote.into(),
        timestamp: "2026-06-02T00:00:00Z".into(),
        raw_payload: "GET / HTTP/1.1".into(),
    }
}

// ========================================================================
// 1. InteractionProtocol::parse  (protocol parse)
// ========================================================================

#[test]
fn parse_dns_exact_lowercase() {
    assert_eq!(InteractionProtocol::parse("dns"), InteractionProtocol::Dns);
}

#[test]
fn parse_http_exact_lowercase() {
    assert_eq!(
        InteractionProtocol::parse("http"),
        InteractionProtocol::Http
    );
}

#[test]
fn parse_smtp_and_smtp_mail_both_map_to_smtp() {
    assert_eq!(
        InteractionProtocol::parse("smtp"),
        InteractionProtocol::Smtp
    );
    assert_eq!(
        InteractionProtocol::parse("smtp-mail"),
        InteractionProtocol::Smtp
    );
}

#[test]
fn parse_is_ascii_case_folding_only() {
    // to_ascii_lowercase folds ASCII case; mixed case still maps.
    assert_eq!(
        InteractionProtocol::parse("HtTp"),
        InteractionProtocol::Http
    );
    assert_eq!(
        InteractionProtocol::parse("SMTP-MAIL"),
        InteractionProtocol::Smtp
    );
    assert_eq!(InteractionProtocol::parse("DnS"), InteractionProtocol::Dns);
}

#[test]
fn parse_unknown_and_near_misses_are_other() {
    // Negative twins: anything outside the exact set is Other.
    for s in [
        "", "ftp", "ssh", "https", "http2", "dns-tcp", "smtps", "smtp2", "dnsx", " dns", "dns ",
        "ldap", "tcp", "icmp",
    ] {
        assert_eq!(
            InteractionProtocol::parse(s),
            InteractionProtocol::Other,
            "{s:?} must parse to Other"
        );
    }
}

#[test]
fn parse_whitespace_padded_is_other_no_trim() {
    // parse() does NOT trim; surrounding whitespace defeats the exact match.
    assert_eq!(
        InteractionProtocol::parse(" dns "),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("\tdns\n"),
        InteractionProtocol::Other
    );
}

#[test]
fn parse_non_ascii_uppercase_does_not_fold() {
    // to_ascii_lowercase leaves non-ASCII untouched; a fullwidth/unicode
    // variant cannot collapse onto an ASCII keyword.
    assert_eq!(
        InteractionProtocol::parse("ＤＮＳ"),
        InteractionProtocol::Other
    );
    assert_eq!(
        InteractionProtocol::parse("dnß"),
        InteractionProtocol::Other
    );
}

#[test]
fn protocol_variants_are_all_distinct() {
    let all = [
        InteractionProtocol::Dns,
        InteractionProtocol::Http,
        InteractionProtocol::Smtp,
        InteractionProtocol::Other,
    ];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i == j {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b, "variants {i} and {j} must differ");
            }
        }
    }
}

#[test]
fn parse_roundtrips_for_canonical_strings_property() {
    // Property-style loop: every canonical string round-trips to its variant
    // regardless of ASCII case permutation.
    let cases: &[(&str, InteractionProtocol)] = &[
        ("dns", InteractionProtocol::Dns),
        ("http", InteractionProtocol::Http),
        ("smtp", InteractionProtocol::Smtp),
        ("smtp-mail", InteractionProtocol::Smtp),
    ];
    for (base, expected) in cases {
        // toggle case of each char in a handful of permutations
        let upper = base.to_ascii_uppercase();
        let title: String = base
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        for variant in [base.to_string(), upper, title] {
            assert_eq!(
                InteractionProtocol::parse(&variant),
                *expected,
                "{variant:?} should parse to {expected:?}"
            );
        }
    }
}

// ========================================================================
// 2. OobAccept filter + From<keyhog_core::OobProtocol>
// ========================================================================

#[test]
fn accept_dns_matches_only_dns() {
    assert!(OobAccept::Dns.matches(InteractionProtocol::Dns));
    assert!(!OobAccept::Dns.matches(InteractionProtocol::Http));
    assert!(!OobAccept::Dns.matches(InteractionProtocol::Smtp));
    assert!(!OobAccept::Dns.matches(InteractionProtocol::Other));
}

#[test]
fn accept_http_matches_only_http() {
    assert!(OobAccept::Http.matches(InteractionProtocol::Http));
    assert!(!OobAccept::Http.matches(InteractionProtocol::Dns));
    assert!(!OobAccept::Http.matches(InteractionProtocol::Smtp));
    assert!(!OobAccept::Http.matches(InteractionProtocol::Other));
}

#[test]
fn accept_smtp_matches_only_smtp() {
    assert!(OobAccept::Smtp.matches(InteractionProtocol::Smtp));
    assert!(!OobAccept::Smtp.matches(InteractionProtocol::Dns));
    assert!(!OobAccept::Smtp.matches(InteractionProtocol::Http));
    assert!(!OobAccept::Smtp.matches(InteractionProtocol::Other));
}

#[test]
fn accept_any_matches_every_protocol_including_other() {
    assert!(OobAccept::Any.matches(InteractionProtocol::Dns));
    assert!(OobAccept::Any.matches(InteractionProtocol::Http));
    assert!(OobAccept::Any.matches(InteractionProtocol::Smtp));
    // Critically `Any` even matches `Other` — the catch-all arm `(Self::Any, _)`.
    assert!(OobAccept::Any.matches(InteractionProtocol::Other));
}

#[test]
fn accept_no_non_any_variant_matches_other() {
    // `Other` is unreachable for the strict filters: only `Any` admits it.
    assert!(!OobAccept::Dns.matches(InteractionProtocol::Other));
    assert!(!OobAccept::Http.matches(InteractionProtocol::Other));
    assert!(!OobAccept::Smtp.matches(InteractionProtocol::Other));
    assert!(OobAccept::Any.matches(InteractionProtocol::Other));
}

#[test]
fn accept_from_core_oob_protocol_maps_each_variant() {
    // From<keyhog_core::OobProtocol> — the CLI/spec → verifier bridge.
    assert!(OobAccept::from(keyhog_core::OobProtocol::Dns).matches(InteractionProtocol::Dns));
    assert!(!OobAccept::from(keyhog_core::OobProtocol::Dns).matches(InteractionProtocol::Http));

    assert!(OobAccept::from(keyhog_core::OobProtocol::Http).matches(InteractionProtocol::Http));
    assert!(!OobAccept::from(keyhog_core::OobProtocol::Http).matches(InteractionProtocol::Dns));

    assert!(OobAccept::from(keyhog_core::OobProtocol::Smtp).matches(InteractionProtocol::Smtp));
    assert!(!OobAccept::from(keyhog_core::OobProtocol::Smtp).matches(InteractionProtocol::Http));

    // Any maps to the catch-all filter.
    let any = OobAccept::from(keyhog_core::OobProtocol::Any);
    assert!(any.matches(InteractionProtocol::Dns));
    assert!(any.matches(InteractionProtocol::Http));
    assert!(any.matches(InteractionProtocol::Smtp));
    assert!(any.matches(InteractionProtocol::Other));
}

#[test]
fn accept_filter_matches_property_grid() {
    // Exhaustive (accept, protocol) grid asserted against the documented
    // truth table.
    let accepts = [
        OobAccept::Dns,
        OobAccept::Http,
        OobAccept::Smtp,
        OobAccept::Any,
    ];
    let protos = [
        InteractionProtocol::Dns,
        InteractionProtocol::Http,
        InteractionProtocol::Smtp,
        InteractionProtocol::Other,
    ];
    for a in accepts {
        for p in protos {
            let expected = matches!(
                (a, p),
                (OobAccept::Any, _)
                    | (OobAccept::Dns, InteractionProtocol::Dns)
                    | (OobAccept::Http, InteractionProtocol::Http)
                    | (OobAccept::Smtp, InteractionProtocol::Smtp)
            );
            assert_eq!(
                a.matches(p),
                expected,
                "matches({a:?}, {p:?}) should be {expected}"
            );
        }
    }
}

// ========================================================================
// 3. redact_interactsh_error  (transport-error redaction)
// ========================================================================

#[test]
fn redact_register_error_exact_display_no_secret() {
    let e = InteractshError::Register {
        status: 401,
        body: "unauthorized".into(),
    };
    let out = redact_interactsh_error(&e);
    assert_eq!(out, "interactsh register failed (HTTP 401): unauthorized");
    assert!(!out.contains("?secret="));
}

#[test]
fn redact_poll_error_exact_display_no_secret() {
    let e = InteractshError::Poll {
        status: 500,
        body: "boom".into(),
    };
    let out = redact_interactsh_error(&e);
    assert_eq!(out, "interactsh poll failed (HTTP 500): boom");
    assert!(!out.contains("secret"));
}

#[test]
fn redact_bad_response_exact_display() {
    let e = InteractshError::BadResponse("data present but aes_key missing".into());
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh response shape unexpected: data present but aes_key missing"
    );
}

#[test]
fn redact_keygen_exact_display() {
    let e = InteractshError::KeyGen("rng exhausted".into());
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh keypair generation failed: rng exhausted"
    );
}

#[test]
fn redact_key_encode_exact_display() {
    let e = InteractshError::KeyEncode("pem error".into());
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh public-key encoding failed: pem error"
    );
}

#[test]
fn redact_blocked_collector_exact_display() {
    let e = InteractshError::BlockedCollector(
        "https://169.254.169.254 resolves to a private/loopback/link-local address".into(),
    );
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh collector host blocked by SSRF guard: https://169.254.169.254 resolves to a private/loopback/link-local address"
    );
}

#[test]
fn collector_ssrf_dns_resolution_failure_blocks_before_contact() {
    let err = TestApi
        .oob_collector_ssrf_check_dns_result(
            "https://collector.example",
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "synthetic dns timeout",
            )),
        )
        .expect_err("collector DNS failure must fail closed");
    let display = redact_interactsh_error(&err);
    assert!(
        display.contains("DNS resolution failed before SSRF screening")
            && display.contains("collector was not contacted")
            && display.contains("synthetic dns timeout"),
        "DNS resolution failure must block the collector request loudly, got {display}"
    );
}

#[test]
fn collector_ssrf_empty_dns_answer_blocks_before_contact() {
    let err = TestApi
        .oob_collector_ssrf_check_dns_result("https://collector.example", Ok(Vec::new()))
        .expect_err("empty collector DNS answer must fail closed");
    let display = redact_interactsh_error(&err);
    assert!(
        display.contains("DNS returned no addresses")
            && display.contains("collector was not contacted"),
        "empty DNS answer must block the collector request loudly, got {display}"
    );
}

#[test]
fn collector_ssrf_public_dns_answer_is_allowed() {
    let public = "8.8.8.8:443"
        .parse()
        .expect("public socket address should parse");
    TestApi
        .oob_collector_ssrf_check_dns_result("https://collector.example", Ok(vec![public]))
        .expect("public collector address should pass the SSRF screen");
}

#[test]
fn redact_aes_unwrap_exact_display() {
    let e = InteractshError::AesUnwrap("expected 32-byte AES-256 key, got 16".into());
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh AES key unwrap failed: expected 32-byte AES-256 key, got 16"
    );
}

#[test]
fn redact_decrypt_exact_display() {
    let e = InteractshError::Decrypt("base64: invalid".into());
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh interaction decrypt failed: base64: invalid"
    );
}

#[test]
fn redact_timeout_exact_display_secs() {
    let e = InteractshError::Timeout(Duration::from_secs(30));
    // Duration Debug for whole seconds renders as `30s`.
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh request timed out after 30s"
    );
}

#[test]
fn redact_timeout_exact_display_millis() {
    let e = InteractshError::Timeout(Duration::from_millis(1500));
    assert_eq!(
        redact_interactsh_error(&e),
        "interactsh request timed out after 1.5s"
    );
}

#[test]
fn redact_never_leaks_secret_query_param_for_any_constructible_variant() {
    // Adversarial: stuff a fake secret into every string-bearing variant and
    // confirm redaction output is the hand-written Display (which contains no
    // `?secret=` framing). The point of the redactor is the Transport arm, but
    // the contract is "no variant's redacted form leaks a poll URL/secret".
    let poisoned = "?secret=deadbeef&id=abc";
    let variants = vec![
        InteractshError::Register {
            status: 403,
            body: poisoned.into(),
        },
        InteractshError::Poll {
            status: 429,
            body: poisoned.into(),
        },
        InteractshError::BadResponse(poisoned.into()),
        InteractshError::KeyGen(poisoned.into()),
        InteractshError::KeyEncode(poisoned.into()),
        InteractshError::BlockedCollector(poisoned.into()),
        InteractshError::AesUnwrap(poisoned.into()),
        InteractshError::Decrypt(poisoned.into()),
    ];
    for v in &variants {
        let out = redact_interactsh_error(v);
        // The body text we injected is echoed (these variants carry no URL of
        // their own); the contract is only that the redactor never *adds* a
        // poll URL. Assert the output equals the Display impl exactly.
        assert_eq!(
            out,
            format!("{v}"),
            "non-transport variant must pass through Display verbatim"
        );
    }
}

// ========================================================================
// 4. rps_to_nanos clamps + default_interval  (rate-limit clamps)
// ========================================================================

#[test]
fn default_interval_exact_for_common_rps() {
    assert_eq!(
        RateLimiter::new(5.0).default_interval(),
        Duration::from_millis(200)
    );
    assert_eq!(
        RateLimiter::new(2.0).default_interval(),
        Duration::from_millis(500)
    );
    assert_eq!(
        RateLimiter::new(4.0).default_interval(),
        Duration::from_millis(250)
    );
    assert_eq!(
        RateLimiter::new(10.0).default_interval(),
        Duration::from_millis(100)
    );
    assert_eq!(
        RateLimiter::new(20.0).default_interval(),
        Duration::from_millis(50)
    );
    assert_eq!(
        RateLimiter::new(50.0).default_interval(),
        Duration::from_millis(20)
    );
    assert_eq!(
        RateLimiter::new(1000.0).default_interval(),
        Duration::from_micros(1000)
    );
    assert_eq!(
        RateLimiter::new(0.5).default_interval(),
        Duration::from_secs(2)
    );
}

#[test]
fn default_interval_nan_clamps_to_one_second() {
    assert_eq!(
        RateLimiter::new(f64::NAN).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_pos_inf_clamps_to_one_second() {
    assert_eq!(
        RateLimiter::new(f64::INFINITY).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_neg_inf_clamps_to_one_second() {
    assert_eq!(
        RateLimiter::new(f64::NEG_INFINITY).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_zero_clamps_to_one_second() {
    assert_eq!(
        RateLimiter::new(0.0).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_negative_clamps_to_one_second() {
    assert_eq!(
        RateLimiter::new(-1.0).default_interval(),
        Duration::from_secs(1)
    );
    assert_eq!(
        RateLimiter::new(-42.0).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_subnormal_rps_falls_back_to_one_second() {
    // 1e9 / MIN_POSITIVE ~= 4.5e316 which exceeds u64::MAX as f64 (~1.8e19),
    // so the `nanos <= u64::MAX as f64` guard fails → 1s fallback.
    assert_eq!(
        RateLimiter::new(f64::MIN_POSITIVE).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_huge_rps_rounds_below_one_falls_back_to_one_second() {
    // 1e9 / 1e10 = 0.1 -> round() = 0.0 -> 0 < 1.0 -> fallback 1s.
    assert_eq!(
        RateLimiter::new(1e10).default_interval(),
        Duration::from_secs(1)
    );
    // 1e9 / 3e9 = 0.333 -> round 0 -> fallback.
    assert_eq!(
        RateLimiter::new(3e9).default_interval(),
        Duration::from_secs(1)
    );
    // 1e100 -> ~1e-91 -> round 0 -> fallback.
    assert_eq!(
        RateLimiter::new(1e100).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_one_nanosecond_boundary() {
    // 1e9 / 1e9 = 1.0 -> round 1.0 -> exactly 1 ns (the smallest non-fallback).
    assert_eq!(
        RateLimiter::new(1e9).default_interval(),
        Duration::from_nanos(1)
    );
    // 1e9 / 2e9 = 0.5 -> round() rounds half away from zero -> 1.0 -> 1 ns.
    assert_eq!(
        RateLimiter::new(2e9).default_interval(),
        Duration::from_nanos(1)
    );
}

#[test]
fn default_interval_one_rps_is_one_second() {
    assert_eq!(
        RateLimiter::new(1.0).default_interval(),
        Duration::from_secs(1)
    );
}

#[test]
fn default_interval_property_inverse_relation_for_valid_rps() {
    // For finite rps in [1, 1e6], the interval equals round(1e9/rps) ns.
    for rps_int in 1u64..=200 {
        let rps = rps_int as f64;
        let expected_nanos = (1.0e9 / rps).round() as u64;
        assert_eq!(
            RateLimiter::new(rps).default_interval(),
            Duration::from_nanos(expected_nanos),
            "rps={rps} should give {expected_nanos} ns"
        );
    }
}

// ========================================================================
// 5. set_default_rps hot-swap
// ========================================================================

#[test]
fn set_default_rps_hot_swaps_interval() {
    let limiter = RateLimiter::new(5.0);
    assert_eq!(limiter.default_interval(), Duration::from_millis(200));
    limiter.set_default_rps(50.0);
    assert_eq!(limiter.default_interval(), Duration::from_millis(20));
    // Hot-swap also honors the clamp.
    limiter.set_default_rps(0.0);
    assert_eq!(limiter.default_interval(), Duration::from_secs(1));
    limiter.set_default_rps(f64::NAN);
    assert_eq!(limiter.default_interval(), Duration::from_secs(1));
}

#[test]
fn set_default_rps_can_raise_after_clamp() {
    let limiter = RateLimiter::new(f64::NAN); // clamped to 1s
    assert_eq!(limiter.default_interval(), Duration::from_secs(1));
    limiter.set_default_rps(4.0);
    assert_eq!(limiter.default_interval(), Duration::from_millis(250));
}

#[test]
fn global_set_default_rps_updates_shared_limiter() {
    // The process-wide limiter is lazily created at 5 rps; the CLI setter
    // retunes it. Use a distinctive value and read it back.
    set_global_default_rps(8.0);
    assert_eq!(
        get_rate_limiter().default_interval(),
        Duration::from_micros(125_000),
        "8 rps -> 125ms"
    );
    // Re-tune again; must reflect the new value (idempotent setter).
    set_global_default_rps(40.0);
    assert_eq!(
        get_rate_limiter().default_interval(),
        Duration::from_millis(25),
        "40 rps -> 25ms"
    );
}

// ========================================================================
// 6. update_limit  (per-service override + clamp independence)
// ========================================================================

#[tokio::test]
async fn update_limit_does_not_change_default_interval() {
    let limiter = RateLimiter::new(10.0); // 100ms default
    limiter.update_limit("svc_a", 1.0).await; // 1s override
    assert_eq!(
        limiter.default_interval(),
        Duration::from_millis(100),
        "per-service override must not touch the default"
    );
    limiter.update_limit("svc_b", 200.0).await; // 5ms override
    assert_eq!(limiter.default_interval(), Duration::from_millis(100));
}

#[tokio::test]
async fn update_limit_clamps_invalid_rps_without_panic() {
    let limiter = RateLimiter::new(10.0);
    // NaN / inf / zero / negative all clamp to a 1s interval internally; the
    // first wait against a freshly-updated service is delayed by the interval
    // (update sets last_request = now), so we keep the assertion to "no panic"
    // and a generous upper bound for the clamped (1s) services is avoided here
    // to keep the suite fast — see update_limit_zero_first_wait_is_delayed.
    limiter.update_limit("nan_svc", f64::NAN).await;
    limiter.update_limit("inf_svc", f64::INFINITY).await;
    limiter.update_limit("neg_svc", -3.0).await;
    // These don't block long because the override is a fast 1000 rps (1ms).
    limiter.update_limit("fast_svc", 1000.0).await;
    let t0 = Instant::now();
    limiter.wait("fast_svc").await; // first wait delayed ~1ms
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "1000 rps override first wait should be ~1ms, well under 1s"
    );
}

#[tokio::test]
async fn update_limit_first_wait_is_delayed_by_interval() {
    // update_limit sets last_request = Instant::now() (NOT now - interval),
    // so unlike the lazily-created default entry, the FIRST wait after an
    // override is delayed by a full interval.
    let limiter = RateLimiter::new(1000.0); // fast default so default path is ~instant
    limiter.update_limit("svc", 20.0).await; // 50ms interval, last_request=now
    let t0 = Instant::now();
    limiter.wait("svc").await;
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= Duration::from_millis(40),
        "first wait after update_limit must be delayed ~50ms, got {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_millis(400),
        "but not absurdly long, got {elapsed:?}"
    );
}

#[tokio::test]
async fn lazily_created_default_service_first_wait_is_instant() {
    // The lazy default path seeds last_request = now - default, so the first
    // wait fires immediately (next_slot == now).
    let limiter = RateLimiter::new(2.0); // 500ms default interval
    let t0 = Instant::now();
    limiter.wait("never_seen_before").await;
    assert!(
        t0.elapsed() < Duration::from_millis(200),
        "first default wait should be ~instant, got {:?}",
        t0.elapsed()
    );
}

#[tokio::test]
async fn back_to_back_default_waits_queue_by_interval() {
    let limiter = RateLimiter::new(20.0); // 50ms interval
    let t0 = Instant::now();
    limiter.wait("svc").await; // instant (lazy seed)
    limiter.wait("svc").await; // queued ~50ms after first slot
    limiter.wait("svc").await; // queued ~50ms after that
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= Duration::from_millis(90),
        "three queued waits at 50ms must take >= ~100ms, got {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "but should not balloon, got {elapsed:?}"
    );
}

#[tokio::test]
async fn update_limit_overrides_an_existing_lazy_default_entry() {
    // First touch creates a lazy default entry; update_limit then *replaces*
    // it (DashMap::insert) with the override interval and last_request=now.
    let limiter = RateLimiter::new(1000.0); // 1ms default
    limiter.wait("svc").await; // lazily create default entry
    limiter.update_limit("svc", 10.0).await; // replace with 100ms, last_request=now
    let t0 = Instant::now();
    limiter.wait("svc").await; // delayed ~100ms by the fresh override slot
    assert!(
        t0.elapsed() >= Duration::from_millis(80),
        "post-override wait must honor the new 100ms interval, got {:?}",
        t0.elapsed()
    );
}

// ========================================================================
// 7. Backpressure floor boundary (> 50 errors)
// ========================================================================

#[tokio::test]
async fn record_success_saturates_at_zero_no_underflow() {
    // record_success uses saturating_sub on a usize; calling it on a fresh
    // limiter (count 0) must not underflow/panic.
    let limiter = RateLimiter::new(1000.0);
    for _ in 0..10 {
        limiter.record_success();
    }
    // Still functional afterwards.
    limiter.wait("svc").await;
}

#[tokio::test]
async fn backpressure_not_engaged_at_exactly_50_errors() {
    // bp triggers only when count > 50. At exactly 50, the second (queued)
    // wait gets only the configured tiny interval, NOT the 1s floor.
    let limiter = RateLimiter::new(1000.0); // 1ms interval
    for _ in 0..50 {
        limiter.record_error();
    }
    let t0 = Instant::now();
    limiter.wait("svc").await; // instant (lazy seed)
    limiter.wait("svc").await; // queued ~1ms; bp not engaged
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "at 50 errors no 1s backpressure floor should apply, got {:?}",
        t0.elapsed()
    );
}

#[tokio::test]
async fn backpressure_engages_above_50_errors_with_one_second_floor() {
    // Adversarial: 51 errors crosses the `> 50` threshold. The first wait on a
    // fresh service is instant (wait_time None, no sleep), but the second
    // queued wait sleeps `wait.max(bp)` = max(~1ms, 1s) = 1s.
    let limiter = RateLimiter::new(1000.0); // 1ms interval
    for _ in 0..51 {
        limiter.record_error();
    }
    let t0 = Instant::now();
    limiter.wait("svc").await; // instant: no sleep -> bp not applied
    limiter.wait("svc").await; // queued: sleeps max(1ms, 1s) = 1s
    let elapsed = t0.elapsed();
    assert!(
        elapsed >= Duration::from_millis(950),
        "above-threshold queued wait must apply the 1s backpressure floor, got {elapsed:?}"
    );
}

#[tokio::test]
async fn backpressure_clears_after_enough_successes() {
    let limiter = RateLimiter::new(1000.0);
    for _ in 0..51 {
        limiter.record_error();
    }
    // Drive the count back down below the threshold.
    for _ in 0..51 {
        limiter.record_success();
    }
    let t0 = Instant::now();
    limiter.wait("svc").await;
    limiter.wait("svc").await; // should NOT incur the 1s floor anymore
    assert!(
        t0.elapsed() < Duration::from_millis(500),
        "after successes pull count below 51, no backpressure floor, got {:?}",
        t0.elapsed()
    );
}

// ========================================================================
// 8. mint / mint_url shape + normalize_server (observable via host/url)
// ========================================================================

#[test]
fn client_for_test_correlation_id_is_fixed_24_chars() {
    let client = test_client("oast.fun");
    assert_eq!(
        TestApi.interactsh_client_correlation_id(&client),
        "abcdefghijklmnopqrstuvwx"
    );
    assert_eq!(TestApi.interactsh_client_correlation_id(&client).len(), 24);
}

#[test]
fn mint_url_unique_id_is_48_chars_corr_plus_24_suffix() {
    let client = test_client("oast.fun");
    let minted = TestApi.interactsh_client_mint_url(&client);
    assert_eq!(minted.unique_id.len(), 48, "24 corr + 24 suffix = 48");
    assert!(
        minted.unique_id.len() < 63,
        "unique-id remains one DNS label under the 63-octet label limit"
    );
    assert!(
        minted
            .unique_id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "unique_id must be DNS-safe lowercase alphanumeric, got {:?}",
        minted.unique_id
    );
    assert!(
        minted.unique_id.starts_with("abcdefghijklmnopqrstuvwx"),
        "unique_id must begin with the correlation id"
    );
    // Suffix is 24 uniformly sampled lowercase DNS-safe alphanumerics.
    let suffix = &minted.unique_id[24..];
    assert_eq!(suffix.len(), 24);
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "suffix must be [a-z0-9], got {suffix:?}"
    );
}

#[test]
fn mint_url_host_and_url_compose_from_server_host() {
    let client = test_client("oast.fun");
    let minted = TestApi.interactsh_client_mint_url(&client);
    let expected_host = format!("{}.oast.fun", minted.unique_id);
    assert_eq!(minted.host, expected_host);
    assert_eq!(minted.url, format!("https://{expected_host}"));
    assert!(minted.url.starts_with("https://"));
}

#[test]
fn mint_url_normalizes_https_scheme_and_strips_trailing_slash() {
    // normalize_server: trim, drop trailing '/', force https; server_host then
    // strips scheme. So all of these yield host suffix `.example.test`.
    for server in [
        "example.test",
        "https://example.test",
        "https://example.test/",
        "  example.test  ",
    ] {
        let client = test_client(server);
        let minted = TestApi.interactsh_client_mint_url(&client);
        assert!(
            minted.host.ends_with(".example.test"),
            "{server:?} -> host {:?} should end with .example.test",
            minted.host
        );
        assert!(
            !minted.host.contains("https://") && !minted.host.contains('/'),
            "host must be bare (no scheme/slash): {:?}",
            minted.host
        );
        assert!(minted.url.starts_with("https://"));
    }
}

#[test]
fn mint_url_force_upgrades_http_to_https() {
    // normalize_server force-upgrades http:// to https://; the host portion
    // is still example.test and the url is https://.
    let client = test_client("http://example.test");
    let minted = TestApi.interactsh_client_mint_url(&client);
    assert!(minted.host.ends_with(".example.test"));
    assert!(
        minted.url.starts_with("https://"),
        "plaintext collector must be force-upgraded, got {:?}",
        minted.url
    );
    assert!(!minted.url.contains("http://"));
}

#[test]
fn mint_url_two_mints_differ_in_suffix() {
    let client = test_client("oast.fun");
    let a = TestApi.interactsh_client_mint_url(&client);
    let b = TestApi.interactsh_client_mint_url(&client);
    assert_eq!(
        &a.unique_id[..24],
        &b.unique_id[..24],
        "same correlation id"
    );
    assert_ne!(
        a.unique_id, b.unique_id,
        "24-char random suffix must (overwhelmingly) differ"
    );
}

#[test]
fn session_mint_delegates_to_client_mint_url() {
    let session = test_session("oast.fun");
    let minted = TestApi.oob_session_mint(&session);
    assert_eq!(minted.unique_id.len(), 48);
    assert!(minted.unique_id.starts_with("abcdefghijklmnopqrstuvwx"));
    assert_eq!(minted.host, format!("{}.oast.fun", minted.unique_id));
}

// ========================================================================
// 9. OobSession::wait_for / peek_match observation plumbing
// ========================================================================

#[tokio::test]
async fn wait_for_returns_observed_when_stored_before_wait() {
    let session = test_session("https://example.test");
    let id = "abcdefghijklmnopqrstaaaaaaaaaaaaa";
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(id, InteractionProtocol::Dns, "9.9.9.9"),
    );
    let obs = session
        .wait_for(id, OobAccept::Dns, Duration::from_secs(2))
        .await;
    match obs {
        OobObservation::Observed {
            protocol,
            remote_address,
            timestamp,
            raw_payload,
        } => {
            assert_eq!(protocol, InteractionProtocol::Dns);
            assert_eq!(remote_address, "9.9.9.9");
            assert_eq!(timestamp, "2026-06-02T00:00:00Z");
            assert_eq!(raw_payload, "GET / HTTP/1.1");
        }
        other => panic!("expected Observed, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_times_out_to_not_observed_when_nothing_stored() {
    let session = test_session("https://example.test");
    let id = "abcdefghijklmnopqrstbbbbbbbbbbbbb";
    let t0 = Instant::now();
    let obs = session
        .wait_for(id, OobAccept::Http, Duration::from_millis(150))
        .await;
    assert!(matches!(obs, OobObservation::NotObserved), "got {obs:?}");
    assert!(
        t0.elapsed() >= Duration::from_millis(120),
        "should have waited ~the full timeout, got {:?}",
        t0.elapsed()
    );
}

#[tokio::test]
async fn wait_for_protocol_filter_rejects_wrong_protocol_then_times_out() {
    // Stored a DNS interaction but we wait for HTTP only -> filter rejects ->
    // NotObserved after timeout (negative twin of the Observed case).
    let session = test_session("https://example.test");
    let id = "abcdefghijklmnopqrstccccccccccccc";
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(id, InteractionProtocol::Dns, "1.1.1.1"),
    );
    let obs = session
        .wait_for(id, OobAccept::Http, Duration::from_millis(150))
        .await;
    assert!(
        matches!(obs, OobObservation::NotObserved),
        "DNS stored, HTTP awaited -> NotObserved, got {obs:?}"
    );
}

#[tokio::test]
async fn wait_for_any_accepts_first_stored_regardless_of_protocol() {
    let session = test_session("https://example.test");
    let id = "abcdefghijklmnopqrstddddddddddddd";
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(id, InteractionProtocol::Other, "2.2.2.2"),
    );
    let obs = session
        .wait_for(id, OobAccept::Any, Duration::from_secs(2))
        .await;
    match obs {
        OobObservation::Observed {
            protocol,
            remote_address,
            ..
        } => {
            assert_eq!(protocol, InteractionProtocol::Other);
            assert_eq!(remote_address, "2.2.2.2");
        }
        other => panic!("Any should accept Other, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_earliest_matching_protocol_wins() {
    // Store two HTTP interactions; peek_match returns the FIRST stored (arrival
    // order). Confirms the documented "earliest-matching-protocol wins".
    let session = test_session("https://example.test");
    let id = "abcdefghijklmnopqrsteeeeeeeeeeeee";
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(id, InteractionProtocol::Http, "first-addr"),
    );
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(id, InteractionProtocol::Http, "second-addr"),
    );
    let obs = session
        .wait_for(id, OobAccept::Http, Duration::from_secs(2))
        .await;
    match obs {
        OobObservation::Observed { remote_address, .. } => {
            assert_eq!(remote_address, "first-addr", "first stored must win");
        }
        other => panic!("expected Observed, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_picks_matching_protocol_even_when_not_first() {
    // DNS arrives first, HTTP second; an HTTP-only wait must skip the DNS entry
    // and return the HTTP one (regression guard: multi-protocol storage).
    let session = test_session("https://example.test");
    let id = "abcdefghijklmnopqrstfffffffffffff";
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(id, InteractionProtocol::Dns, "dns-addr"),
    );
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(id, InteractionProtocol::Http, "http-addr"),
    );
    let obs = session
        .wait_for(id, OobAccept::Http, Duration::from_secs(2))
        .await;
    match obs {
        OobObservation::Observed {
            protocol,
            remote_address,
            ..
        } => {
            assert_eq!(protocol, InteractionProtocol::Http);
            assert_eq!(remote_address, "http-addr");
        }
        other => panic!("HTTP filter must find the HTTP entry, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_returns_disabled_after_abort_poller_for_drop() {
    let session = test_session("https://example.test");
    TestApi.oob_session_abort_poller_for_drop(&session);
    let id = "abcdefghijklmnopqrstggggggggggggg";
    let obs = session
        .wait_for(id, OobAccept::Any, Duration::from_secs(5))
        .await;
    match obs {
        OobObservation::Disabled(msg) => {
            assert_eq!(msg, "session shut down");
        }
        other => panic!("expected Disabled after shutdown, got {other:?}"),
    }
}

#[tokio::test]
async fn wait_for_disabled_is_immediate_not_blocked_to_timeout() {
    let session = test_session("https://example.test");
    TestApi.oob_session_abort_poller_for_drop(&session);
    let id = "abcdefghijklmnopqrsthhhhhhhhhhhhh";
    let t0 = Instant::now();
    let _ = session
        .wait_for(id, OobAccept::Any, Duration::from_secs(30))
        .await;
    assert!(
        t0.elapsed() < Duration::from_secs(1),
        "shutdown wait_for must short-circuit, not sleep the 30s timeout, got {:?}",
        t0.elapsed()
    );
}

#[tokio::test]
async fn wait_for_cancel_removes_waiter_entry() {
    let session = test_session("https://example.test");
    let id = "cancelledwaiterid000000000000000000";
    let parked = Arc::clone(&session);
    let waiter_id = id.to_string();
    let handle = tokio::spawn(async move {
        parked
            .wait_for(&waiter_id, OobAccept::Dns, Duration::from_secs(30))
            .await
    });

    for _ in 0..50 {
        if TestApi.oob_session_waiter_count(&session) == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        TestApi.oob_session_waiter_count(&session),
        1,
        "wait_for must register exactly one parked waiter before cancellation"
    );

    handle.abort();
    let _ = handle.await;
    for _ in 0..50 {
        if TestApi.oob_session_waiter_count(&session) == 0 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        TestApi.oob_session_waiter_count(&session),
        0,
        "dropping a wait_for future must remove its waiter entry"
    );
}

#[tokio::test]
async fn abort_poller_for_drop_is_idempotent() {
    let session = test_session("https://example.test");
    TestApi.oob_session_abort_poller_for_drop(&session);
    // Second call is a no-op (swap returns true) and must not panic.
    TestApi.oob_session_abort_poller_for_drop(&session);
    let obs = session
        .wait_for(
            "abcdefghijklmnopqrstiiiiiiiiiiiii",
            OobAccept::Any,
            Duration::from_millis(50),
        )
        .await;
    assert!(matches!(obs, OobObservation::Disabled(_)));
}

#[tokio::test]
async fn wait_for_no_match_for_unrelated_id_times_out() {
    // Store under one id; wait on a different id -> NotObserved (no cross-talk).
    let session = test_session("https://example.test");
    TestApi.oob_session_store_and_notify(
        &session,
        interaction(
            "abcdefghijklmnopqrstjjjjjjjjjjjjj",
            InteractionProtocol::Http,
            "x",
        ),
    );
    let obs = session
        .wait_for(
            "abcdefghijklmnopqrstkkkkkkkkkkkkk",
            OobAccept::Http,
            Duration::from_millis(120),
        )
        .await;
    assert!(matches!(obs, OobObservation::NotObserved), "got {obs:?}");
}

#[tokio::test]
async fn config_default_timeout_matches_oob_config_default() {
    let session = test_session("https://example.test");
    // OobConfig::default().default_timeout == 30s.
    assert_eq!(
        TestApi.oob_session_default_timeout(&session),
        Duration::from_secs(30)
    );
}

#[test]
fn oob_config_default_values_are_documented_constants() {
    let cfg = OobConfig::default();
    assert_eq!(cfg.server, "oast.fun");
    assert_eq!(cfg.default_timeout, Duration::from_secs(30));
    assert_eq!(cfg.max_timeout, Duration::from_secs(120));
    assert_eq!(cfg.poll_interval, Duration::from_secs(2));
    assert_eq!(cfg.max_observation_age, Duration::from_secs(600));
}
