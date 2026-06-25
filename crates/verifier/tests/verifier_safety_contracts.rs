//! Lane-8 (verifier-safety) regression contracts.
//!
//! Each test here pins one safety invariant of the live credential-verification
//! path and goes RED if that invariant regresses. Every assertion checks a
//! concrete value (exact error string, exact byte presence/absence, exact
//! result variant) — never `is_ok()` / `!is_empty()` decoration.
//!
//! Covered invariants:
//!   1. Response bodies are hard-capped (decompression/OOM-bomb defense).
//!   2. Internal / link-local targets (cloud IMDS, loopback) are refused
//!      BEFORE any outbound request — even when the detector allowlists them.
//!   3. The raw credential never appears in ANY emitted `VerifiedFinding`
//!      string (verification result, metadata keys/values, redacted form).
//!   4. A per-request timeout is enforced against a slow server.
//!   5. The DNS-pin client-build failure path FAILS CLOSED (no silent
//!      fallback to an unpinned client — the DNS-rebinding-window reopen
//!      Law-10 bug). Pinned at the source so a refactor that reintroduces
//!      the fallback trips immediately.
//!   6. The verifier's reqwest does not enable auto-decompression features,
//!      so the 1 MB streaming cap measures real wire bytes (no inflate-then-
//!      cap gzip bomb).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{
    AuthSpec, DedupedMatch, DetectorSpec, HeaderSpec, HttpMethod, MatchLocation, MetadataSpec,
    ScriptEngine, Severity, VerificationResult, VerifySpec,
};
use keyhog_verifier::{VerificationEngine, VerifyConfig};
use rusty_fork::rusty_fork_test;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// Spawn a one-shot-per-connection HTTP mock on loopback. Returns the
/// `http://127.0.0.1:<port>` base URL. The handler decides the response.
async fn spawn_mock<F, Fut>(handler: F) -> String
where
    F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = handler.clone();
            tokio::spawn(async move { h(stream).await });
        }
    });
    format!("http://127.0.0.1:{port}")
}

/// Build a single-detector spec that verifies `credential` against `url`.
fn spec_for(id: &str, url: Option<String>, metadata: Vec<MetadataSpec>) -> DetectorSpec {
    DetectorSpec {
        tests: Vec::new(),
        id: id.to_string(),
        name: id.to_string(),
        service: "test".to_string(),
        severity: Severity::Critical,
        patterns: vec![],
        companions: vec![],
        keywords: vec![],
        min_confidence: None,
        verify: Some(VerifySpec {
            url,
            method: Some(HttpMethod::Get),
            headers: vec![],
            body: None,
            auth: None,
            success: None,
            metadata,
            service: "test".to_string(),
            timeout_ms: None,
            steps: vec![],
            // Allowlist loopback + IMDS so the *only* gate that can fire is the
            // SSRF/private-IP guard, not the domain allowlist. This isolates
            // the invariant under test.
            allowed_domains: vec![
                "127.0.0.1".into(),
                "localhost".into(),
                "169.254.169.254".into(),
            ],
            oob: None,
        }),
        ..Default::default()
    }
}

fn group_for(id: &str, credential: &str) -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from(id),
        detector_name: Arc::from(id),
        service: Arc::from("test"),
        severity: Severity::Critical,
        credential: keyhog_core::SensitiveString::from(credential),
        credential_hash: [0u8; 32].into(),
        primary_location: MatchLocation {
            source: Arc::from("fs"),
            file_path: Some(Arc::from("test")),
            line: Some(1),
            offset: 1,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: vec![],
        companions: HashMap::new(),
        confidence: Some(1.0),
    }
}

/// Engine that permits HTTP + loopback so a mock server is reachable. Used by
/// the body-cap / timeout / leak tests where the point is NOT the SSRF gate.
fn permissive_engine(spec: DetectorSpec) -> VerificationEngine {
    VerificationEngine::new(
        &[spec],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            ..Default::default()
        },
    )
    .unwrap()
}

rusty_fork_test! {
    #![rusty_fork(timeout_ms = 5000)]
    #[test]
    fn script_auth_verify_requires_explicit_config_not_env() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let saved = std::env::var("KEYHOG_ALLOW_SCRIPT_VERIFY").ok();
            struct Restore(Option<String>);
            impl Drop for Restore {
                fn drop(&mut self) {
                    unsafe {
                        match &self.0 {
                            Some(value) => std::env::set_var("KEYHOG_ALLOW_SCRIPT_VERIFY", value),
                            None => std::env::remove_var("KEYHOG_ALLOW_SCRIPT_VERIFY"),
                        }
                    }
                }
            }
            let _restore = Restore(saved);
            unsafe {
                std::env::set_var("KEYHOG_ALLOW_SCRIPT_VERIFY", "1");
            }

            let mut spec = spec_for(
                "script-auth",
                Some("http://127.0.0.1/script".into()),
                vec![],
            );
            spec.verify.as_mut().unwrap().auth = Some(AuthSpec::Script {
                engine: ScriptEngine::from("notreal"),
                code: "print('STATUS: LIVE')".into(),
            });

            let default_engine = permissive_engine(spec.clone());
            let findings = default_engine
                .verify_all(vec![group_for("script-auth", "secret")])
                .await;
            match &findings[0].verification {
                VerificationResult::Error(message) => {
                    assert!(
                        message.contains("AuthSpec::Script verification disabled")
                            && message.contains("--allow-script-verify")
                            && !message.contains("KEYHOG_ALLOW_SCRIPT_VERIFY"),
                        "script auth must ignore ambient env and name the explicit flag, got: {message}"
                    );
                }
                other => panic!("expected script auth disabled error, got {other:?}"),
            }

            let explicit_engine = VerificationEngine::new(
                &[spec],
                VerifyConfig {
                    danger_allow_private_ips: true,
                    danger_allow_http: true,
                    allow_script_verify: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let findings = explicit_engine
                .verify_all(vec![group_for("script-auth", "secret")])
                .await;
            match &findings[0].verification {
                VerificationResult::Error(message) => {
                    assert!(
                        message.contains("engine 'notreal' is not on"),
                        "explicit allow should pass the disabled gate and reach engine allowlist, got: {message}"
                    );
                }
                other => panic!("expected script engine allowlist error, got {other:?}"),
            }
        });
    }
}

#[tokio::test]
async fn script_auth_requires_explicit_status_token() {
    let mut spec = spec_for(
        "script-auth-status",
        Some("http://127.0.0.1/script".into()),
        vec![],
    );
    spec.verify.as_mut().unwrap().auth = Some(AuthSpec::Script {
        engine: ScriptEngine::Python3,
        code: "print('script ran but did not classify credential')".into(),
    });

    let engine = VerificationEngine::new(
        &[spec],
        VerifyConfig {
            danger_allow_private_ips: true,
            danger_allow_http: true,
            allow_script_verify: true,
            ..Default::default()
        },
    )
    .unwrap();
    let findings = engine
        .verify_all(vec![group_for("script-auth-status", "secret")])
        .await;

    match &findings[0].verification {
        VerificationResult::Error(message) => {
            assert!(
                message.contains("returned no explicit status")
                    && message.contains("STATUS: LIVE")
                    && message.contains("STATUS: DEAD"),
                "malformed script output must be an explicit verifier contract error, got: {message}"
            );
        }
        other => panic!("malformed script output must not collapse to dead, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_companion_templates_fail_closed_before_verification_request() {
    let url_spec = spec_for(
        "missing-url-companion",
        Some("http://127.0.0.1:1/{{companion.absent_url}}".into()),
        vec![],
    );
    let mut header_spec = spec_for(
        "missing-header-companion",
        Some("http://127.0.0.1:1/verify".into()),
        vec![],
    );
    header_spec
        .verify
        .as_mut()
        .unwrap()
        .headers
        .push(HeaderSpec {
            name: "Authorization".into(),
            value: "Bearer {{companion.absent_header}}".into(),
        });
    let mut auth_spec = spec_for(
        "missing-auth-companion",
        Some("http://127.0.0.1:1/verify".into()),
        vec![],
    );
    auth_spec.verify.as_mut().unwrap().auth = Some(AuthSpec::Bearer {
        field: "companion.absent_auth".into(),
    });

    for (spec, missing) in [
        (url_spec, "absent_url"),
        (header_spec, "absent_header"),
        (auth_spec, "absent_auth"),
    ] {
        let id = spec.id.clone();
        let findings = permissive_engine(spec)
            .verify_all(vec![group_for(&id, "secret")])
            .await;
        match &findings[0].verification {
            VerificationResult::Error(message) => {
                assert!(
                    message.contains("failed to resolve verification companion")
                        && message.contains(missing)
                        && message.contains("Fix:"),
                    "missing companion {missing} must fail closed with a fix, got: {message}"
                );
            }
            other => panic!("missing companion {missing} must not collapse to dead, got {other:?}"),
        }
    }
}

// ===========================================================================
// 1. Response-body cap (decompression / OOM-bomb defense)
// ===========================================================================

#[tokio::test]
async fn response_body_over_one_mb_is_capped_with_exact_error() {
    // Server advertises and streams 2 MiB. The streaming reader must abort at
    // the 1 MiB boundary with the documented error rather than buffering it all.
    let base = spawn_mock(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\n\r\n")
            .await;
        let chunk = vec![b'A'; 256 * 1024];
        for _ in 0..8 {
            if stream.write_all(&chunk).await.is_err() {
                break;
            }
        }
    })
    .await;

    let engine = permissive_engine(spec_for("bodycap", Some(format!("{base}/")), vec![]));
    let findings = engine
        .verify_all(vec![group_for("bodycap", "secret")])
        .await;
    assert_eq!(findings.len(), 1);
    match &findings[0].verification {
        VerificationResult::Error(msg) => {
            assert_eq!(
                msg, "response body exceeds 1MB limit",
                "over-cap body must produce the exact cap error, got {msg:?}"
            );
        }
        other => panic!("expected body-cap Error, got {other:?}"),
    }
}

#[tokio::test]
async fn gzip_content_encoding_does_not_bypass_the_wire_byte_cap() {
    // Decompression-bomb runtime proof: the server advertises
    // `Content-Encoding: gzip` and streams 2 MiB of raw bytes. Because the
    // verifier's reqwest is built WITHOUT the gzip feature AND the builder
    // calls .no_gzip() explicitly, reqwest never inflates the body — the 1 MB
    // streaming cap counts real wire bytes and fires. A regression that turned
    // on auto-gzip would inflate first, letting a tiny compressed bomb expand
    // far past 1 MB before our cap saw a byte; this test would then NOT see the
    // wire-byte cap error on a 2 MiB raw stream.
    let base = spawn_mock(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2097152\r\n\r\n",
            )
            .await;
        let chunk = vec![b'A'; 256 * 1024];
        for _ in 0..8 {
            if stream.write_all(&chunk).await.is_err() {
                break;
            }
        }
    })
    .await;

    let engine = permissive_engine(spec_for("gzbomb", Some(format!("{base}/")), vec![]));
    let findings = engine.verify_all(vec![group_for("gzbomb", "secret")]).await;
    assert_eq!(findings.len(), 1);
    match &findings[0].verification {
        VerificationResult::Error(msg) => {
            assert_eq!(
                msg, "response body exceeds 1MB limit",
                "a Content-Encoding: gzip body must still hit the WIRE-byte cap \
                 (no auto-inflate); got {msg:?}"
            );
        }
        other => panic!(
            "gzip-labelled over-cap body must produce the wire-byte cap error, got {other:?}"
        ),
    }
}

#[tokio::test]
async fn response_body_just_under_cap_is_read_not_rejected() {
    // Boundary twin: a body strictly under 1 MiB must NOT trip the cap. Proves
    // the cap is an over-limit guard, not an always-reject.
    let body_len = 1024 * 1024 - 16; // just under MAX_RESPONSE_BODY_BYTES
    let base = spawn_mock(move |mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\n\r\n");
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&vec![b'B'; body_len]).await;
    })
    .await;

    let engine = permissive_engine(spec_for("undercap", Some(format!("{base}/")), vec![]));
    let findings = engine
        .verify_all(vec![group_for("undercap", "secret")])
        .await;
    assert_eq!(findings.len(), 1);
    // A 200 with no success-spec → Live; the load-bearing assertion is that it
    // is NOT the over-cap error.
    match &findings[0].verification {
        VerificationResult::Error(msg) => {
            assert_ne!(
                msg, "response body exceeds 1MB limit",
                "a sub-1MB body must not trip the cap"
            );
        }
        VerificationResult::Live | VerificationResult::Dead => {}
        other => panic!("unexpected verification for under-cap body: {other:?}"),
    }
}

// ===========================================================================
// 2. Internal / link-local target refusal — before any outbound request
// ===========================================================================

#[tokio::test]
async fn imds_metadata_target_is_refused_even_when_allowlisted() {
    // The detector explicitly allowlists 169.254.169.254, so the ONLY thing
    // that can stop the credential from being shipped to the cloud metadata
    // endpoint is the SSRF private-IP guard. With default config (private IPs
    // NOT allowed) it must be blocked with the private-URL error.
    let spec = spec_for(
        "imds",
        Some("https://169.254.169.254/latest/meta-data/iam/security-credentials/".into()),
        vec![],
    );
    let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
    let findings = engine.verify_all(vec![group_for("imds", "secret")]).await;
    assert_eq!(findings.len(), 1);
    match &findings[0].verification {
        VerificationResult::Error(msg) => {
            assert_eq!(
                msg, "blocked: private URL",
                "IMDS target must be refused by the SSRF guard, got {msg:?}"
            );
        }
        other => panic!("IMDS must be blocked pre-fetch; got {other:?}"),
    }
}

#[tokio::test]
async fn loopback_target_refused_before_any_connection_attempt() {
    // Stand up a loopback listener that COUNTS connections, allowlist it, but
    // run with default config (no private IPs). The SSRF gate must fire before
    // the socket is ever touched: the hit counter must stay at zero.
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            hits_task.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut b = [0u8; 64];
                let _ = stream.read(&mut b).await;
            });
        }
    });

    let spec = spec_for("loop", Some(format!("https://127.0.0.1:{port}/")), vec![]);
    let engine = VerificationEngine::new(&[spec], VerifyConfig::default()).unwrap();
    let findings = engine.verify_all(vec![group_for("loop", "secret")]).await;
    assert_eq!(findings.len(), 1);
    assert!(
        matches!(&findings[0].verification, VerificationResult::Error(m) if m == "blocked: private URL"),
        "loopback must be refused with the private-URL error, got {:?}",
        findings[0].verification
    );
    // The decisive proof: the guard fired pre-connect.
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "SSRF guard must refuse the loopback target BEFORE opening a socket"
    );
}

// ===========================================================================
// 3. Credential never appears in any emitted finding string
// ===========================================================================

#[tokio::test]
async fn raw_credential_never_appears_in_any_emitted_finding_string() {
    // A highly distinctive credential that cannot collide with framework text.
    const CRED: &str = "SUPERSECRET_DEADBEEF_credential_value_0123456789ABCDEF";

    // The server reflects the credential back in its body to make the leak
    // path maximally easy to hit, and exposes a JSON field the detector
    // extracts into metadata. If ANY emitted string carried the raw value,
    // this test would catch it.
    let cred_for_server = CRED.to_string();
    let base = spawn_mock(move |mut stream| {
        let cred = cred_for_server.clone();
        async move {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            // Body echoes the credential and an account field.
            let body = format!("{{\"token\":\"{cred}\",\"account\":\"acct-123\"}}");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        }
    })
    .await;

    let spec = spec_for(
        "leakcheck",
        Some(format!("{base}/?token={{{{match}}}}")),
        vec![MetadataSpec {
            name: "account".into(),
            json_path: "/account".into(),
        }],
    );
    let engine = permissive_engine(spec);
    let findings = engine.verify_all(vec![group_for("leakcheck", CRED)]).await;
    assert_eq!(findings.len(), 1);
    let f = &findings[0];

    // The redacted form must be present and must NOT be the raw credential.
    assert_ne!(
        f.credential_redacted.as_ref(),
        CRED,
        "credential_redacted must be redacted, not the raw value"
    );
    assert!(
        f.credential_redacted.contains("..."),
        "redacted credential should be the SUPE...CDEF shape, got {:?}",
        f.credential_redacted
    );

    // The verification-result string must never carry the credential.
    if let VerificationResult::Error(msg) = &f.verification {
        assert!(
            !msg.contains(CRED),
            "verification Error string leaked the credential: {msg}"
        );
    }

    // No metadata key OR value may contain the raw credential — even though the
    // server reflected it in the body, only the explicitly-extracted `/account`
    // field is captured, and that field does not contain the credential.
    for (k, v) in &f.metadata {
        assert!(
            !k.contains(CRED) && !v.contains(CRED),
            "metadata leaked the credential: {k}={v}"
        );
    }

    // Finally, the credential is a substring of the SERVER body but must not be
    // a substring of the entire serialized finding (debug form covers every
    // field the reporter could emit).
    let serialized = format!("{f:?}");
    assert!(
        !serialized.contains(CRED),
        "the serialized VerifiedFinding leaked the raw credential"
    );
}

// ===========================================================================
// 4. Timeout enforcement
// ===========================================================================

#[tokio::test]
async fn slow_server_hits_the_configured_timeout() {
    // Server sends a status line then stalls indefinitely. With a 150 ms
    // per-detector timeout the verifier must abort with a timeout-class error,
    // not hang the scan.
    let base = spawn_mock(|mut stream| async move {
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf).await;
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n").await;
        // Never finish the headers; hold the connection open.
        tokio::time::sleep(Duration::from_secs(30)).await;
    })
    .await;

    let mut spec = spec_for("slow", Some(format!("{base}/")), vec![]);
    if let Some(v) = spec.verify.as_mut() {
        v.timeout_ms = Some(150);
    }
    let engine = permissive_engine(spec);

    let started = std::time::Instant::now();
    let findings = tokio::time::timeout(
        Duration::from_secs(10),
        engine.verify_all(vec![group_for("slow", "secret")]),
    )
    .await
    .expect("verify_all must return — the per-request timeout must fire, not hang");
    let elapsed = started.elapsed();

    assert_eq!(findings.len(), 1);
    // 3 retries × (150 ms timeout + exponential backoff/jitter) stays far below
    // the 30 s server stall.
    // The hard ceiling here is just "did NOT hang for the 30 s server stall".
    assert!(
        elapsed < Duration::from_secs(8),
        "timeout must bound the request; took {elapsed:?}"
    );
    match &findings[0].verification {
        VerificationResult::Error(msg) => {
            assert!(
                msg.contains("timeout") || msg.contains("max retries exceeded"),
                "slow server must yield a timeout-class error, got {msg:?}"
            );
        }
        other => panic!("expected timeout error, got {other:?}"),
    }
}

// ===========================================================================
// 4b. A transport failure becomes Error (Unknown), never a silent Live/Dead
//     (Law 10: a verification that ERRORS must report Unknown loudly — never
//     fail-open to "valid" nor fail-shut to a confident "dead").
// ===========================================================================

#[tokio::test]
async fn connection_reset_yields_error_not_silent_live_or_dead() {
    // Server accepts the connection, reads the request, then drops the socket
    // WITHOUT writing any HTTP response (hard reset). reqwest surfaces this as a
    // connect/request error. The verifier must map it to VerificationResult::Error
    // (a non-conclusive "Unknown") — NOT Live (fail-open: the credential is NOT
    // proven valid) and NOT Dead (fail-shut: the credential is NOT proven
    // rejected). Treating an errored probe as either verdict is a security bug.
    let base = spawn_mock(|stream| async move {
        // Read nothing, write nothing — just drop the stream to reset.
        drop(stream);
    })
    .await;

    let mut spec = spec_for("reset", Some(format!("{base}/")), vec![]);
    if let Some(v) = spec.verify.as_mut() {
        v.timeout_ms = Some(300);
    }
    let engine = permissive_engine(spec);
    let findings = engine.verify_all(vec![group_for("reset", "secret")]).await;
    assert_eq!(findings.len(), 1);
    match &findings[0].verification {
        VerificationResult::Error(_) => { /* correct: Unknown, surfaced loudly */ }
        VerificationResult::Live => {
            panic!(
                "FAIL-OPEN: a connection-reset probe was reported Live (credential not proven valid)"
            )
        }
        VerificationResult::Dead => {
            panic!(
                "FAIL-SHUT: a connection-reset probe was reported Dead (credential not proven rejected)"
            )
        }
        other => panic!("connection reset must yield Error (Unknown), got {other:?}"),
    }
}

// ===========================================================================
// 5. DNS-pin failure FAILS CLOSED — no silent unpinned fallback (Law 10)
// ===========================================================================

#[test]
fn dns_pin_build_failure_fails_closed_not_silent_fallback() {
    // Source-pin: the rebuild path in resolved_client_for_url() must not clone
    // the unpinned base client on a pin-build error. That fallback re-resolves
    // the host through the system resolver at connect time and reopens the
    // exact DNS-rebinding window the pin exists to close (Law 10: no silent
    // fallback). Assert the dangerous fallback comment is gone and the loud
    // fail-closed error is present.
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/request.rs"
    ))
    .expect("request.rs must be readable");

    assert!(
        src.contains("resolve_to_addrs"),
        "DNS pinning via resolve_to_addrs must remain in place"
    );
    assert!(
        !src.contains("Fall back to the shared client"),
        "the unpinned silent-fallback branch must be removed (reopens DNS-rebinding)"
    );
    assert!(
        src.contains("DNS pin client build failed"),
        "pin-build failure must surface a loud blocked error, not fall back"
    );
    // The fail-closed branch must return a blocked VerificationResult, not
    // clone base_client. Scope the inspection to the current pinned-client
    // owner so the proxy/no-pin branches elsewhere do not count.
    let pin_section = src
        .split("fn build_pinned_client(")
        .nth(1)
        .expect("the pinned client builder owner");
    let builder_fn = pin_section
        .split("pub(crate) async fn build_request_for_step")
        .next()
        .expect("pinned builder before request-step builder");
    assert!(
        builder_fn.contains(".map_err(|e|")
            && builder_fn.contains("VerificationResult::Error")
            && builder_fn.contains("DNS pin client build failed"),
        "pin-build Err arm must fail closed with a blocked VerificationResult, \
         got:\n{builder_fn}"
    );
    assert!(
        !builder_fn.contains("base_client.clone()"),
        "pin-build Err arm must not clone the unpinned base client (silent fallback)"
    );
}

#[test]
fn ssrf_ip_policy_has_one_classifier_owner() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ssrf.rs"))
        .expect("ssrf.rs must be readable");

    let owner = src
        .split("fn verifier_blocks_ip_addr(")
        .nth(1)
        .expect("ssrf.rs must define the canonical verifier IP classifier")
        .split("/// Compatibility alias")
        .next()
        .expect("classifier owner must appear before compatibility alias");
    assert!(
        owner.contains("crate::bogon::ip_addr_is_bogon(ip)"),
        "the canonical verifier classifier must delegate shared reserved/private ranges to bogon"
    );
    assert!(
        owner.contains("ipv4.is_multicast() || ipv4.octets()[0] >= 240"),
        "only verifier-specific IPv4 multicast/Class-E policy should be layered on top of bogon"
    );

    let fast_alias = src
        .split("pub fn is_private_ip_addr_fast(")
        .nth(1)
        .expect("historical fast-name compatibility alias must exist")
        .split("/// Check a resolved IP address")
        .next()
        .expect("fast alias body before canonical public function");
    assert!(
        fast_alias.contains("verifier_blocks_ip_addr(*ip)"),
        "is_private_ip_addr_fast must call the single classifier instead of owning a duplicate table"
    );

    let public_veto = src
        .split("pub fn is_private_ip_addr(")
        .nth(1)
        .expect("post-resolution public IP veto must exist")
        .split("/// Returns true if the URL")
        .next()
        .expect("public veto body before URL classifier");
    assert!(
        public_veto.contains("verifier_blocks_ip_addr(*ip)"),
        "is_private_ip_addr must call the same classifier as the compatibility alias"
    );

    let url_classifier = src
        .split("pub fn is_private_url(")
        .nth(1)
        .expect("URL SSRF classifier must exist");
    assert!(
        url_classifier.matches("verifier_blocks_ip_addr(").count() >= 3,
        "URL literal and encoded-IP checks must route through the same IP classifier"
    );
    assert!(
        !url_classifier.contains("crate::bogon::ip_addr_is_bogon")
            && !url_classifier.contains("is_private_ip_addr_fast(&IpAddr"),
        "URL classifier must not re-inline the bogon/fast union"
    );
    for retired_mask in [
        "0xFF000000",
        "0xFFF00000",
        "0xFFFF0000",
        "0xFFC00000",
        "0xF0000000",
    ] {
        assert!(
            !src.contains(retired_mask),
            "retired duplicate SSRF bitmask table returned via {retired_mask}"
        );
    }
}

#[test]
fn interpolation_context_is_explicit_at_request_call_sites() {
    let request = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/request.rs"
    ))
    .expect("verify/request.rs must be readable");
    let template_helper = request
        .split("pub(crate) fn apply_header_body_templates(")
        .nth(1)
        .expect("request.rs must own the header/body template helper")
        .split("fn request_for_method(")
        .next()
        .expect("template helper must be bounded before request_for_method");
    assert!(
        template_helper.contains("interpolate_http_value(&header.value, credential, companions)")
            && template_helper
                .contains("interpolate_http_value(body_template, credential, companions)"),
        "shared header/body template helper must use HTTP-value interpolation"
    );

    let credential = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/credential.rs"
    ))
    .expect("verify/credential.rs must be readable");
    assert!(
        credential
            .contains("let raw_url = interpolate_url(url_template, credential, companions_ref);"),
        "single-step URL templates must use URL-context interpolation"
    );
    assert!(
        credential.contains("apply_header_body_templates("),
        "single-step verification must route header/body templates through the shared HTTP-value helper"
    );
    assert!(
        !credential.contains("use crate::interpolate::{companions_with_oob, interpolate};"),
        "single-step verification must not import the ambiguous generic interpolation helper"
    );

    let multi_step = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/multi_step.rs"
    ))
    .expect("verify/multi_step.rs must be readable");
    assert!(
        multi_step
            .contains("let raw_url = interpolate_url(&step.url, credential, &current_companions);"),
        "multi-step URL templates must use URL-context interpolation"
    );
    assert!(
        multi_step.contains("apply_header_body_templates("),
        "multi-step verification must route header/body templates through the shared HTTP-value helper"
    );

    let auth = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/auth.rs"))
        .expect("verify/auth.rs must be readable");
    assert!(
        auth.contains("let value = interpolate_http_value(template, credential, companions);"),
        "AuthSpec::Header templates feed Authorization/header values and must not URL-encode"
    );
    assert!(
        !auth.contains("use crate::interpolate::{interpolate,"),
        "auth verification must not import the ambiguous generic interpolation helper"
    );
}

#[test]
fn single_and_multi_step_share_http_request_lifecycle_helpers() {
    let request = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/request.rs"
    ))
    .expect("verify/request.rs must be readable");
    assert!(
        request.contains("pub(crate) fn apply_header_body_templates(")
            && request.contains("interpolate_http_value(&header.value, credential, companions)")
            && request.contains("request = request.body(body);"),
        "one request helper must own header/body interpolation and attachment"
    );

    let response = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/response.rs"
    ))
    .expect("verify/response.rs must be readable");
    assert!(
        response.contains("pub(crate) struct HttpResponseBody")
            && response.contains("pub(crate) async fn execute_and_read_response(")
            && response.contains("execute_request(request).await?")
            && response.contains("read_response_body(response).await?"),
        "one response helper must own execute + capped-body-read for verifier HTTP steps"
    );

    let credential = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/credential.rs"
    ))
    .expect("verify/credential.rs must be readable");
    assert!(
        credential.contains("apply_header_body_templates(")
            && credential.contains("execute_and_read_response(request).await"),
        "single-step verify must use the shared request lifecycle helpers"
    );
    for forbidden in [
        "for header in &spec.headers",
        "execute_request(request).await",
        "read_response_body(response).await",
    ] {
        assert!(
            !credential.contains(forbidden),
            "single-step verify must not grow a duplicate request lifecycle via {forbidden}"
        );
    }

    let multi_step = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/multi_step.rs"
    ))
    .expect("verify/multi_step.rs must be readable");
    assert!(
        multi_step.contains("apply_header_body_templates(")
            && multi_step.contains("execute_and_read_response(request).await"),
        "multi-step verify must use the shared request lifecycle helpers"
    );
    for forbidden in [
        "for header in &step.headers",
        "execute_request(request).await",
        "read_response_body(response).await",
    ] {
        assert!(
            !multi_step.contains(forbidden),
            "multi-step verify must not grow a duplicate request lifecycle via {forbidden}"
        );
    }
}

#[test]
fn resolved_client_for_url_is_split_into_explicit_egress_stages() {
    let request = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/request.rs"
    ))
    .expect("verify/request.rs must be readable");
    let resolved = request
        .split("pub(crate) async fn resolved_client_for_url(")
        .nth(1)
        .expect("resolved_client_for_url must exist")
        .split("fn parse_target_url(")
        .next()
        .expect("resolved_client_for_url must be followed by parse_target_url");

    for needle in [
        "parse_target_url(raw_url)?",
        "enforce_target_url_policy(&url, allow_private_ips, allow_http)?",
        "proxied_target(base_client, url)",
        "target_host(&url)",
        "resolve_direct_target_addrs(&url, &host, allow_private_ips).await?",
        "direct_target_client(base_client, &host, &pinned_addrs, timeout, insecure_tls)?",
    ] {
        assert!(
            resolved.contains(needle),
            "resolved_client_for_url must delegate egress stage {needle}"
        );
    }

    for owner in [
        "fn parse_target_url(",
        "fn enforce_target_url_policy(",
        "fn proxied_target(",
        "fn target_host(",
        "async fn resolve_direct_target_addrs(",
        "fn direct_target_client(",
    ] {
        assert!(request.contains(owner), "request.rs must define {owner}");
    }

    let policy = request
        .split("fn enforce_target_url_policy(")
        .nth(1)
        .expect("policy stage must exist")
        .split("fn proxied_target(")
        .next()
        .expect("policy stage must be bounded before proxied_target");
    assert!(
        policy.contains("screen_target_url_and_addrs(url, &[], allow_private_ips)?")
            && policy.contains("VerificationResult::Error(HTTPS_ONLY_ERROR.into())"),
        "policy stage must own URL-shape SSRF screening before HTTPS enforcement"
    );

    let direct_resolve = request
        .split("async fn resolve_direct_target_addrs(")
        .nth(1)
        .expect("direct resolver stage must exist")
        .split("fn direct_target_client(")
        .next()
        .expect("direct resolver stage must be bounded before client selection");
    assert!(
        direct_resolve.contains("crate::ssrf::resolve_dns_cached")
            && direct_resolve
                .contains("screen_target_url_and_addrs(url, &addrs, allow_private_ips)?")
            && direct_resolve.contains("blocked: DNS returned no addresses")
            && direct_resolve.contains("blocked: DNS resolution failed"),
        "direct resolver stage must own DNS resolution, resolved-IP screening, and fail-closed DNS errors"
    );

    let direct_client = request
        .split("fn direct_target_client(")
        .nth(1)
        .expect("direct client stage must exist")
        .split("fn pinned_client_for(")
        .next()
        .expect("direct client stage must be bounded before cache owner");
    assert!(
        direct_client.contains("return Ok(base_client.clone());")
            && direct_client
                .contains("pinned_client_for(host, pinned_addrs, timeout, insecure_tls)"),
        "direct client stage must preserve the empty-host base-client path and the pinned-client cache path"
    );
}

#[test]
fn aws_sts_egress_uses_resolved_screened_client() {
    let aws = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/aws.rs"))
        .expect("verify/aws.rs must be readable");
    assert!(
        aws.contains("execute_request") && aws.contains("resolved_client_for_url"),
        "AWS verifier must import the shared resolved-client egress owner"
    );
    assert!(
        aws.contains("let resolved_target = match resolved_client_for_url(")
            && aws.contains("allow_private_ips")
            && aws.contains("allow_http")
            && aws.contains("proxy_in_use")
            && aws.contains("insecure_tls"),
        "AWS STS must screen and DNS-pin its fixed endpoint through resolved_client_for_url"
    );
    assert!(
        aws.contains("&resolved_target.client") && aws.contains("resolved_target.url.as_str()"),
        "AWS STS request must be sent through the resolved/pinned client and URL"
    );

    let auth = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/auth.rs"))
        .expect("verify/auth.rs must be readable");
    let aws_call = auth
        .split("AuthSpec::AwsV4")
        .nth(1)
        .expect("AuthSpec::AwsV4 arm must exist");
    for needle in [
        "allow_private_ips",
        "allow_http",
        "proxy_in_use",
        "insecure_tls",
    ] {
        assert!(
            aws_call.contains(needle),
            "AuthSpec::AwsV4 must pass network policy field {needle} to build_aws_probe"
        );
    }

    let request = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/request.rs"
    ))
    .expect("verify/request.rs must be readable");
    let builder = request
        .split("pub(crate) async fn build_request_for_step")
        .nth(1)
        .expect("request step builder must exist");
    for needle in [
        "allow_private_ips: bool",
        "allow_http: bool",
        "proxy_in_use: bool",
        "insecure_tls: bool",
    ] {
        assert!(
            builder.contains(needle),
            "request step builder must carry network policy field {needle}"
        );
    }
}

// ===========================================================================
// 5b. OOB interaction drops are LOUD, not silent (Law 10)
// ===========================================================================

#[test]
fn oob_decrypt_entry_drops_are_surfaced_loudly_not_silently() {
    // A malformed/undecryptable interactsh entry is skipped so one bad entry
    // can't abort the whole poll batch — but the drop is recall-affecting (a
    // missed OOB callback can flip an exfil-capable credential from Live to
    // Dead). Law 10: that drop must be surfaced LOUDLY (`warn!`), never via the
    // silent `debug!` it used to use for the JSON-parse path nor silently
    // (the non-UTF-8 path had NO log at all before this fix).
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/decrypt.rs"))
        .expect("oob/decrypt.rs must be readable");

    // Every skip path must warn and mention the missed-callback consequence:
    // non-UTF-8 decrypt, malformed JSON, and parsed JSON with no interaction id.
    let warn_count = src.matches("warn!(").count();
    assert!(
        warn_count >= 3,
        "all OOB drop paths (non-UTF-8 decrypt + JSON parse + missing id) must warn!; found {warn_count}"
    );
    // The warning must state the recall consequence so the operator notices.
    // (`may be missed` appears contiguously in both warn! messages; the full
    // phrase wraps across a source line-continuation so we match the tail.)
    assert!(
        src.contains("may be missed") && src.contains("OOB callback"),
        "the drop warning must state the recall consequence so the operator notices"
    );
    // The previously-silent paths must no longer use debug! for the skip.
    assert!(
        !src.contains("debug!(target: \"keyhog::oob\", error = %e, \"interactsh JSON parse failed"),
        "the JSON-parse drop must be warn!, not the silent debug! it used before"
    );
    // The non-UTF-8 branch must not be a bare silent `return Ok(None)`: it must
    // be preceded by a warn within the same Err arm.
    let utf8_arm = src
        .split("std::str::from_utf8(payload)")
        .nth(1)
        .expect("the from_utf8 match site");
    let utf8_err_arm = utf8_arm
        .split("let raw: InteractionRaw")
        .next()
        .expect("text before the raw deserialize");
    assert!(
        utf8_err_arm.contains("warn!("),
        "the non-UTF-8 decrypt drop must warn! before returning Ok(None)"
    );
    let missing_id_arm = src
        .split("if unique_id.is_empty()")
        .nth(1)
        .expect("the missing-id drop site");
    let missing_id_before_return = missing_id_arm
        .split("return Ok(None);")
        .next()
        .expect("missing-id arm before return");
    assert!(
        missing_id_before_return.contains("warn!(")
            && missing_id_before_return.contains("full-id or unique-id"),
        "a decrypted interaction without an id must warn before it is dropped"
    );
}

#[test]
fn oob_decrypt_hot_path_does_not_clone_ciphertext_or_recollect_payload() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/decrypt.rs"))
        .expect("oob/decrypt.rs must be readable");

    assert!(
        src.contains("split_at_mut(16)") && src.contains(".decrypt(payload)"),
        "decrypt_entry must decrypt in place inside the decoded buffer, not clone ciphertext"
    );
    assert!(
        !src.contains("ct.to_vec()"),
        "decrypt_entry must not clone the ciphertext tail before AES-CFB decrypt"
    );
    assert!(
        src.contains("fn truncate_raw_payload(mut raw_payload: String) -> String"),
        "payload truncation must keep ownership and truncate in place"
    );
    assert!(
        !src.contains(".chars().take(MAX_RAW_PAYLOAD).collect()"),
        "payload truncation must not allocate a second String"
    );
}

// ===========================================================================
// 6. No auto-decompression feature => the 1 MB cap measures real wire bytes
// ===========================================================================

#[test]
fn verifier_reqwest_has_no_auto_decompression_feature() {
    // The 1 MB streaming cap in read_response_body() is only sound against a
    // gzip/brotli/deflate decompression bomb if reqwest is NOT compiled with an
    // auto-decompression feature (which would inflate the body before our cap
    // ever counts a byte). Pin the verifier's reqwest feature set so a future
    // edit that turns on `gzip`/`brotli`/`deflate` is forced to revisit the cap
    // (count-before-inflate) and update this contract deliberately.
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("verifier Cargo.toml must be readable");

    // Find the reqwest dependency line and inspect its feature list.
    let reqwest_line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("reqwest"))
        .expect("verifier must declare a reqwest dependency");
    for feat in ["\"gzip\"", "\"brotli\"", "\"deflate\"", "\"zstd\""] {
        assert!(
            !reqwest_line.contains(feat),
            "verifier reqwest must not enable {feat}: auto-decompression breaks the \
             1MB wire-byte cap (decompression-bomb vector). Line: {reqwest_line}"
        );
    }
    // Positive pin: the stream feature (used by the capped streaming reader)
    // must remain enabled.
    assert!(
        reqwest_line.contains("\"stream\""),
        "verifier reqwest must keep the `stream` feature for the capped body reader"
    );
}

// ===========================================================================
// 6b. Both client builders call .no_gzip()/.no_brotli()/.no_zstd()/.no_deflate()
//     explicitly (call-site defense-in-depth, not just the Cargo feature pin)
// ===========================================================================

#[test]
fn engine_base_client_builder_disables_auto_decompression_explicitly() {
    // The feature pin above stops the verifier's OWN reqwest from enabling
    // gzip/brotli/zstd/deflate. But a TRANSITIVE dependency could enable a
    // decompression feature for the whole reqwest crate (Cargo unions
    // features). reqwest exposes `no_gzip()`/`no_brotli()`/`no_zstd()`/
    // `no_deflate()` precisely so a client can opt OUT even when another crate
    // opted the feature IN. The base engine client (verify/mod.rs) is the
    // client used on the proxy path and as the AwsV4 self-constructing client;
    // it must call all four so the 1 MB streaming cap always measures wire
    // bytes. These methods exist unconditionally and are no-ops when the
    // feature is off, so the call is always safe.
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/mod.rs"))
        .expect("verify/mod.rs must be readable");
    let new_fn = src
        .split("pub fn new(")
        .nth(1)
        .expect("VerificationEngine::new must exist");
    let builder_section = new_fn
        .split("let client = builder.build()")
        .next()
        .expect("client build site");
    for needle in [".no_gzip()", ".no_brotli()", ".no_zstd()", ".no_deflate()"] {
        assert!(
            builder_section.contains(needle),
            "VerificationEngine base client builder must call {needle} \
             (transitive-feature decompression-bomb defense)"
        );
    }
}

#[test]
fn dns_pinned_rebuild_client_disables_auto_decompression_explicitly() {
    // The DNS-pinned per-request rebuild in resolved_client_for_url() is the
    // client that actually serves the request on the direct (no-proxy) path.
    // It MUST mirror the base client's no-decompression posture or the 1 MB
    // cap would measure inflated bytes on that path. Scope the inspection to
    // the pinned `.build()` site so we don't accidentally match calls elsewhere.
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verify/request.rs"
    ))
    .expect("request.rs must be readable");
    let pin_section = src
        .split("danger_accept_invalid_certs(insecure_tls)")
        .nth(1)
        .expect("the pinned client builder section");
    let pin_builder = pin_section
        .split(".resolve_to_addrs(&host, &pinned_addrs)")
        .next()
        .expect("text up to resolve_to_addrs");
    for needle in [".no_gzip()", ".no_brotli()", ".no_zstd()", ".no_deflate()"] {
        assert!(
            pin_builder.contains(needle),
            "DNS-pinned rebuild client must call {needle} so the body cap \
             measures wire bytes on the direct path too"
        );
    }
}

// ===========================================================================
// 7. OOB deregister error body is hard-capped (parity with register/poll)
// ===========================================================================

#[test]
fn oob_deregister_error_body_is_capped_not_unbounded() {
    // register()/poll() both stream their error/diagnostic bodies through the
    // shared `read_capped_text(_, ERROR_BODY_CAP)` budget. deregister() used a
    // bare `resp.text().await.unwrap_or_default()`, which buffers the ENTIRE
    // server-controlled body with no cap — a hostile/misbehaving collector
    // returning a multi-GiB body on a deregister-failure status could spike
    // process memory. Pin the fix at the source: the deregister error path must
    // route through read_capped_text and must NOT use the uncapped resp.text().
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/client.rs"))
        .expect("oob/client.rs must be readable");

    // Isolate the deregister fn body so the assertion can't be satisfied by an
    // unrelated call elsewhere in the file.
    let deregister = src
        .split("pub async fn deregister(")
        .nth(1)
        .expect("deregister fn must exist");
    let deregister_body = deregister
        .split("pub fn correlation_id")
        .next()
        .unwrap_or(deregister);

    assert!(
        deregister_body.contains("read_capped_text(resp, ERROR_BODY_CAP)"),
        "deregister error path must cap the body via read_capped_text(_, ERROR_BODY_CAP)"
    );
    assert!(
        !deregister_body.contains("resp.text().await.unwrap_or_default()"),
        "deregister must not read an UNCAPPED body via resp.text() (memory-bomb vector)"
    );
}

#[test]
fn oob_collector_direct_client_is_dns_pinned() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/client.rs"))
        .expect("oob/client.rs must be readable");
    let helper = src
        .split("async fn collector_http_client(")
        .nth(1)
        .expect("collector_http_client must exist");
    let helper_body = helper
        .split("pub(crate) fn ssrf_check_collector_dns_result_for_test")
        .next()
        .expect("collector helper section must be bounded");

    assert!(
        helper_body.contains("crate::ssrf::is_private_url(server)"),
        "OOB collector policy must reject private-looking collector URLs before network contact"
    );
    assert!(
        helper_body.contains("crate::ssrf::resolve_dns_cached(&host_port)"),
        "OOB collector direct path must resolve the collector host before contact"
    );
    assert!(
        helper_body.contains("check_collector_resolved_addrs(server, &addrs)?"),
        "OOB collector direct path must screen every resolved address"
    );
    assert!(
        helper_body.contains(".resolve_to_addrs(&host, &pinned_addrs)"),
        "OOB collector direct path must pin the screened DNS answers"
    );
    assert!(
        helper_body.contains("refusing an unpinned collector client"),
        "OOB collector pin-client build failure must fail closed, not use an unpinned client"
    );
}

#[test]
fn oob_collector_pinned_client_preserves_security_builder_options() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/client.rs"))
        .expect("oob/client.rs must be readable");
    let helper = src
        .split("async fn collector_http_client(")
        .nth(1)
        .expect("collector_http_client must exist");
    let builder = helper
        .split(".resolve_to_addrs(&host, &pinned_addrs)")
        .next()
        .expect("collector pinned builder must be present");

    for needle in [
        ".timeout(timeout)",
        ".danger_accept_invalid_certs(insecure_tls)",
        ".no_proxy()",
        ".no_gzip()",
        ".no_brotli()",
        ".no_zstd()",
        ".no_deflate()",
        ".redirect(reqwest::redirect::Policy::none())",
    ] {
        assert!(
            builder.contains(needle),
            "OOB pinned collector client must preserve {needle}"
        );
    }
}

#[test]
fn enable_oob_uses_engine_network_policy_for_collector_client() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/verify/mod.rs"))
        .expect("verify/mod.rs must be readable");
    let enable = src
        .split("pub async fn enable_oob(")
        .nth(1)
        .expect("enable_oob must exist");
    let enable_body = enable
        .split("pub async fn shutdown_oob")
        .next()
        .expect("enable_oob section must be bounded");

    assert!(
        enable_body.contains("OobSession::start_with_network_policy"),
        "enable_oob must use the OOB start path that accepts network policy"
    );
    for needle in ["self.timeout", "self.proxy_in_use", "self.insecure_tls"] {
        assert!(
            enable_body.contains(needle),
            "enable_oob must pass {needle} into the OOB collector client"
        );
    }
}

#[test]
fn oob_session_docs_match_fail_closed_runtime_contract() {
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("verifier lib.rs must be readable");
    let docs = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/OOB.md"))
        .expect("docs/OOB.md must be readable");
    let session =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/oob/session.rs"))
            .expect("oob/session.rs must be readable");
    let normalized_lib = lib
        .lines()
        .map(|line| line.trim_start().trim_start_matches("///").trim())
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    assert!(
        normalized_lib.contains(
            "those detectors fail closed with a verification error before any HTTP probe is sent"
        ),
        "VerificationEngine::oob_session docs must state the no-session fail-closed contract"
    );
    assert!(
        !normalized_lib.contains("fall through to HTTP-only success criteria")
            && !docs.contains("tokens resolve to\n  empty strings; HTTP-only verification proceeds")
            && !session.contains("degrades to HTTP-only success criteria"),
        "OOB-required detectors must not be documented as silently falling through to HTTP-only verification"
    );
    assert!(
        docs.contains("OOB-required detectors fail closed before sending any HTTP probe")
            && docs.contains("oob_disabled = \"no active OOB session\"")
            && session.contains("fails closed with a verification error for this finding"),
        "user-facing and developer OOB docs must describe fail-closed required-OOB behavior"
    );
}
