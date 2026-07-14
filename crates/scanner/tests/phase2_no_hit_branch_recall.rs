//! Regression gate for the scan_coalesced no-hit branch fallback fix.
//!
//! Companion to phase2_wire_regression_69.rs: that test asserts the
//! wire between scan_prepared_with_triggered → scan_phase2_patterns
//! stays alive. THIS test asserts the parallel-coalesced no-hit branch
//! in scan_coalesced(chunks) ALSO routes through scan_phase2_patterns
//! when the chunk has no literal-prefix Hyperscan hits.
//! The portable per-chunk test locks the same admission contract without SIMD.
//!
//! Bug: kubernetes-bootstrap-token has no literal prefix; its regex
//! `\b([a-z0-9]{6}\.[a-z0-9]{16})\b` lives in self.phase2_patterns gated only
//! by keyword AC ("kubernetes", "kubeadm", "bootstrap-token", ...).
//! When a chunk contains ONLY this detector's pattern + keywords
//! (typical k8s config file with one bootstrap token), phase 1 of
//! scan_coalesced produces hits=0 - and pre-fix, the no-hit branch
//! only ran scan_generic_assignments, never scan_phase2_patterns.
//! The detector was silently dead on its own canonical input.

mod support;
use support::contracts::test_chunk as make_chunk;
use support::paths::detector_dir;

use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const BARE_ENTROPY_SECRET: &str = "qA9zM4nB7vC2xL8pR5tY1uI6oP3sD0fG9hJ2kL7mN4bV8cX1zQ6wE5rT0yU3iO";

fn compile_scanner_with_config(config: ScannerConfig) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    CompiledScanner::compile(detectors)
        .expect("compile")
        .with_config(config)
}

#[cfg(feature = "entropy")]
fn compile_portable_entropy_scanner(config: ScannerConfig) -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    detectors.retain(|detector| detector.id == "generic-secret");
    assert_eq!(detectors.len(), 1, "portable entropy fixture owner");
    detectors[0].patterns.clear();
    detectors[0].keywords = vec!["aaaa".to_string()];
    CompiledScanner::compile(detectors)
        .expect("compile")
        .with_config(config)
}

#[cfg(not(feature = "simd"))]
fn compile_portable_phase2_scanner(config: ScannerConfig) -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    detectors.retain(|detector| detector.id == "kubernetes-bootstrap-token");
    assert_eq!(detectors.len(), 1, "portable phase-2 fixture owner");
    detectors[0].keywords.clear();
    CompiledScanner::compile(detectors)
        .expect("compile")
        .with_config(config)
}

#[test]
fn kubernetes_bootstrap_token_fires_in_direct_scan() {
    // Sanity check - via scanner.scan(&chunk) the bootstrap detector
    // already worked pre-fix. If THIS test fails, my edits broke the
    // direct scan path; the coalesced-path tests below would be
    // diagnosing a different bug.
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let chunk = make_chunk(
        "KUBERNETES_BOOTSTRAP_TOKEN=k3m9zq.4r8w2nq3p6vt5b1z\n",
        "k8s-bootstrap.env",
    );
    let matches = scanner.scan(&chunk);
    let fired = matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "kubernetes-bootstrap-token");
    assert!(
        fired,
        "direct scan must already find the bootstrap token. matches: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref().to_string(), m.credential.to_string()))
            .collect::<Vec<_>>(),
    );
}

#[cfg(not(feature = "simd"))]
#[test]
fn portable_cpu_phase2_pattern_survives_direct_literal_rejection() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_portable_phase2_scanner(config);
    let chunk = make_chunk(
        &format!("{}k3m9zq.4r8w2nq3p6vt5b1z\n", "#".repeat(64)),
        "k8s-bootstrap.env",
    );

    let admission = scanner.phase1_admission_summary(std::slice::from_ref(&chunk));
    assert_eq!(admission.admitted_chunks, 0);
    assert_eq!(
        admission.alphabet_rejected_chunks + admission.bigram_rejected_chunks,
        1,
        "fixture must enter backend-neutral no-hit admission"
    );
    let matches = scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback);
    assert!(
        matches.iter().any(|finding| {
            finding.detector_id.as_ref() == "kubernetes-bootstrap-token"
                && finding.credential.as_ref() == "k3m9zq.4r8w2nq3p6vt5b1z"
        }),
        "portable CPU fallback must retain anchorless phase-2 findings: {matches:?}"
    );
}

#[test]
fn kubernetes_bootstrap_token_fires_in_coalesced_no_hit_branch() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Single-secret chunk: only a kubernetes bootstrap token, no other
    // detector's literal prefix (no ghp_, sk-, AKIA, etc.). The phase 1
    // literal-set walk will find ZERO hits, routing this through the
    // no-hit branch of scan_coalesced. The keyword "TOKEN" passes
    // has_generic_assignment_keyword which gates the phase-2 path.
    let chunk = make_chunk(
        "KUBERNETES_BOOTSTRAP_TOKEN=k3m9zq.4r8w2nq3p6vt5b1z\n",
        "k8s-bootstrap.env",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    assert_eq!(results.len(), 1, "one chunk → one result vec");
    let matches = &results[0];

    let bootstrap_fired = matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "kubernetes-bootstrap-token");
    assert!(
        bootstrap_fired,
        "kubernetes-bootstrap-token must fire on canonical k8s env line via scan_coalesced \
         no-hit branch (regression for prefix-less phase-2 detectors silently dead when \
         phase 1 produces 0 literal-prefix hits). Matches: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref().to_string(), m.credential.to_string()))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn kubernetes_bootstrap_token_canonical_kubeadm_join_fires() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");

    // Canonical kubeadm-join command from the detector's contract.
    // No literal-prefix detector matches; only the bootstrap regex
    // can extract the token. Word "token" appears (twice) so the
    // has_generic_assignment_keyword gate passes.
    let chunk = make_chunk(
        "kubeadm join 10.0.0.1:6443 --token k3m9zq.4r8w2nq3p6vt5b1z \
         --discovery-token-ca-cert-hash sha256:abc\n",
        "kubeadm-join.sh",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];

    let bootstrap_fired = matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "kubernetes-bootstrap-token");
    assert!(
        bootstrap_fired,
        "kubernetes-bootstrap-token must fire on canonical kubeadm-join command via \
         scan_coalesced no-hit branch. Matches: {:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref().to_string(), m.credential.to_string()))
            .collect::<Vec<_>>(),
    );
}

// Asserts the `entropy-generic` detector fires, which is compiled out without
// the `entropy` feature; gate the test to the feature so `--no-default-features`
// (lean / portable-without-entropy) builds stay green instead of failing on a
// detector that cannot exist in that configuration.
#[cfg(feature = "entropy")]
#[test]
fn bare_entropy_secret_file_still_enters_coalesced_no_hit_branch() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let chunk = make_chunk(
        &format!("VALUE={BARE_ENTROPY_SECRET}\n"),
        "config/secrets.env",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref() == "entropy-generic"
            && m.credential.as_ref().contains(BARE_ENTROPY_SECRET)
    });
    assert!(
        entropy_fired,
        "bare high-entropy value in a secret/config file must still be admitted \
         through the no-hit coalesced branch; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn bare_entropy_secret_enters_portable_per_chunk_no_hit_path() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_portable_entropy_scanner(config);
    let chunk = make_chunk(
        &format!("VALUE={BARE_ENTROPY_SECRET}\n"),
        "config/portable-secrets.env",
    );

    let admission = scanner.phase1_admission_summary(std::slice::from_ref(&chunk));
    assert_eq!(admission.admitted_chunks, 0);
    assert_eq!(
        admission.alphabet_rejected_chunks + admission.bigram_rejected_chunks,
        1,
        "fixture must be rejected by direct-literal admission"
    );
    let matches = scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback);
    assert!(
        matches.iter().any(|finding| {
            finding.detector_id.as_ref() == "entropy-generic"
                && finding.credential.as_ref().contains(BARE_ENTROPY_SECRET)
        }),
        "portable CPU fallback must not skip anchorless entropy findings: {matches:?}"
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_bare_entropy_secret_enters_coalesced_no_hit_branch_on_plain_text_path() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "KP4QX7RM2SN5TB8VW3YZ";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated full-line high-entropy token must enter the no-hit coalesced \
         entropy path even when the plain-text path is not otherwise entropy-eligible; \
         matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn embedded_isolated_entropy_secret_enters_coalesced_no_hit_branch_on_plain_text_path() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn";
    let prefix = "prefixFiller0123456789".repeat(12);
    let chunk = make_chunk(
        &format!("{prefix} {secret}\n"),
        "notes/sufficiency-probe.txt",
    );

    let direct = scanner.scan(&chunk);
    assert!(
        direct.iter().any(|m| m.credential.as_ref() == secret),
        "direct scan must recover an embedded isolated entropy token after same-line filler; matches={:?}",
        direct
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.location.offset))
            .collect::<Vec<_>>()
    );

    scanner.clear_fragment_cache();
    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "coalesced no-hit admission must not reject an embedded isolated entropy token on a \
         plain-text path only because same-line filler precedes it; matches={:?}",
        matches
            .iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.offset
            ))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn zero_width_generic_assignment_enters_coalesced_no_hit_branch_after_normalization() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn";
    let chunk = make_chunk(
        &format!("se\u{200B}cretKey=\"{secret}\"\n"),
        "notes/normalized-no-hit.txt",
    );

    scanner.clear_fragment_cache();
    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "coalesced no-hit admission must consult normalized text for generic/entropy \
         anchors instead of falling through to decode-only or empty output; matches={:?}",
        matches
            .iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.offset
            ))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn deterministic_same_line_filler_does_not_surface_as_embedded_isolated_secret() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let filler = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789..".repeat(4);
    let chunk = make_chunk(&format!("{filler}\n"), "notes/sufficiency-probe.txt");

    let direct = scanner.scan(&chunk);
    assert!(
        direct.iter().all(|m| m.credential.as_ref() != filler),
        "direct scan must suppress deterministic alphabet filler; matches={:?}",
        direct
            .iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.offset
            ))
            .collect::<Vec<_>>()
    );

    scanner.clear_fragment_cache();
    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    assert!(
        matches.iter().all(|m| m.credential.as_ref() != filler),
        "coalesced no-hit route must suppress deterministic alphabet filler; matches={:?}",
        matches
            .iter()
            .map(|m| (
                m.detector_id.as_ref(),
                m.credential.as_ref(),
                m.location.offset
            ))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_short_dash_entropy_secret_enters_direct_scan_prefilter_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "QXjK-nCvdgB1eKnjRTfl";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "a direct single-chunk scan must recover a no-literal isolated entropy \
         token instead of stopping at the alphabet/bigram prefilter; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn multiline_symbolic_isolated_candidate_enters_coalesced_no_hit_branch() {
    let scanner = compile_scanner_with_config(ScannerConfig::default());
    let secret = "BadCbc0#-DE&1$FA";
    let chunk = make_chunk(&format!("`{secret}`\\\n\n"), "notes/multiline-symbolic.txt");

    let direct = scanner.scan(&chunk);
    assert!(
        direct.iter().any(|m| m.credential.as_ref() == secret),
        "direct scan must surface the multiline-isolated symbolic candidate; matches={:?}",
        direct
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );

    scanner.clear_fragment_cache();
    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    assert!(
        matches.iter().any(|m| m.credential.as_ref() == secret),
        "coalesced no-hit branch must admit multiline preprocessing when it creates \
         an isolated entropy candidate; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_bare_base64_shaped_entropy_secret_bypasses_blob_shape_gate() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated full-line token must not be hard-dropped only because its \
         bytes also satisfy the random-base64 blob shape; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_bare_base64_random_byte_shape_reaches_audit_floor() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated full-line base64-shaped token that decodes to random bytes \
         must reach the audit/report-floor path instead of being hard-dropped \
         as an assignment-sourced random-byte blob; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn credential_assignment_base64_random_byte_shape_reaches_audit_floor() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "JwbAykwNNL4zIbfQOSw6FvkB5uYAFzOQidAQ9PTG";
    let cases = [
        (
            format!("SERVICE_API_TOKEN=\"{secret}\"\n"),
            "deploy/.env",
            "env assignment",
        ),
        (
            format!("{{\n  \"service\": {{\n    \"apiToken\": \"{secret}\"\n  }}\n}}\n"),
            "settings/config.json",
            "camelCase JSON field",
        ),
        (
            format!("const client = new Client({{ token: \"{secret}\" }});\n"),
            "src/client.js",
            "nested source object field",
        ),
    ];

    for (body, path, label) in cases {
        let chunk = make_chunk(&body, path);
        let matches = scanner.scan(&chunk);
        let entropy_fired = matches.iter().any(|m| {
            m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
        });
        assert!(
            entropy_fired,
            "a same-line credential assignment ({label}) must score base64-shaped \
             random-byte tokens instead of hard-dropping them before \
             penalties/model arbitration; matches={:?}",
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_slash_bearing_base64_entropy_secret_bypasses_path_fragment_gate() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "ev0BsFtSD7S/4VWYObxiEhME3hJBXeYzR43jgiB1";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated 40-byte slash-bearing high-entropy token must not be \
         hard-dropped as a URL/path fragment solely because it contains '/'; \
         matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn authorization_call_arg_surfaces_quoted_high_entropy_token() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "cvxs2sDMfkbwkGohlpD2BuQhAcqkYTI0nCInqbKrMfyX87TPRTfNvVVq89b9VGLi";
    let body = format!("response = requests.get(url, headers={{'Authorization': '{secret}'}})\n");
    let chunk = make_chunk(&body, "src/fetch.py");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let surfaced = matches
        .iter()
        .any(|m| m.credential.as_ref().contains(secret));
    assert!(
        surfaced,
        "a quoted Authorization header value in source must reach the report path \
         instead of depending on a detector-specific service anchor; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_structured_dotted_tokens_enter_full_line_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);

    for secret in [
        "eyJ1Gk3_5qIWlCW9vrWA_Zc-CikFlEy5grq-2ah0D7iS150sDBETlYuoN_r_XnRJK0Q.A8Lrhe179XcO43ta8Er9KpU33H_dwrJBsHKF1z7bspluw3wF7r4mGMKpVCr9U5s-P58CXz3eACIeqezEPDEGO4PUH4LR9w.yO6nijlKQf5R0gF1JB",
        "eyJhLD.eyJU16ZBmIIV3MOOWUXh-WS4UwUtRqqHlT9ANpC.KogxfWs1PZbn20DHnHLP5g78xRyaU82oYuwJ",
    ] {
        let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");
        let matches = scanner.scan(&chunk);
        let entropy_fired = matches.iter().any(|m| {
            m.detector_id.as_ref().starts_with("entropy-")
                && m.credential.as_ref().contains(secret)
        });
        assert!(
            entropy_fired,
            "an isolated full-line structured dotted token must enter entropy \
             recovery instead of being rejected by the JWT-shaped universal \
             plausibility gate; secret={secret}; matches={:?}",
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_unstructured_dotted_values_stay_suppressed() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);

    for value in [
        "this.someService.copilotToken1234567890",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
    ] {
        let chunk = make_chunk(value, "notes/sufficiency-probe.txt");
        let matches = scanner.scan(&chunk);
        let entropy_fired = matches.iter().any(|m| {
            m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(value)
        });
        assert!(
            !entropy_fired,
            "property-access and two-segment JWT-looking values must not enter \
             isolated dotted-token recovery; value={value}; matches={:?}",
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_bare_split_entropy_secret_bypasses_identifier_emit_gate() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "kp4qx7rm_sn5tb8vw_3yzkp4qx";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated whole-line mixed token that uses underscore separators must not be \
         killed by the word-separated identifier gate after the isolated-token extractor \
         already proved the whole line is the credential candidate; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_leading_slash_base64_entropy_secrets_bypass_path_rejection() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);

    for secret in [
        "/ZM9TBrKrmGsNmjQ8mT3OA94HhblZa+QFPiyCEs5lkO/nMLpQAK4lXOELxyxeH8ilqtekYJEB1J5+TkPo/QyFcIoCVvQ2hmsCfjd==",
        "/7j3M6glXEI5gvG5RRuIQjBARCDxbz8wJWl3EiPP",
    ] {
        let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");
        let matches = scanner.scan(&chunk);
        let entropy_fired = matches.iter().any(|m| {
            m.detector_id.as_ref().starts_with("entropy-")
                && m.credential.as_ref().contains(secret)
        });
        assert!(
            entropy_fired,
            "an isolated leading-slash base64 token must not be rejected only \
             because `/` can start a path; secret={secret}; matches={:?}",
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_absolute_path_with_random_segment_stays_below_leading_slash_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let path = "/tmp/Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz/cache";
    let chunk = make_chunk(path, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(path)
    });
    assert!(
        !entropy_fired,
        "slash-separated absolute paths must not enter the isolated leading-slash \
         base64 token exception; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_symbol_heavy_entropy_secrets_enter_full_line_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);

    let secret = "RJ{4~d__D!Ts3S-jP46V~SAQ";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");
    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated symbol-heavy high-entropy credential must enter the \
         full-line recovery path; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_dictionary_password_with_one_symbol_stays_below_symbol_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let value = "SnowFlakePass123!";
    let chunk = make_chunk(value, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(value)
    });
    assert!(
        !entropy_fired,
        "dictionary-style passwords with one punctuation mark must not enter \
         the symbol-heavy full-line recovery branch; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_no_digit_symbolic_random_secret_enters_full_line_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "AFHzLDdEbht+JO%$Qr";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated no-digit symbolic credential must enter full-line recovery \
         when the shared randomness model says its alphabetic runs are random; \
         matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_no_digit_symbolic_identifier_stays_suppressed() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let identifier = "OAuthTokenSecret!@#Value";
    let chunk = make_chunk(identifier, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(identifier)
    });
    assert!(
        !entropy_fired,
        "credential-word identifiers with punctuation must stay below the \
         no-digit symbolic recovery branch; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_colon_separated_opaque_entropy_secret_enters_full_line_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "Kp4Qx7Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn5Tb8Vw3Yz:Kp4Qx7Rm2Sn5Tb8V";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "a single-colon opaque credential made of two random alnum halves must \
         enter isolated full-line recovery; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_hash_scheme_and_short_password_colon_values_stay_suppressed() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    for value in [
        "sha256:7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d7b3e5d8c1a9f4e2b6c8d3a5e9f1b7c4d",
        "user:CorrectHorseBattery123",
    ] {
        let chunk = make_chunk(value, "notes/sufficiency-probe.txt");
        let matches = scanner.scan(&chunk);
        let entropy_fired = matches.iter().any(|m| {
            m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(value)
        });
        assert!(
            !entropy_fired,
            "hash-scheme and short user/password colon shapes must not enter \
             the isolated colon-token recovery branch; value={value}; matches={:?}",
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_bang_led_symbolic_entropy_secret_bypasses_punctuation_gate() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret =
        "!t1c!_Axt_7ARTF*Pzzl8L8qY*XoT5AiY2Yo-ppyTjrjvA0JAM2UPZFE1iFJa4U2q=#GhFKv&2UJR7wOQqIiQ6qWW";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "a long high-entropy credential that legitimately starts with `!` must \
         not be discarded as a punctuation-decorated identifier; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_js_coercion_identifier_stays_below_bang_led_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let identifier = "!!apiKeyOrOAuthToken1234567890CredentialName";
    let chunk = make_chunk(identifier, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(identifier)
    });
    assert!(
        !entropy_fired,
        "JS truthy-coercion / decorated identifier shapes must stay suppressed \
         even though long `!`-led opaque credential bodies are recoverable; \
         matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_mixed_underscore_entropy_secret_enters_direct_scan_prefilter_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "H_ZM9TBrKrmGsNmjQ8mT";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated mixed-case/digit underscore token must enter direct no-hit \
         entropy recovery instead of being filtered as a low-entropy identifier; \
         matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_snake_case_identifier_with_digits_stays_below_entropy_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let identifier = "s3_secret_access_key";
    let chunk = make_chunk(identifier, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(identifier)
    });
    assert!(
        !entropy_fired,
        "snake_case identifiers with digits must not enter the isolated-token \
         separator floor; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_mixed_alnum_entropy_secret_uses_randomness_floor() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "C372xGw30nSx5QdQuTxy";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "an isolated 20-byte mixed alnum token that the shared randomness model \
         classifies as random must clear the lower full-line floor; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_camelcase_identifier_with_digits_stays_below_mixed_alnum_floor() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let identifier = "ClientSecretConfigValue2";
    let chunk = make_chunk(identifier, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(identifier)
    });
    assert!(
        !entropy_fired,
        "pronounceable camelCase identifiers with digits must not enter the \
         lower mixed-alnum isolated-token floor; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_bare_dash_entropy_secret_bypasses_serial_decoy_gate() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let secret = "Kp4Qx7-Rm2Sn5Tb8Vw3YzKp4Qx7Rm2Sn";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let matches = &results[0];
    let entropy_fired = matches.iter().any(|m| {
        m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
    });
    assert!(
        entropy_fired,
        "a random isolated token with an embedded dash must not be killed by the \
         dash-segmented serial decoy gate; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_lower_dash_app_password_enters_full_line_recovery() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "kp4q-x7rm-2sn5-tb8v";
    let chunk = make_chunk(secret, "notes/sufficiency-probe.txt");

    let matches = scanner.scan(&chunk);
    let entropy_matches = matches
        .iter()
        .filter(|m| {
            m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
        })
        .count();
    assert_eq!(
        entropy_matches,
        1,
        "an isolated lowercase 4x4 app-password token with mixed alnum groups \
         must emit exactly once after clearing the app-password floor instead of requiring a service \
         keyword anchor; matches={:?}",
        matches
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
            .collect::<Vec<_>>()
    );
}

#[cfg(feature = "entropy")]
#[test]
fn lower_dash_app_password_surfaces_in_assignment_contexts() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);
    let secret = "kp4q-x7rm-2sn5-tb8v";
    let cases = [
        (
            format!("export SERVICE_API_TOKEN={secret}\n"),
            "deploy/.env",
            "env export",
        ),
        (
            format!("config:\n  service:\n    api_token: {secret}\n"),
            "k8s/values.yaml",
            "yaml value",
        ),
        (
            format!("const client = new Client({{ token: \"{secret}\" }});\n"),
            "src/client.js",
            "source assignment",
        ),
    ];

    for (body, path, label) in cases {
        let chunk = make_chunk(&body, path);
        let matches = scanner.scan(&chunk);
        let entropy_fired = matches.iter().any(|m| {
            m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(secret)
        });
        assert!(
            entropy_fired,
            "a lowercase 4x4 app-password token must surface in {label} \
             context once it is sufficient as an isolated credential; \
             matches={:?}",
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
                .collect::<Vec<_>>()
        );
    }
}

#[cfg(feature = "entropy")]
#[test]
fn isolated_lower_dash_identifiers_and_hex_serials_stay_suppressed() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    config.penalize_test_paths = false;
    let scanner = compile_scanner_with_config(config);

    for value in [
        "abcd-efgh-ijkl-mnop",
        "1a2b-3c4d-5e6f-7a8b",
        "A1B2-C3D4-E5F6-G7H8",
    ] {
        let chunk = make_chunk(value, "notes/sufficiency-probe.txt");
        let matches = scanner.scan(&chunk);
        let entropy_fired = matches.iter().any(|m| {
            m.detector_id.as_ref().starts_with("entropy-") && m.credential.as_ref().contains(value)
        });
        assert!(
            !entropy_fired,
            "identifier-like, all-hex, and uppercase serial 4x4 dash shapes \
             must stay below the lowercase app-password recovery branch; \
             value={value}; matches={:?}",
            matches
                .iter()
                .map(|m| (m.detector_id.as_ref(), m.credential.as_ref(), m.confidence))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn bare_entropy_source_file_obeys_default_entropy_source_gate() {
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    let scanner = compile_scanner_with_config(config);
    let chunk = make_chunk(
        &format!("const VALUE = \"{BARE_ENTROPY_SECRET}\";\n"),
        "src/lib.rs",
    );

    let results = scanner.scan_coalesced(std::slice::from_ref(&chunk));
    let leaked = results[0]
        .iter()
        .any(|m| m.credential.as_ref().contains(BARE_ENTROPY_SECRET));
    assert!(
        !leaked,
        "source files must not emit bare entropy findings unless entropy_source_files is enabled; matches={:?}",
        results[0]
            .iter()
            .map(|m| (m.detector_id.as_ref(), m.credential.as_ref()))
            .collect::<Vec<_>>()
    );
}
