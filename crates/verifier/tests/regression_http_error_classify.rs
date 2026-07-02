//! Regression lock: the verifier's OOB (interactsh) HTTP-client error
//! **classification + redaction** contract.
//!
//! The OOB collector client (`crates/verifier/src/oob/`) is a real HTTP client:
//! it registers, polls, and deregisters against a collector over HTTPS, and
//! every failure is funnelled into exactly one [`InteractshError`] variant. That
//! error is then run through [`redact_interactsh_error`] before it is ever
//! logged, because a raw `reqwest::Error`'s `Display` bakes in the poll URL —
//! and the poll URL embeds the session correlation secret. The redaction policy
//! is deliberately **variant-scoped**:
//!
//!   * `InteractshError::Transport(reqwest::Error)` is collapsed to a
//!     category-only string (`kind=connect|timeout|request|body|decode|status`)
//!     with the URL stripped.
//!   * **Every other variant** is hand-written to embed no URL, so redaction is
//!     an exact, byte-for-byte pass-through of its `Display`.
//!
//! This file pins the pass-through half with **exact** operator-facing strings
//! (the `unit/oob_redact_transport_errors.rs` boundary test only asserts weak
//! `.contains(...)` shapes and skips `Deregister`/`KeyEncode`; here every
//! assertion is the full message verbatim), plus the structural invariants that
//! keep the taxonomy diagnosable: pairwise distinctness, phase preservation
//! across the register/poll/deregister trio, sub-second timeout rendering, and
//! adversarial format-injection safety.
//!
//! Nothing here opens a socket or touches an accelerator — the classification is
//! pure and host-independent. The `Transport` branch is intentionally NOT tested
//! here: constructing a `reqwest::Error` requires the `reqwest` crate, which is a
//! normal dependency of `keyhog-verifier` and NOT a dev-dependency, so it is
//! unreachable from a standalone integration-test binary. That branch is covered
//! by in-crate unit tests instead. This file is distinct from
//! `regression_probe_timeout_mapping.rs` (main-path transport constant strings +
//! Poll/Timeout/Register only) and `regression_status_verdict_map.rs` (the AWS
//! STS status classifier).

use std::collections::HashSet;
use std::time::Duration;

use keyhog_verifier::oob::{redact_interactsh_error, InteractshError};

// ────────────────────────────────────────────────────────────────────────────
// Group A — exact operator-facing message for each non-transport variant.
// redact == Display, byte-for-byte, for every variant except `Transport`.
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn keygen_error_redacts_to_exact_message() {
    let err = InteractshError::KeyGen("rng exhausted".to_string());
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh keypair generation failed: rng exhausted"
    );
}

/// `KeyEncode` is untested by the existing weak boundary test — pin its exact
/// message so the RSA-public-key-encoding failure phrase can't silently drift.
#[test]
fn keyencode_error_redacts_to_exact_message() {
    let err = InteractshError::KeyEncode("der write failed".to_string());
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh public-key encoding failed: der write failed"
    );
}

#[test]
fn register_http_status_failure_redacts_to_exact_message() {
    let err = InteractshError::Register {
        status: 401,
        body: "unauthorized".to_string(),
    };
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh register failed (HTTP 401): unauthorized"
    );
}

/// `Deregister` is untested by the existing weak boundary test — pin its exact
/// message and confirm the phase word is `deregister`, not `register`.
#[test]
fn deregister_http_status_failure_redacts_to_exact_message() {
    let err = InteractshError::Deregister {
        status: 500,
        body: "cleanup rejected".to_string(),
    };
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh deregister failed (HTTP 500): cleanup rejected"
    );
}

#[test]
fn poll_http_status_failure_redacts_to_exact_message() {
    let err = InteractshError::Poll {
        status: 404,
        body: "not found".to_string(),
    };
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh poll failed (HTTP 404): not found"
    );
}

#[test]
fn bad_response_error_redacts_to_exact_message() {
    let err = InteractshError::BadResponse("data present but aes_key missing".to_string());
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh response shape unexpected: data present but aes_key missing"
    );
}

#[test]
fn blocked_collector_error_redacts_to_exact_message() {
    let err = InteractshError::BlockedCollector("169.254.169.254".to_string());
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh collector host blocked by SSRF guard: 169.254.169.254"
    );
}

#[test]
fn aes_unwrap_error_redacts_to_exact_message() {
    let err = InteractshError::AesUnwrap("rsa-oaep: decryption error".to_string());
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh AES key unwrap failed: rsa-oaep: decryption error"
    );
}

#[test]
fn decrypt_error_redacts_to_exact_message() {
    let err = InteractshError::Decrypt("cfb init: bad iv length".to_string());
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh interaction decrypt failed: cfb init: bad iv length"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Group B — timeout rendering. The transport-deadline variant renders the exact
// `Duration` via its `Debug` form; pin sub-second and zero boundaries (the
// existing test only covers a whole-second 7s value).
// ────────────────────────────────────────────────────────────────────────────

#[test]
fn timeout_error_renders_subsecond_duration_exactly() {
    let err = InteractshError::Timeout(Duration::from_millis(1500));
    assert_eq!(
        redact_interactsh_error(&err),
        "interactsh request timed out after 1.5s"
    );
}

#[test]
fn timeout_error_renders_millisecond_and_zero_boundaries_exactly() {
    let millis = InteractshError::Timeout(Duration::from_millis(250));
    assert_eq!(
        redact_interactsh_error(&millis),
        "interactsh request timed out after 250ms"
    );

    let zero = InteractshError::Timeout(Duration::ZERO);
    assert_eq!(
        redact_interactsh_error(&zero),
        "interactsh request timed out after 0ns"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Group C — structural invariants of the classification.
// ────────────────────────────────────────────────────────────────────────────

/// The register / deregister / poll trio share the `(HTTP {status}): {body}`
/// shape, so at an identical status+body they must stay distinguishable purely
/// by the phase word — losing the phase would hide which lifecycle step failed.
#[test]
fn register_deregister_poll_stay_phase_distinct_at_same_status_and_body() {
    let register = redact_interactsh_error(&InteractshError::Register {
        status: 503,
        body: "same".to_string(),
    });
    let deregister = redact_interactsh_error(&InteractshError::Deregister {
        status: 503,
        body: "same".to_string(),
    });
    let poll = redact_interactsh_error(&InteractshError::Poll {
        status: 503,
        body: "same".to_string(),
    });

    assert_eq!(register, "interactsh register failed (HTTP 503): same");
    assert_eq!(deregister, "interactsh deregister failed (HTTP 503): same");
    assert_eq!(poll, "interactsh poll failed (HTTP 503): same");

    let set: HashSet<&String> = [&register, &deregister, &poll].into_iter().collect();
    assert_eq!(set.len(), 3, "phase word must keep the three distinct");
}

/// Every non-transport variant must redact to a distinct operator string —
/// an operator has to be able to tell a keygen failure from a decrypt failure
/// from an SSRF refusal. A collision here is a real diagnostics bug.
#[test]
fn all_ten_non_transport_variants_redact_pairwise_distinct() {
    let reasons = [
        redact_interactsh_error(&InteractshError::KeyGen("x".to_string())),
        redact_interactsh_error(&InteractshError::KeyEncode("x".to_string())),
        redact_interactsh_error(&InteractshError::Register {
            status: 400,
            body: "x".to_string(),
        }),
        redact_interactsh_error(&InteractshError::Deregister {
            status: 400,
            body: "x".to_string(),
        }),
        redact_interactsh_error(&InteractshError::Poll {
            status: 400,
            body: "x".to_string(),
        }),
        redact_interactsh_error(&InteractshError::BadResponse("x".to_string())),
        redact_interactsh_error(&InteractshError::BlockedCollector("x".to_string())),
        redact_interactsh_error(&InteractshError::AesUnwrap("x".to_string())),
        redact_interactsh_error(&InteractshError::Decrypt("x".to_string())),
        redact_interactsh_error(&InteractshError::Timeout(Duration::from_secs(1))),
    ];
    let unique: HashSet<&String> = reasons.iter().collect();
    assert_eq!(
        unique.len(),
        10,
        "all 10 non-transport error classifications must be pairwise distinct"
    );
}

/// Redaction is Transport-scoped ONLY: a non-transport variant is passed through
/// verbatim even when its payload happens to embed a full URL with a secret
/// query param. This pins the actual policy — the code trusts every non-transport
/// variant to be constructed without the poll URL, and never scrubs them. If a
/// future change routed the poll URL into (say) `BadResponse`, this test would
/// still pass, but the invariant it documents is exactly why that must never
/// happen: only `Transport` carries reqwest's URL, so only `Transport` is scrubbed.
#[test]
fn redaction_is_transport_scoped_non_transport_payload_passes_through_verbatim() {
    let payload = "https://oast.fun/poll?id=abc&secret=deadbeef";
    let err = InteractshError::BlockedCollector(payload.to_string());
    assert_eq!(
        redact_interactsh_error(&err),
        format!("interactsh collector host blocked by SSRF guard: {payload}"),
    );
}

/// Adversarial: a body containing brace/format tokens and newlines must be
/// preserved literally — the message is built with a captured Display, never a
/// second `format!` over attacker-influenced text, so `{}`/`{0}`/`\n` are inert.
#[test]
fn error_body_with_format_tokens_and_newlines_is_preserved_verbatim() {
    let hostile = "{}{0}{status}\nline2\t{{escaped}}";
    let err = InteractshError::Poll {
        status: 418,
        body: hostile.to_string(),
    };
    assert_eq!(
        redact_interactsh_error(&err),
        format!("interactsh poll failed (HTTP 418): {hostile}"),
    );
}

/// Boundary: a zero status with an empty body renders the fixed prefix with an
/// empty tail, and the numeric `u16` upper bound (65535) renders unclamped.
#[test]
fn status_and_body_numeric_boundaries_render_exactly() {
    let zero = InteractshError::Register {
        status: 0,
        body: String::new(),
    };
    assert_eq!(
        redact_interactsh_error(&zero),
        "interactsh register failed (HTTP 0): "
    );

    let max = InteractshError::Deregister {
        status: u16::MAX,
        body: "edge".to_string(),
    };
    assert_eq!(
        redact_interactsh_error(&max),
        "interactsh deregister failed (HTTP 65535): edge"
    );
}
