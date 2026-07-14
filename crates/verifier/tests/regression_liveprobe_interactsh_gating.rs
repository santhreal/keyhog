//! Regression: OOB live-probe / interactsh gating in the detector quality gate.
//!
//! The verifier's OOB path (`[detector.verify.oob]` + `{{interactsh*}}` tokens)
//! is only sound when the block and the tokens are configured *consistently*.
//! `keyhog_core::validate_detector` fails-closed on the four ways an author can
//! get this wrong so a malformed OOB probe never ships:
//!
//!   1. `oob` block present but NO `{{interactsh*}}` token anywhere -> the
//!      callback URL has nowhere to land and `wait_for` times out forever.
//!   2. `{{interactsh*}}` token present but NO `oob` block -> the token resolves
//!      to an empty string at runtime and a malformed request is sent.
//!   3. both present -> passes (the sound configuration).
//!   4. a companion named `__keyhog_oob_*` collides with the reserved synthetic
//!      keys the OOB interpolator injects -> rejected.
//!
//! Each assertion pins the EXACT `QualityIssue::Error` payload string (byte for
//! byte, after Rust line-continuation folding) and the exact error count, not a
//! shape check. Distinct from the iter4 canary regression file.

use keyhog_core::AuthSpec;
use keyhog_core::{
    validate_detector, CompanionSpec, DetectorSpec, HeaderSpec, HttpMethod, OobPolicy, OobProtocol,
    OobSpec, PatternSpec, QualityIssue, Severity, StepSpec, SuccessSpec, VerifySpec,
};

// ── Exact expected error payloads (line-continuation `\` folds the newline AND
//    the leading whitespace on the next source line, so these are single-spaced).

const ERR_OOB_WITHOUT_TOKEN: &str =
    "verify.oob is set but no `{{interactsh}}` / `{{interactsh.host}}` / \
`{{interactsh.url}}` / `{{interactsh.id}}` token appears in any verify \
template - the OOB callback URL has nowhere to land, so the wait_for \
would always time out. Either embed an interactsh token in the body, \
URL, or a header - or remove the [detector.verify.oob] block.";

const ERR_TOKEN_WITHOUT_OOB: &str =
    "an `{{interactsh*}}` token is referenced in a verify template but no \
[detector.verify.oob] block is set - the token will resolve to an empty \
string at runtime and ship a malformed request to the service. Either \
add a [detector.verify.oob] block or remove the token.";

const ERR_OOB_MULTISTEP: &str = "verify.oob cannot be combined with multi-step verification: the \
runtime must bind each interactsh callback to a concrete request \
step, and this detector shape cannot be evaluated honestly. Use a \
single request verifier for the OOB probe or split the detector.";

// ── Builders ────────────────────────────────────────────────────────────────

/// A detector that validates with ZERO issues when `verify` is left `None`:
/// one anchored pattern with a literal prefix and a matching keyword.
fn base_detector() -> DetectorSpec {
    DetectorSpec {
        id: "demo".into(),
        name: "Demo".into(),
        service: "example".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "demo_[A-Z0-9]{8}".into(),
            ..Default::default()
        }],
        keywords: vec!["demo_".into()],
        ..Default::default()
    }
}

/// A single-request verify spec with a literal (non-templated) HTTPS URL, so the
/// only validation error that can surface is the OOB-consistency one under test.
fn base_verify() -> VerifySpec {
    VerifySpec {
        url: Some("https://api.example.com/verify".into()),
        allowed_domains: vec!["api.example.com".into()],
        ..Default::default()
    }
}

fn oob_http() -> OobSpec {
    OobSpec {
        protocol: OobProtocol::Http,
        timeout_secs: None,
        policy: OobPolicy::default(),
    }
}

fn companion(name: &str) -> CompanionSpec {
    CompanionSpec {
        name: name.into(),
        // pure char class with a TIGHT within_lines (<=5) is accepted (positional
        // anchoring) and only emits a Warning, never an Error -> keeps the Error
        // channel clean so a reserved-name Error is unambiguous.
        regex: "[A-Za-z0-9]{20}".into(),
        within_lines: 3,
        required: false,
    }
}

/// The `Error` payloads only (drops `Warning`s), in emission order.
fn errors(spec: &DetectorSpec) -> Vec<String> {
    validate_detector(spec)
        .into_iter()
        .filter_map(|issue| match issue {
            QualityIssue::Error(msg) => Some(msg),
            QualityIssue::Warning(_) => None,
        })
        .collect()
}

// ── 1. oob block WITHOUT any interactsh token -> error ────────────────────────

#[test]
fn oob_block_without_token_is_error() {
    let mut spec = base_detector();
    spec.verify = Some(VerifySpec {
        oob: Some(oob_http()),
        ..base_verify()
    });

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(errs[0], ERR_OOB_WITHOUT_TOKEN);
}

#[test]
fn oob_block_without_token_is_error_variant_not_warning() {
    let mut spec = base_detector();
    spec.verify = Some(VerifySpec {
        oob: Some(oob_http()),
        ..base_verify()
    });

    let issues = validate_detector(&spec);
    let oob_issues: Vec<&QualityIssue> = issues
        .iter()
        .filter(|i| match i {
            QualityIssue::Error(m) | QualityIssue::Warning(m) => m.contains("verify.oob is set"),
        })
        .collect();
    assert_eq!(oob_issues.len(), 1);
    assert!(
        matches!(oob_issues[0], QualityIssue::Error(_)),
        "OOB gating must fail-closed as Error, not Warning: {:?}",
        oob_issues[0]
    );
}

// ── 2. interactsh token WITHOUT an oob block -> error ─────────────────────────

#[test]
fn token_in_body_without_oob_block_is_error() {
    let mut spec = base_detector();
    spec.verify = Some(VerifySpec {
        body: Some("target={{interactsh.url}}".into()),
        ..base_verify()
    });

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(errs[0], ERR_TOKEN_WITHOUT_OOB);
}

#[test]
fn token_in_header_without_oob_block_is_error() {
    let mut spec = base_detector();
    spec.verify = Some(VerifySpec {
        headers: vec![HeaderSpec {
            name: "X-Callback".into(),
            value: "{{interactsh.host}}".into(),
        }],
        ..base_verify()
    });

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(errs[0], ERR_TOKEN_WITHOUT_OOB);
}

#[test]
fn bare_interactsh_token_in_url_without_oob_block_is_error() {
    // The bare `{{interactsh}}` spelling sits in a query param on an otherwise
    // literal, allow-listed host so no exfil / single-brace error masks it.
    let mut spec = base_detector();
    spec.verify = Some(VerifySpec {
        url: Some("https://api.example.com/cb?probe={{interactsh}}".into()),
        ..base_verify()
    });

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(errs[0], ERR_TOKEN_WITHOUT_OOB);
}

// ── 3. both present -> passes (no consistency error) ──────────────────────────

#[test]
fn oob_block_with_token_passes_clean() {
    let mut spec = base_detector();
    spec.verify = Some(VerifySpec {
        body: Some("x={{interactsh.url}}".into()),
        oob: Some(oob_http()),
        ..base_verify()
    });

    let errs = errors(&spec);
    assert_eq!(
        errs.len(),
        0,
        "a consistent OOB detector must produce zero errors, got {errs:?}"
    );
}

#[test]
fn every_interactsh_token_spelling_satisfies_the_oob_block() {
    // All four documented spellings match the `{{interactsh` substring gate, so
    // each one paired with an oob block validates clean.
    for token in [
        "{{interactsh}}",
        "{{interactsh.host}}",
        "{{interactsh.url}}",
        "{{interactsh.id}}",
    ] {
        let mut spec = base_detector();
        spec.verify = Some(VerifySpec {
            body: Some(format!("callback={token}")),
            oob: Some(oob_http()),
            ..base_verify()
        });

        let errs = errors(&spec);
        assert_eq!(
            errs.len(),
            0,
            "token spelling {token} with an oob block must be clean, got {errs:?}"
        );
    }
}

// ── Adversarial: a near-miss token is NOT recognized -> still fails closed ─────

#[test]
fn near_miss_token_does_not_satisfy_the_oob_block() {
    // `{{interact}}` lacks the trailing `sh`, so the `{{interactsh` substring
    // gate does NOT count it as an interactsh reference. With an oob block set
    // and no real token, this is the "oob without token" failure, NOT a pass.
    let mut spec = base_detector();
    spec.verify = Some(VerifySpec {
        body: Some("callback={{interact}}".into()),
        oob: Some(oob_http()),
        ..base_verify()
    });

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(errs[0], ERR_OOB_WITHOUT_TOKEN);
}

// ── 4. reserved companion names -> error ──────────────────────────────────────

#[test]
fn reserved_companion_name_oob_url_is_error() {
    let mut spec = base_detector();
    spec.companions = vec![companion("__keyhog_oob_url")];

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(
        errs[0],
        "companion 0 name '__keyhog_oob_url' is reserved for the OOB interpolator. \
Pick a different name; this collision would corrupt verify templates."
    );
}

#[test]
fn reserved_companion_name_oob_host_is_error() {
    let mut spec = base_detector();
    spec.companions = vec![companion("__keyhog_oob_host")];

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(
        errs[0],
        "companion 0 name '__keyhog_oob_host' is reserved for the OOB interpolator. \
Pick a different name; this collision would corrupt verify templates."
    );
}

#[test]
fn all_three_reserved_names_flagged_and_benign_name_is_not() {
    // Two reserved companions + one benign one at index 1. The reserved check
    // uses the companion's own index, so the errors carry indexes 0 and 2.
    let mut spec = base_detector();
    spec.companions = vec![
        companion("__keyhog_oob_url"),
        companion("safe_secret"),
        companion("__keyhog_oob_id"),
    ];

    let errs = errors(&spec);
    assert_eq!(
        errs.len(),
        2,
        "exactly the two reserved names must error, got {errs:?}"
    );
    assert_eq!(
        errs[0],
        "companion 0 name '__keyhog_oob_url' is reserved for the OOB interpolator. \
Pick a different name; this collision would corrupt verify templates."
    );
    assert_eq!(
        errs[1],
        "companion 2 name '__keyhog_oob_id' is reserved for the OOB interpolator. \
Pick a different name; this collision would corrupt verify templates."
    );
    // Negative twin: none of the errors reference the benign companion.
    assert!(
        !errs.iter().any(|e| e.contains("safe_secret")),
        "benign companion must not be flagged: {errs:?}"
    );
}

#[test]
fn non_reserved_companion_name_produces_no_reserved_error() {
    // `oob_url` (no `__keyhog_` prefix) is a perfectly legal name.
    let mut spec = base_detector();
    spec.companions = vec![companion("oob_url")];

    let errs = errors(&spec);
    assert_eq!(
        errs.len(),
        0,
        "a non-reserved companion name must not error, got {errs:?}"
    );
}

// ── oob + multi-step verification is mutually exclusive ───────────────────────

#[test]
fn oob_combined_with_multistep_is_error() {
    // A step embeds a real interactsh token (so the token/oob consistency check
    // passes), isolating the multi-step-vs-oob incompatibility error.
    let mut spec = base_detector();
    let mut verify = base_verify();
    verify.url = None; // with steps present, the default URL is not the validated one
    verify.oob = Some(oob_http());
    verify.steps = vec![StepSpec {
        name: "probe".into(),
        method: HttpMethod::Post,
        url: "https://api.example.com/step".into(),
        auth: AuthSpec::None {},
        headers: Vec::new(),
        body: Some("x={{interactsh.url}}".into()),
        success: SuccessSpec::default(),
        extract: Vec::new(),
    }];
    spec.verify = Some(verify);

    let errs = errors(&spec);
    assert_eq!(errs.len(), 1, "expected exactly one error, got {errs:?}");
    assert_eq!(errs[0], ERR_OOB_MULTISTEP);
}

// ── OobProtocol choice does not change the gating outcome ─────────────────────

#[test]
fn gating_is_independent_of_oob_protocol_and_policy() {
    // The consistency gate keys only on presence, never on protocol/policy.
    for protocol in [
        OobProtocol::Dns,
        OobProtocol::Http,
        OobProtocol::Smtp,
        OobProtocol::Any,
    ] {
        let mut spec = base_detector();
        spec.verify = Some(VerifySpec {
            // token present, oob present -> clean regardless of protocol
            body: Some("cb={{interactsh}}".into()),
            oob: Some(OobSpec {
                protocol,
                timeout_secs: Some(10),
                policy: OobPolicy::OobOnly,
            }),
            ..base_verify()
        });
        assert_eq!(
            errors(&spec).len(),
            0,
            "protocol {protocol:?} with a token must validate clean"
        );

        // Same protocol, but drop the token -> the fixed oob-without-token error.
        let mut spec_no_token = base_detector();
        spec_no_token.verify = Some(VerifySpec {
            oob: Some(OobSpec {
                protocol,
                timeout_secs: Some(10),
                policy: OobPolicy::OobOnly,
            }),
            ..base_verify()
        });
        let errs = errors(&spec_no_token);
        assert_eq!(errs.len(), 1, "protocol {protocol:?}: got {errs:?}");
        assert_eq!(errs[0], ERR_OOB_WITHOUT_TOKEN);
    }
}
