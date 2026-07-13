//! #131 UX lock (batch 2): the two remaining bare verifier reasons 
//! `max retries exceeded` and `invalid AWS region`: now carry context + an
//! actionable fix, and a family-wide contract gate covers ALL SIX actionable
//! verification reasons so a future edit can't reintroduce a bare token. Each
//! message keeps its legacy short phrase as the leading substring (Law 3:
//! downstream `.contains` checks keep matching).

use keyhog_verifier::testing::{
    CONNECTION_FAILED_ERROR, INVALID_AWS_REGION_ERROR, MAX_RETRIES_ERROR, REDIRECT_LIMIT_ERROR,
    REQUEST_FAILED_ERROR, TIMEOUT_ERROR,
};

/// Every operator-facing verification reason that describes an ACTIONABLE failure
/// (as opposed to a security refusal like `blocked: private URL`). Each must
/// state the problem and a concrete fix.
const ACTIONABLE_REASONS: &[(&str, &str)] = &[
    (TIMEOUT_ERROR, "timeout"),
    (CONNECTION_FAILED_ERROR, "connection failed"),
    (REDIRECT_LIMIT_ERROR, "too many redirects"),
    (REQUEST_FAILED_ERROR, "request failed"),
    (MAX_RETRIES_ERROR, "max retries exceeded"),
    (INVALID_AWS_REGION_ERROR, "invalid AWS region"),
];

/// The substring after the `Fix:` marker (the remedy guidance).
fn fix_portion(msg: &str) -> &str {
    let idx = msg
        .find("Fix:")
        .expect("message must contain a Fix: marker");
    &msg[idx + "Fix:".len()..]
}

// ── MAX_RETRIES_ERROR ─────────────────────────────────────────────────────────

#[test]
fn max_retries_leads_with_legacy_phrase() {
    assert!(
        MAX_RETRIES_ERROR.starts_with("max retries exceeded"),
        "must lead with `max retries exceeded`: {MAX_RETRIES_ERROR:?}"
    );
}

#[test]
fn max_retries_has_fix_section() {
    assert!(MAX_RETRIES_ERROR.contains("Fix:"), "must state the fix");
}

#[test]
fn max_retries_names_the_retryable_cause() {
    assert!(
        MAX_RETRIES_ERROR.contains("rate-limit") || MAX_RETRIES_ERROR.contains("retryable"),
        "must explain that the attempts hit retryable errors: {MAX_RETRIES_ERROR:?}"
    );
}

#[test]
fn max_retries_suggests_lowering_concurrency() {
    assert!(
        MAX_RETRIES_ERROR.contains("concurrency"),
        "the fix includes lowering verification concurrency: {MAX_RETRIES_ERROR:?}"
    );
}

#[test]
fn max_retries_suggests_retrying_later() {
    assert!(
        fix_portion(MAX_RETRIES_ERROR).contains("retry"),
        "the fix should suggest retrying later"
    );
}

// ── INVALID_AWS_REGION_ERROR ──────────────────────────────────────────────────

#[test]
fn aws_region_leads_with_legacy_phrase() {
    assert!(
        INVALID_AWS_REGION_ERROR.starts_with("invalid AWS region"),
        "must lead with `invalid AWS region`: {INVALID_AWS_REGION_ERROR:?}"
    );
}

#[test]
fn aws_region_has_fix_section() {
    assert!(
        INVALID_AWS_REGION_ERROR.contains("Fix:"),
        "must state the fix"
    );
}

#[test]
fn aws_region_states_the_length_limit() {
    assert!(
        INVALID_AWS_REGION_ERROR.contains("30"),
        "must name the 30-char format limit: {INVALID_AWS_REGION_ERROR:?}"
    );
}

#[test]
fn aws_region_gives_a_concrete_example() {
    assert!(
        INVALID_AWS_REGION_ERROR.contains("us-east-1"),
        "must show a valid region example: {INVALID_AWS_REGION_ERROR:?}"
    );
}

#[test]
fn aws_region_points_at_spec_or_companion() {
    assert!(
        INVALID_AWS_REGION_ERROR.contains("detector")
            || INVALID_AWS_REGION_ERROR.contains("companion"),
        "the fix must point at where to correct the region"
    );
}

// ── family-wide contract over all six actionable reasons ──────────────────────

#[test]
fn every_actionable_reason_leads_with_its_legacy_phrase() {
    for (msg, legacy) in ACTIONABLE_REASONS {
        assert!(
            msg.starts_with(legacy),
            "{legacy:?} must remain the leading substring of {msg:?}"
        );
    }
}

#[test]
fn every_actionable_reason_has_a_fix_section() {
    for (msg, _) in ACTIONABLE_REASONS {
        assert!(
            msg.contains("Fix:"),
            "every actionable reason must include `Fix:`: {msg:?}"
        );
    }
}

#[test]
fn every_actionable_reason_has_problem_then_fix_structure() {
    // A sentence boundary precedes the fix: the problem is stated, THEN the remedy.
    for (msg, _) in ACTIONABLE_REASONS {
        assert!(
            msg.contains(". Fix:"),
            "{msg:?} should state the problem as a sentence before `Fix:`"
        );
    }
}

#[test]
fn every_actionable_reason_fix_has_an_imperative_verb() {
    const VERBS: &[&str] = &[
        "check", "raise", "retry", "correct", "lower", "set", "reduce", "point",
    ];
    for (msg, _) in ACTIONABLE_REASONS {
        let fix = fix_portion(msg);
        assert!(
            VERBS.iter().any(|v| fix.contains(v)),
            "the Fix: section of {msg:?} must be actionable (imperative verb), got {fix:?}"
        );
    }
}

#[test]
fn no_actionable_reason_ends_at_the_fix_marker() {
    // Guard against a truncated message that says `Fix:` with nothing after it.
    for (msg, _) in ACTIONABLE_REASONS {
        assert!(
            fix_portion(msg).trim().len() >= 10,
            "{msg:?} has an empty/too-short Fix: section"
        );
    }
}

#[test]
fn every_actionable_reason_is_single_line() {
    for (msg, _) in ACTIONABLE_REASONS {
        assert!(
            !msg.contains('\n'),
            "reason must be single-line for report/SARIF: {msg:?}"
        );
    }
}

#[test]
fn no_actionable_reason_has_a_double_space() {
    for (msg, _) in ACTIONABLE_REASONS {
        assert!(
            !msg.contains("  "),
            "reason has a double space (bad line continuation): {msg:?}"
        );
    }
}

#[test]
fn no_actionable_reason_leaks_a_template_placeholder() {
    for (msg, _) in ACTIONABLE_REASONS {
        assert!(
            !msg.contains("{credential}") && !msg.contains("companion."),
            "static reason must not carry an interpolation placeholder: {msg:?}"
        );
    }
}

#[test]
fn every_actionable_reason_is_substantial() {
    for (msg, _) in ACTIONABLE_REASONS {
        assert!(
            msg.len() >= 60,
            "{msg:?} is too short to carry context + fix"
        );
    }
}

#[test]
fn all_actionable_reasons_are_distinct() {
    let msgs: Vec<&str> = ACTIONABLE_REASONS.iter().map(|(m, _)| *m).collect();
    for i in 0..msgs.len() {
        for j in (i + 1)..msgs.len() {
            assert_ne!(msgs[i], msgs[j], "two actionable reasons collided");
        }
    }
}

#[test]
fn all_legacy_phrases_are_distinct() {
    // The leading phrases are what downstream code keys on; they must not alias.
    let phrases: Vec<&str> = ACTIONABLE_REASONS.iter().map(|(_, p)| *p).collect();
    for i in 0..phrases.len() {
        for j in (i + 1)..phrases.len() {
            assert_ne!(phrases[i], phrases[j], "two legacy phrases collided");
        }
    }
}
