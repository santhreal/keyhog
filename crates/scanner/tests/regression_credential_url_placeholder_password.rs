//! Regression: a credentialled URL whose PASSWORD SUB-FIELD is a placeholder is
//! not a finding.
//!
//! # The class this closes
//!
//! A connection-string detector captures the whole `scheme://user:pass@host`
//! span as the credential. Every placeholder gate in the suppression tree tests
//! the WHOLE captured value, so a template password is invisible to all of them:
//! `looks_like_bracketed_template_placeholder` requires the value to start `<`
//! and end `>`, and `postgresql://olympus:<password>@localhost:5433/olympus`
//! does neither. The URL therefore reached the report at CRITICAL, and an
//! ordinary repository with `.env.example`-style connection strings could not
//! gate CI on keyhog without a baseline.
//!
//! The gate (`decision.rs` 5e4) re-runs the STRUCTURAL placeholder tests against
//! the extracted password alone. This file pins:
//!
//!   * every credentialled-URL detector in the registry, enumerated at run time
//!     from each detector's OWN positive fixture, so a connection-string
//!     detector added tomorrow is covered the day its spec lands and no id list
//!     here can go stale;
//!   * every placeholder FORM, so the fix is not pinned to the reported
//!     `<password>` spelling;
//!   * the negative twin per detector: the detector's own vetted positive, whose
//!     password is real, still fires. That is the property a false-positive fix
//!     is most likely to break;
//!   * the boundary cases that separate "the password IS a placeholder" from
//!     "the password merely CONTAINS placeholder-shaped bytes".
//!
//! # What it does not catch
//!
//! The union is derived from fixtures, so a detector that CAN match a
//! credentialled URL through a secondary pattern while its positive fixture uses
//! a different shape (`keystonejs-credentials`, whose fixture is a session
//! secret) is out of scope here. Giving that detector a URL fixture is what
//! brings it in; nothing in this file needs to change.
//!
//! The gate consults the curated placeholder vocabulary, so a real password that
//! happens to open with a bounded vocabulary word (`example…`, `changeme…`) is
//! suppressed. That is pre-existing behaviour for the identical value on the
//! generic-password path; this gate makes the URL path agree with it rather than
//! introducing it. Instructional fragments (`insert`, `change`, `replace`) are
//! deliberately NOT consulted here: a URL is strong positive evidence, so a
//! substring collision must not cost a critical finding.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::{
    credential_url_userinfo_password_for_test, named_detector_suppressed,
};

/// One credentialled-URL detector and a URL of its own to exercise it with.
struct UrlCase {
    id: String,
    /// The URL span lifted out of the detector's positive fixture, in the exact
    /// shape that detector's pattern composes.
    url: String,
    /// The password sub-field inside [`Self::url`]. Real, because it came from a
    /// fixture the detector is required to fire on.
    password: String,
}

/// Password forms that are a template, never a secret. Each is the whole
/// password sub-field.
const PLACEHOLDER_PASSWORDS: &[&str] = &[
    // The form in the reported false positive.
    "<password>",
    "<PASSWORD>",
    "{password}",
    "{{redis_password}}",
    "${DB_PASSWORD}",
    "$DB_PASSWORD",
    "CHANGEME",
    "your_password_here",
    "xxxxxxxxxxxx",
];

/// The URL span around the first `scheme://` in `text`, plus its password
/// sub-field. `None` when `text` carries no credentialled URL.
///
/// The span runs from the start of the scheme to the first byte that cannot be
/// part of a URL in a config file or shell line: whitespace, a quote, or a
/// comma. Fixtures embed URLs in assignments (`CLICKHOUSE_URL=clickhouse://…`),
/// so the leading key has to come off before the value is a credential.
fn url_span(text: &str) -> Option<(String, String)> {
    let separator = text.find("://")?;
    let scheme_start = text[..separator]
        .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '+'))
        .map_or(0, |index| index + 1);
    let tail = &text[separator + 3..];
    let end = tail
        .find(|c: char| c.is_ascii_whitespace() || c == '"' || c == '\'' || c == ',')
        .map_or(text.len(), |offset| separator + 3 + offset);
    let url = &text[scheme_start..end];
    let password = credential_url_userinfo_password_for_test(url)?;
    if password.is_empty() {
        return None;
    }
    Some((url.to_string(), password.to_string()))
}

/// Every credentialled-URL detector in the registry, derived at run time from
/// the detectors' own `[[detector.tests]] test_positive` fixtures. There is no
/// id list to keep: a detector is in scope exactly when it declares a positive
/// whose credential is a `scheme://user:password@host` URL.
fn url_cases() -> Vec<UrlCase> {
    let mut cases = Vec::new();
    for spec in keyhog_core::embedded_detector_specs() {
        for test in &spec.tests {
            let Some(positive) = test.test_positive.as_deref() else {
                continue;
            };
            let Some((url, password)) = url_span(positive) else {
                continue;
            };
            cases.push(UrlCase {
                id: spec.id.clone(),
                url,
                password,
            });
        }
    }
    cases
}

fn suppressed(detector_id: &str, credential: &str) -> bool {
    named_detector_suppressed(
        credential,
        Some("scripts/firewall-peer-mac.sh"),
        // Assignment carries the highest context multiplier, so it is the
        // hardest context in which to suppress. Passing here covers the softer
        // documentation/comment contexts.
        CodeContext::Assignment,
        Some("filesystem"),
        detector_id,
    )
}

/// Anti-vacuity. Every assertion below iterates a derived set, so an empty or
/// collapsed derivation would turn this file into a suite that proves nothing
/// while staying green. The reported detector must be in it by name.
#[test]
fn the_derived_union_is_populated_and_contains_the_reported_detector() {
    let cases = url_cases();
    assert!(
        cases.len() >= 10,
        "derivation collapsed: only {} credentialled-URL fixtures found",
        cases.len()
    );
    assert!(
        cases
            .iter()
            .any(|case| case.id == "postgresql-connection-string"),
        "the detector from the reported false positive is not in the derived union: {:?}",
        cases.iter().map(|case| &case.id).collect::<Vec<_>>()
    );
}

#[test]
fn placeholder_password_suppresses_for_every_detector_and_every_form() {
    for case in url_cases() {
        for password in PLACEHOLDER_PASSWORDS {
            let credential = case.url.replace(&case.password, password);
            assert!(
                suppressed(&case.id, &credential),
                "{}: placeholder password {password:?} must not surface: {credential}",
                case.id
            );
        }
    }
}

/// The negative twin, run against each detector's OWN vetted positive. A gate
/// that suppressed these would be silently deleting the findings the detector
/// exists to produce.
#[test]
fn the_fixture_password_still_fires_for_every_detector() {
    for case in url_cases() {
        assert!(
            !suppressed(&case.id, &case.url),
            "{}: fixture password {:?} must still surface: {}",
            case.id,
            case.password,
            case.url
        );
    }
}

/// The exact value from the external audit that motivated the gate.
#[test]
fn reported_psycopg_url_is_suppressed() {
    assert!(suppressed(
        "postgresql-connection-string",
        "postgresql://olympus:<password>@localhost"
    ));
}

#[test]
fn placeholder_bytes_outside_the_password_field_do_not_suppress() {
    // A template HOST with a real password is still a leaked credential: the
    // gate reads the password sub-field only.
    assert!(!suppressed(
        "postgresql-connection-string",
        "postgresql://olympus:w0kVdGwi5GpLapAX@<host>"
    ));
    // A template USERNAME likewise says nothing about the password.
    assert!(!suppressed(
        "postgresql-connection-string",
        "postgresql://${DB_USER}:w0kVdGwi5GpLapAX@localhost"
    ));
}

#[test]
fn a_password_that_only_resembles_a_template_still_fires() {
    // Unterminated wrapper: not a template, and `password` is not a vocabulary
    // word, so the value is treated as the secret it looks like.
    assert!(!suppressed(
        "postgresql-connection-string",
        "postgresql://olympus:<passwordXk29fjQ2@localhost"
    ));
    // `$` followed by non-identifier bytes is a bcrypt-shaped secret, not a
    // shell variable reference.
    assert!(!suppressed(
        "postgresql-connection-string",
        "postgresql://olympus:$2y$10$N9qo8uLOickgx2ZMRZo@localhost"
    ));
}

/// A URL with no password sub-field must not be dragged through the gate: the
/// span between scheme and `@` is a username, and the gate has no secret to
/// judge.
#[test]
fn url_without_a_password_field_is_untouched_by_the_gate() {
    // `ssh://git@host` has userinfo but no `:`, so no password span exists.
    // Whatever the rest of the tree decides, the placeholder gate contributes
    // nothing, which is what the negative below pins.
    assert!(!suppressed(
        "postgresql-connection-string",
        "postgresql://w0kVdGwi5GpLapAX@localhost"
    ));
}
