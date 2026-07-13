//! Regression coverage for the Docker image-*reference* admission gate.
//!
//! The docker source does NOT split a reference into registry/repo/tag/digest
//! parts, it admits or rejects the whole reference via `validate_image_name`
//! (a compiled, ReDoS-bounded regex plus an unsafe-character prefilter) and then
//! hands the verbatim string to `docker image save`. That validator is the pure,
//! host-independent surface: it runs *before* any docker binary is resolved or
//! spawned, so a rejected reference surfaces as exactly one wrapped
//! `SourceError` from `DockerImageSource::chunks()` on every host, docker
//! installed or not.
//!
//! This file drives the public `DockerImageSource` + `Source::chunks` path and
//! asserts:
//!   * concrete accept verdicts for real references (`ubuntu:22.04`,
//!     `gcr.io/proj/img@sha256:...`, `library/ubuntu:22.04`, digest-only,
//!     uppercase tag, whitespace-padded), proven by the ABSENCE of any
//!     validation-rejection message (host-independent: a valid name then fails,
//!     if at all, only on docker-binary/export, never on validation),
//!   * concrete reject verdicts (`Ubuntu`, short/long/wrong-algo digests,
//!     registry-with-port) each yielding EXACTLY ONE error carrying
//!     `invalid docker image '<name>'`,
//!   * unsafe-character rejects (empty, leading `-`, interior control byte)
//!     carrying `docker image contains unsafe characters`,
//!   * the 64-hex-digest boundary (63 reject / 64 accept / 65 reject),
//!   * the `SourceError::Other` wrapper (`failed to read source: … Fix: …`).
//!
//! Distinct from `regression_dockerfile_parse.rs` (image-config chunk builders),
//! `regression_docker_layer_classify.rs` (layer-blob digest labels), and
//! `docker_oci_classification.rs` (media-type index-vs-manifest verdicts): none
//! of those exercise the image-reference admission gate on the public
//! `DockerImageSource` entry point.

#![cfg(feature = "docker")]

use keyhog_core::Source;
use keyhog_sources::DockerImageSource;

/// Every error message `DockerImageSource::chunks()` yields for `image`.
///
/// A rejected reference short-circuits inside `collect_docker_chunks` before any
/// docker binary work, so the iterator is `std::iter::once(Err(_))`: exactly
/// one element. A valid reference proceeds to docker resolution/export, so it may
/// yield zero errors (image scanned) or a non-validation docker error.
fn errors_for(image: &str) -> Vec<String> {
    // Bind the owner so the `'_`-borrowing iterator does not outlive a temporary.
    let source = DockerImageSource::new(image);
    source
        .chunks()
        .filter_map(|row| row.err())
        .map(|error| error.to_string())
        .collect()
}

/// Whether `image` was rejected by the *validator* (as opposed to any downstream
/// docker-binary/export failure). True iff some yielded error carries one of the
/// two fixed validation strings.
fn rejected_as_validation(image: &str) -> bool {
    errors_for(image).iter().any(|message| {
        message.contains("invalid docker image")
            || message.contains("docker image contains unsafe characters")
    })
}

/// A concrete, all-lowercase 64-hex sha256 body (the exact digest length the
/// validator's `@sha256:[a-f0-9]{64}` clause admits).
fn hex64() -> String {
    "a".repeat(64)
}

// ---------------------------------------------------------------------------
// accept verdicts (host-independent: a valid ref is NEVER a validation error)
// ---------------------------------------------------------------------------

#[test]
fn bare_repo_reference_is_admitted() {
    assert_eq!(
        rejected_as_validation("ubuntu"),
        false,
        "`ubuntu` is a valid bare repository reference and must pass validation"
    );
}

#[test]
fn repo_with_dotted_tag_is_admitted() {
    // `ubuntu:22.04`: repo `ubuntu`, tag `:22.04` (`[\w]` then `[\w.\-]*`).
    assert_eq!(rejected_as_validation("ubuntu:22.04"), false);
}

#[test]
fn latest_tag_is_admitted() {
    assert_eq!(rejected_as_validation("ubuntu:latest"), false);
}

#[test]
fn namespaced_repo_with_tag_is_admitted() {
    // `library/ubuntu:22.04`: one path segment + repo + tag.
    assert_eq!(rejected_as_validation("library/ubuntu:22.04"), false);
}

#[test]
fn registry_repo_and_digest_is_admitted() {
    // `gcr.io/proj/img@sha256:<64 hex>`: dotted registry host as a path segment,
    // nested namespace, digest-pinned (a canonical fully-qualified reference).
    let reference = format!("gcr.io/proj/img@sha256:{}", hex64());
    assert_eq!(
        rejected_as_validation(&reference),
        false,
        "fully-qualified registry/repo@digest reference must pass validation"
    );
}

#[test]
fn digest_only_reference_without_tag_is_admitted() {
    let reference = format!("ubuntu@sha256:{}", hex64());
    assert_eq!(rejected_as_validation(&reference), false);
}

#[test]
fn uppercase_tag_is_admitted() {
    // The tag clause is `[\w][\w.\-]{0,127}`, so uppercase tag chars are allowed
    // even though the repository clause (`[a-z0-9]`) forbids them.
    assert_eq!(rejected_as_validation("ubuntu:LATEST"), false);
}

#[test]
fn surrounding_whitespace_is_trimmed_then_admitted() {
    // `validate_image_name` trims before matching, so padding does not reject.
    assert_eq!(rejected_as_validation("  ubuntu:22.04  "), false);
}

// ---------------------------------------------------------------------------
// reject verdicts via the regex ("invalid docker image '<name>'")
// ---------------------------------------------------------------------------

#[test]
fn uppercase_repository_is_rejected_with_name_echoed() {
    // Repository clause is `[a-z0-9]`; `U` fails. Reference is not empty, not
    // dash-led, and control-free, so it reaches the regex and is rejected there.
    let errors = errors_for("Ubuntu");
    assert_eq!(
        errors.len(),
        1,
        "a validation reject short-circuits to exactly one error, got {}",
        errors.len()
    );
    assert!(
        errors[0].contains("invalid docker image 'Ubuntu'"),
        "uppercase repo must be rejected with the name echoed, got: {}",
        errors[0]
    );
}

#[test]
fn registry_with_port_is_rejected() {
    // `localhost:5000/img`: the `:` port separator only the *tag* clause allows,
    // but a `/` path segment follows it (no regex path matches).
    let errors = errors_for("localhost:5000/img");
    assert_eq!(errors.len(), 1, "single validation error expected");
    assert!(
        errors[0].contains("invalid docker image 'localhost:5000/img'"),
        "registry-with-port must be rejected, got: {}",
        errors[0]
    );
}

#[test]
fn short_digest_is_rejected() {
    // `@sha256:` requires exactly 64 hex; `abc` (3) fails the digest clause and
    // leaves an unmatched suffix.
    let errors = errors_for("ubuntu@sha256:abc");
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("invalid docker image 'ubuntu@sha256:abc'"),
        "short digest must be rejected, got: {}",
        errors[0]
    );
}

#[test]
fn non_sha256_digest_algorithm_is_rejected() {
    // Only `@sha256:` is admitted; a 40-hex `@sha1:` body is not.
    let reference = format!("ubuntu@sha1:{}", "a".repeat(40));
    let errors = errors_for(&reference);
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("invalid docker image 'ubuntu@sha1:"),
        "non-sha256 digest algorithm must be rejected, got: {}",
        errors[0]
    );
}

// ---------------------------------------------------------------------------
// reject verdicts via the unsafe-character prefilter
// ---------------------------------------------------------------------------

#[test]
fn empty_reference_is_rejected_as_unsafe() {
    // Trimmed-empty trips the `is_empty()` guard before the regex.
    let errors = errors_for("   ");
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("docker image contains unsafe characters"),
        "empty/whitespace-only reference must be an unsafe-character reject, got: {}",
        errors[0]
    );
}

#[test]
fn leading_dash_reference_is_rejected_as_unsafe() {
    // A leading `-` would be parsed as a `docker image save` flag; rejected up
    // front as unsafe rather than as a regex mismatch.
    let errors = errors_for("-rm");
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("docker image contains unsafe characters"),
        "leading-dash reference must be an unsafe-character reject, got: {}",
        errors[0]
    );
}

#[test]
fn interior_control_byte_is_rejected_as_unsafe() {
    // A non-whitespace control byte (bell, U+0007) survives trimming and trips
    // the `char::is_control` guard.
    let errors = errors_for("ubuntu\u{0007}latest");
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains("docker image contains unsafe characters"),
        "interior control byte must be an unsafe-character reject, got: {}",
        errors[0]
    );
}

// ---------------------------------------------------------------------------
// boundary: the 64-hex digest length
// ---------------------------------------------------------------------------

#[test]
fn digest_length_boundary_63_reject_64_accept_65_reject() {
    let too_short = format!("ubuntu@sha256:{}", "a".repeat(63));
    let exact = format!("ubuntu@sha256:{}", "a".repeat(64));
    let too_long = format!("ubuntu@sha256:{}", "a".repeat(65));

    assert_eq!(
        rejected_as_validation(&too_short),
        true,
        "63-hex digest is below the exact-64 requirement and must be rejected"
    );
    assert_eq!(
        rejected_as_validation(&exact),
        false,
        "exactly-64-hex digest must be admitted"
    );
    assert_eq!(
        rejected_as_validation(&too_long),
        true,
        "65-hex digest exceeds the exact-64 requirement and must be rejected"
    );
}

// ---------------------------------------------------------------------------
// error wrapping contract
// ---------------------------------------------------------------------------

#[test]
fn validation_error_is_wrapped_with_read_source_and_fix_advice() {
    // `SourceError::Other` Displays as `failed to read source: {inner}. Fix: …`,
    // so the inner validation reason is embedded, not the whole string.
    let errors = errors_for("Ubuntu");
    assert_eq!(errors.len(), 1);
    let message = &errors[0];
    assert!(
        message.starts_with("failed to read source:"),
        "error must carry the SourceError::Other wrapper prefix, got: {message}"
    );
    assert!(
        message.contains("Fix:"),
        "error must carry actionable Fix advice, got: {message}"
    );
    assert!(
        message.contains("invalid docker image 'Ubuntu'"),
        "the inner validation reason must survive wrapping, got: {message}"
    );
}
