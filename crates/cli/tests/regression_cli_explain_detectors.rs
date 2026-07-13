//! Regression e2e: `keyhog explain <id>` across concrete detectors.
//!
//! Drives the REAL shipped binary (`env!("CARGO_BIN_EXE_keyhog")`), no
//! in-process reach into private helpers. Every assertion pins a CONCRETE
//! value read out of the source of truth:
//!   - detector specs in `detectors/{github-classic-pat,aws-access-key,
//!     stripe-secret-key}.toml` (Name / Service / Severity),
//!   - the per-service rotation URLs in `subcommands/explain.rs::rotation_guide`
//!     (github -> github.com docs, aws -> aws docs, stripe -> stripe dashboard
//!     proven DISTINCT, not one shared constant),
//!   - the exit-code contract (`exit_codes::EXIT_USER_ERROR == 2`),
//!   - the `hot-*` SIMD fast-path alias -> canonical registry id resolution.
//!
//! Colours: the child's stdout is a pipe (not a TTY) so `style::for_stdout`
//! yields the PLAIN (empty-ANSI) palette; assertions match plain text. We also
//! export `NO_COLOR=1` as belt-and-suspenders.

use std::process::{Command, Output};

/// Exact per-service rotation URLs baked into `explain.rs::rotation_guide`.
const GITHUB_ROTATION_URL: &str = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens";
const AWS_ROTATION_URL: &str = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey";
const STRIPE_ROTATION_URL: &str = "https://dashboard.stripe.com/apikeys";

/// Run `keyhog explain <arg...>` against the real binary with colour disabled.
fn explain(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keyhog"));
    cmd.arg("explain");
    for a in args {
        cmd.arg(a);
    }
    cmd.env("NO_COLOR", "1");
    cmd.output().expect("spawn keyhog explain")
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// github-classic-pat
// ---------------------------------------------------------------------------

/// Positive: `explain github-classic-pat` exits 0 and prints the EXACT
/// Name / Service / Severity lines from `detectors/github-classic-pat.toml`.
#[test]
fn github_classic_pat_prints_exact_name_service_severity() {
    let out = explain(&["github-classic-pat"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let s = stdout_of(&out);

    assert!(
        s.contains("Name:      GitHub Classic PAT"),
        "expected exact Name line; got:\n{s}"
    );
    assert!(
        s.contains("Service:   github"),
        "expected exact Service line; got:\n{s}"
    );
    assert!(
        s.contains("Severity:  Critical"),
        "expected exact Severity line (Debug of Severity::Critical); got:\n{s}"
    );
}

/// Positive: the header line is the book glyph + the canonical id.
#[test]
fn github_classic_pat_header_is_book_glyph_and_id() {
    let out = explain(&["github-classic-pat"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout_of(&out);
    assert!(
        s.contains("\u{1F4D6} github-classic-pat"),
        "expected book-glyph header with canonical id; got:\n{s}"
    );
}

/// Positive: github rotation guide is the github.com PAT docs URL, under a
/// "Rotation guide for github:" heading.
#[test]
fn github_classic_pat_prints_github_rotation_url() {
    let out = explain(&["github-classic-pat"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout_of(&out);
    assert!(
        s.contains("Rotation guide for github:"),
        "expected github rotation heading; got:\n{s}"
    );
    assert!(
        s.contains(GITHUB_ROTATION_URL),
        "expected exact github rotation URL; got:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// aws-access-key
// ---------------------------------------------------------------------------

/// Positive: `explain aws-access-key` exits 0 with the exact aws spec lines.
#[test]
fn aws_access_key_prints_exact_name_service_severity() {
    let out = explain(&["aws-access-key"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let s = stdout_of(&out);

    assert!(
        s.contains("Name:      AWS Access Key"),
        "expected exact Name line; got:\n{s}"
    );
    assert!(
        s.contains("Service:   aws"),
        "expected exact Service line; got:\n{s}"
    );
    assert!(
        s.contains("Severity:  Critical"),
        "expected Severity::Critical; got:\n{s}"
    );
}

/// Positive: aws rotation guide is the AWS IAM access-key rotation docs URL.
#[test]
fn aws_access_key_prints_aws_rotation_url() {
    let out = explain(&["aws-access-key"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout_of(&out);
    assert!(
        s.contains("Rotation guide for aws:"),
        "expected aws rotation heading; got:\n{s}"
    );
    assert!(
        s.contains(AWS_ROTATION_URL),
        "expected exact aws rotation URL; got:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// stripe-secret-key
// ---------------------------------------------------------------------------

/// Positive: `explain stripe-secret-key` exits 0 with the exact stripe spec.
#[test]
fn stripe_secret_key_prints_exact_name_service_severity() {
    let out = explain(&["stripe-secret-key"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let s = stdout_of(&out);

    assert!(
        s.contains("Name:      Stripe Secret Key"),
        "expected exact Name line; got:\n{s}"
    );
    assert!(
        s.contains("Service:   stripe"),
        "expected exact Service line; got:\n{s}"
    );
    assert!(
        s.contains("Severity:  Critical"),
        "expected Severity::Critical; got:\n{s}"
    );
}

/// Positive: stripe rotation guide is the Stripe dashboard API-keys URL.
#[test]
fn stripe_secret_key_prints_stripe_rotation_url() {
    let out = explain(&["stripe-secret-key"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout_of(&out);
    assert!(
        s.contains("Rotation guide for stripe:"),
        "expected stripe rotation heading; got:\n{s}"
    );
    assert!(
        s.contains(STRIPE_ROTATION_URL),
        "expected exact stripe rotation URL; got:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// The load-bearing invariant: rotation URL is PER-SERVICE, not one shared const
// ---------------------------------------------------------------------------

/// Cross-detector: each detector's rotation URL is its OWN service URL and
/// NOT any of the other two. If `rotation_guide` ever collapsed to a single
/// shared constant, at least one of these mutual-exclusion checks fails.
#[test]
fn rotation_urls_are_per_service_not_a_shared_constant() {
    let gh = stdout_of(&explain(&["github-classic-pat"]));
    let aws = stdout_of(&explain(&["aws-access-key"]));
    let stripe = stdout_of(&explain(&["stripe-secret-key"]));

    // github output: only the github URL.
    assert!(gh.contains(GITHUB_ROTATION_URL), "github missing its URL");
    assert!(
        !gh.contains(AWS_ROTATION_URL),
        "github output leaked the aws URL"
    );
    assert!(
        !gh.contains(STRIPE_ROTATION_URL),
        "github output leaked the stripe URL"
    );

    // aws output: only the aws URL.
    assert!(aws.contains(AWS_ROTATION_URL), "aws missing its URL");
    assert!(
        !aws.contains(GITHUB_ROTATION_URL),
        "aws output leaked the github URL"
    );
    assert!(
        !aws.contains(STRIPE_ROTATION_URL),
        "aws output leaked the stripe URL"
    );

    // stripe output: only the stripe URL.
    assert!(
        stripe.contains(STRIPE_ROTATION_URL),
        "stripe missing its URL"
    );
    assert!(
        !stripe.contains(GITHUB_ROTATION_URL),
        "stripe output leaked the github URL"
    );
    assert!(
        !stripe.contains(AWS_ROTATION_URL),
        "stripe output leaked the aws URL"
    );

    // And the three URLs are genuinely distinct strings.
    assert_ne!(GITHUB_ROTATION_URL, AWS_ROTATION_URL);
    assert_ne!(GITHUB_ROTATION_URL, STRIPE_ROTATION_URL);
    assert_ne!(AWS_ROTATION_URL, STRIPE_ROTATION_URL);
}

/// Positive: every explanation ends with the 4-step canonical remediation
/// block (fixed operator guidance, not per-detector).
#[test]
fn explain_prints_canonical_remediation_steps() {
    let out = explain(&["stripe-secret-key"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout_of(&out);
    assert!(
        s.contains("1. Treat the credential as compromised; assume it has been read."),
        "missing remediation step 1; got:\n{s}"
    );
    assert!(
        s.contains("2. Rotate it at the issuer (see rotation-guide URL above)."),
        "missing remediation step 2; got:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// hot-* SIMD fast-path alias resolution
// ---------------------------------------------------------------------------

/// Positive: a `hot-github_pat` fast-path label resolves to the canonical
/// `github-classic-pat` registry spec, exits 0, and says so on stdout.
#[test]
fn hot_alias_github_resolves_to_canonical_id() {
    let out = explain(&["hot-github_pat"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let s = stdout_of(&out);
    assert!(
        s.contains("'hot-github_pat' is keyhog's SIMD fast-path label; showing the canonical detector 'github-classic-pat'."),
        "expected the hot-alias resolution notice; got:\n{s}"
    );
    // And it actually renders the canonical spec, not just the notice.
    assert!(
        s.contains("Name:      GitHub Classic PAT"),
        "hot alias must render the canonical github spec; got:\n{s}"
    );
    assert!(
        s.contains(GITHUB_ROTATION_URL),
        "hot alias must carry the canonical github rotation URL; got:\n{s}"
    );
}

/// Positive: `hot-aws_key` resolves to `aws-access-key` (distinct mapping).
#[test]
fn hot_alias_aws_resolves_to_canonical_id() {
    let out = explain(&["hot-aws_key"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let s = stdout_of(&out);
    assert!(
        s.contains("showing the canonical detector 'aws-access-key'."),
        "expected aws canonical resolution; got:\n{s}"
    );
    assert!(
        s.contains("Name:      AWS Access Key"),
        "hot alias must render the aws spec; got:\n{s}"
    );
}

/// Boundary: id resolution is ASCII-case-insensitive
/// (`d.id.eq_ignore_ascii_case`). Upper/mixed-case still hits the same spec.
#[test]
fn mixed_case_id_resolves_same_detector() {
    let out = explain(&["GitHub-Classic-PAT"]);
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr_of(&out));
    let s = stdout_of(&out);
    assert!(
        s.contains("Name:      GitHub Classic PAT"),
        "mixed-case id must resolve to the same spec; got:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// Negative twins
// ---------------------------------------------------------------------------

/// Negative: a wholly-unknown id (no substring match anywhere) exits 2 and
/// names the offending id on stderr, pointing at `keyhog detectors`.
#[test]
fn unknown_detector_id_exits_two_and_names_it() {
    let out = explain(&["zzznope-not-a-real-detector"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown id must exit EXIT_USER_ERROR (2); stderr={}",
        stderr_of(&out)
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("no detector with id 'zzznope-not-a-real-detector'"),
        "error must name the bad id; got:\n{err}"
    );
    assert!(
        err.contains("keyhog detectors"),
        "error must point at the list command; got:\n{err}"
    );
}

/// Negative twin: an unknown `hot-*` label whose service prefix DOES match
/// real detectors exits 2 with the fast-path-label message listing related
/// ids (NOT the plain "no detector with id" branch).
#[test]
fn unknown_hot_label_exits_two_with_fastpath_message() {
    let out = explain(&["hot-github_zzz_unmapped"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unmapped hot label must exit 2; stderr={}",
        stderr_of(&out)
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("is a keyhog SIMD fast-path label, not a registry detector id"),
        "expected the fast-path-label branch; got:\n{err}"
    );
    assert!(
        err.contains("github-classic-pat"),
        "related-detector list must surface the github spec; got:\n{err}"
    );
}

/// Negative/boundary: a bare service substring (`github`) is not a detector id
/// but matches several, so it exits 2 with a "Did you mean" suggestion list
/// that includes the classic PAT id.
#[test]
fn ambiguous_substring_exits_two_with_suggestions() {
    let out = explain(&["github"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "bare substring must exit 2; stderr={}",
        stderr_of(&out)
    );
    let err = stderr_of(&out);
    assert!(
        err.contains("no detector with id 'github'. Did you mean:"),
        "expected did-you-mean framing; got:\n{err}"
    );
    assert!(
        err.contains("github-classic-pat"),
        "suggestions must include the classic PAT id; got:\n{err}"
    );
}
