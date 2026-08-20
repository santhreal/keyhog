//! Regression: a real credential inside a minified or vendored bundle must be
//! REACHABLE and, when it is not reported, COUNTED.
//!
//! Before this lane, `looks_like_vendored_minified_path` dropped every finding
//! whose path ended `.min.js` / `.bundle.js` / `.min.css` or sat under
//! `node_modules/`, `site-packages/`, `wp-includes/`, `dist/assets/` and
//! friends. The drop was unconditional, uncounted, and defeated by no flag:
//!
//!   * `keyhog scan app.min.js` read all 1441 bytes and printed `[]`, exit 0.
//!   * `keyhog scan wp/` read `wp-includes/config.php`, reported 105 bytes
//!     scanned, printed `[]`, exit 0, and an EMPTY `coverage_gap_summary`.
//!   * `--no-default-excludes` made the walker read the file and changed
//!     nothing about the report: the flag promised coverage it did not deliver.
//!   * Copying the identical bytes to a path without a vendored segment
//!     reported the credential.
//!
//! Build tooling inlines API keys into frontend bundles, so this was the single
//! class keyhog could not report at all while saying "No secrets detected".
//!
//! Every assertion here pins a concrete exit code, count, or substring against
//! bytes planted in the fixture. The planted value is a live-SHAPED Stripe key
//! that is not on the bundled test-fixture suppression list (the published
//! `sk_live_4eC39...` docs example is, and would prove nothing).

use std::{path::PathBuf, process::Command, process::Stdio};

/// Live-shaped Stripe secret key. Not a real credential and not the Stripe
/// docs example, which the bundled test-fixture list suppresses.
const PLANTED_KEY: &str = "sk_live_51H8xQ2eZvKYlo2CkVvNbHqRt9pXwZmA3dLfGyUcTiOnEsRaBvQwXyZ12";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// One minified-looking line carrying the planted key, padded so the file is
/// bundle-sized rather than a two-token toy.
fn minified_bundle() -> String {
    format!("var a=1,b=2;function q(x){{return x+1}}var STRIPE_KEY=\"{PLANTED_KEY}\";var _pad=\"{}\";\n",
        "abcdefgh".repeat(160))
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn scan(args: &[&str], target: &std::path::Path) -> Run {
    let output = Command::new(binary())
        .args(["scan", "--backend", "cpu", "--daemon=off", "--no-config"])
        .arg(target)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn keyhog");
    Run {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn finding_count(stdout: &str) -> usize {
    let value: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("scan --format json must emit a JSON array");
    value
        .as_array()
        .expect("scan --format json must emit a JSON array")
        .len()
}

/// The bytes ARE read (a `wp-includes/` path is not on the walker's default
/// directory-exclusion list), the detector DOES match, and the finding is then
/// dropped. That drop must be counted and named in the operator summary, with
/// the flag that recovers it. Anything less is a silent miss.
#[test]
fn vendored_path_suppression_is_counted_and_named_in_the_summary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vendored = dir.path().join("wp-includes");
    std::fs::create_dir(&vendored).expect("create wp-includes");
    std::fs::write(
        vendored.join("config.php"),
        format!("<?php $stripe = \"{PLANTED_KEY}\"; ?>\n"),
    )
    .expect("write vendored config");

    let run = scan(&["--format", "json"], dir.path());

    assert_eq!(
        finding_count(&run.stdout),
        0,
        "the vendored-path policy still suppresses by default; stdout={}",
        run.stdout
    );
    assert!(
        run.stderr.contains("credential match(es) were DROPPED"),
        "a suppressed finding must be COUNTED and named, not vanish; stderr={}",
        run.stderr
    );
    assert!(
        run.stderr.contains("1 credential match(es)"),
        "the summary must state how many matches were dropped; stderr={}",
        run.stderr
    );
    assert!(
        run.stderr.contains("--no-default-excludes"),
        "the summary must name the flag that recovers the dropped findings; stderr={}",
        run.stderr
    );
}

/// `--no-default-excludes` must defeat the suppression too. Before this lane it
/// defeated only the walker skip, so the flag reported more bytes scanned and
/// the same zero findings: a false affordance.
#[test]
fn no_default_excludes_reaches_the_credential_in_a_vendored_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vendored = dir.path().join("wp-includes");
    std::fs::create_dir(&vendored).expect("create wp-includes");
    std::fs::write(
        vendored.join("config.php"),
        format!("<?php $stripe = \"{PLANTED_KEY}\"; ?>\n"),
    )
    .expect("write vendored config");

    // `--evidence-policy paranoid` blocks on `review` too. A `.php` body is not
    // a structured-config context, so the recovered finding is `review` tier and
    // the default policy would exit 0 with the finding present: that would pin
    // reachability without pinning a blocking exit.
    let run = scan(
        &[
            "--format",
            "json",
            "--no-default-excludes",
            "--evidence-policy",
            "paranoid",
        ],
        dir.path(),
    );

    assert_eq!(
        finding_count(&run.stdout),
        1,
        "--no-default-excludes must report the credential in a vendored path; stdout={} stderr={}",
        run.stdout,
        run.stderr
    );
    assert_eq!(
        run.code,
        Some(1),
        "a reported finding exits 1; stderr={}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("credential match(es) were DROPPED"),
        "with the suppression disabled nothing is dropped, so no gap row; stderr={}",
        run.stderr
    );
}

/// The `.min.js` basename rule, driven through an explicitly named file so the
/// walker reads it under default policy. This is the exact reported shape:
/// 1441 bytes scanned, zero findings, exit 0.
#[test]
fn minified_bundle_credential_is_reachable_with_no_default_excludes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let bundle = dir.path().join("app.min.js");
    std::fs::write(&bundle, minified_bundle()).expect("write bundle");

    let suppressed = scan(&["--format", "json"], &bundle);
    assert_eq!(
        finding_count(&suppressed.stdout),
        0,
        "default policy still suppresses minified bundles; stdout={}",
        suppressed.stdout
    );
    assert!(
        suppressed
            .stderr
            .contains("credential match(es) were DROPPED"),
        "the default-policy drop must be visible; stderr={}",
        suppressed.stderr
    );

    let reachable = scan(&["--format", "json", "--no-default-excludes"], &bundle);
    assert_eq!(
        finding_count(&reachable.stdout),
        1,
        "an operator must be able to reach a credential in app.min.js; stdout={} stderr={}",
        reachable.stdout,
        reachable.stderr
    );
    assert!(
        reachable.stdout.contains("stripe-secret-key"),
        "the recovered finding must be the planted Stripe key; stdout={}",
        reachable.stdout
    );
}

/// The identical bytes at a non-vendored path are reported under default
/// policy. This is the control: it proves the detector and the fixture are
/// sound, so a zero-finding vendored result is the policy and not a dud key.
#[test]
fn identical_bytes_at_a_plain_path_are_reported_by_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let plain = dir.path().join("app.js");
    std::fs::write(&plain, minified_bundle()).expect("write plain bundle");

    let run = scan(&["--format", "json"], &plain);

    assert_eq!(
        finding_count(&run.stdout),
        1,
        "the control path must report the planted key; stdout={} stderr={}",
        run.stdout,
        run.stderr
    );
}

/// The gap must reach machine consumers, not just the terminal. A category the
/// human summary prints and SARIF omits is a structured false-clean.
#[test]
fn vendored_path_suppression_is_visible_in_the_json_envelope() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vendored = dir.path().join("wp-includes");
    std::fs::create_dir(&vendored).expect("create wp-includes");
    std::fs::write(
        vendored.join("config.php"),
        format!("<?php $stripe = \"{PLANTED_KEY}\"; ?>\n"),
    )
    .expect("write vendored config");

    let run = scan(&["--format", "json-envelope"], dir.path());
    let envelope: serde_json::Value =
        serde_json::from_str(run.stdout.trim()).expect("json-envelope stdout must be JSON");

    let gaps = envelope["coverage_gap_summary"]
        .as_array()
        .expect("a suppressed finding must produce a coverage_gap_summary entry");
    let row = gaps
        .iter()
        .find(|row| {
            row["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("vendored/minified path policy"))
        })
        .unwrap_or_else(|| panic!("no vendored-path gap row in {gaps:?}"));
    assert_eq!(
        row["count"].as_u64(),
        Some(1),
        "the envelope must carry the exact suppressed-finding count; row={row:?}"
    );
}
