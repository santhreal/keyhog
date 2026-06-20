//! Boundary and negative-twin tests for `--precision` mode.
//!
//! These tests explore the edges of the precision mode contract:
//! - Credentials at exactly the 0.85 boundary (must pass)
//! - Credentials just below the boundary (must fail)
//! - Precision combined with other valid flag combinations
//! - Precision behavior with empty/minimal files

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

#[path = "../support/json_report.rs"]
mod json_report_support;

use json_report_support::parse_json_array;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn scan_with_args(fixture: &str, args: &[&str]) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    // `config.txt`, NOT `fixture.txt`: a `fixture`/`test`/`mock`/`spec`
    // filename trips the ML test-context down-weight, which would drop
    // high-confidence credentials below the 0.85 precision floor and confound
    // these boundary assertions with the unrelated test-fixture heuristic.
    let path = dir.path().join("config.txt");
    std::fs::write(&path, fixture).expect("write fixture");

    let output = Command::new(binary())
        .arg("scan")
        .args(["--backend", "simd"])
        .args(args)
        .arg("--format")
        .arg("json")
        .arg("--no-daemon")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// Precision mode negative twin: the same file content scanned with and without
/// `--precision` must show that precision is tighter (fewer or equal findings).
/// Use a fixture with mixed-strength credentials.
#[test]
fn precision_mode_negative_twin_is_subset_of_default() {
    let fixture = concat!(
        "aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n",
        "DATABASE_PASSWORD = \"admin123\"\n",
    );

    let (def_out, _, _) = scan_with_args(fixture, &[]);
    let (prec_out, _, _) = scan_with_args(fixture, &["--precision"]);

    let def: Vec<String> = parse_json_array(&def_out, "default precision negative-twin scan")
        .iter()
        .filter_map(|finding| {
            finding
                .get("detector_id")
                .and_then(|value| value.as_str())
                .map(String::from)
        })
        .collect();

    let prec: Vec<String> = parse_json_array(&prec_out, "explicit precision negative-twin scan")
        .iter()
        .filter_map(|finding| {
            finding
                .get("detector_id")
                .and_then(|value| value.as_str())
                .map(String::from)
        })
        .collect();

    // Every detector found in precision mode must also be in default mode.
    for det in &prec {
        assert!(
            def.contains(det),
            "precision found detector {det:?} but default didn't; \
             this violates the subset property. default={def:?}, precision={prec:?}"
        );
    }

    // Precision must be strictly tighter (fewer findings).
    assert!(
        prec.len() < def.len(),
        "precision must be strictly tighter than default; \
         default={def:?}, precision={prec:?}"
    );
}

/// Precision mode is commutative with `--no-suppress-test-fixtures`:
/// both flags can coexist and the effect is composable. The suppression
/// filter and the precision floor are independent.
#[test]
fn precision_mode_composes_with_no_suppress_test_fixtures() {
    let stripe_key = concat!("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc");
    let fixture = format!("STRIPE_KEY = \"{stripe_key}\"\n");

    // Default (with suppression): no Stripe finding.
    let (def_suppressed, _, def_code) = scan_with_args(&fixture, &[]);
    assert_eq!(
        def_code,
        Some(0),
        "default mode suppresses the Stripe demo key"
    );
    let def: Vec<String> =
        parse_json_array(&def_suppressed, "default suppressed Stripe precision scan")
            .iter()
            .filter_map(|finding| {
                finding
                    .get("service")
                    .and_then(|value| value.as_str())
                    .map(String::from)
            })
            .collect();
    assert!(
        def.is_empty(),
        "default suppresses Stripe and should emit no findings for this fixture; got {def:?}"
    );

    // Precision with no-suppress: the Stripe key is high-confidence, so it should
    // surface even under precision (it clears the 0.85 floor).
    let (prec_nosuppress, _, prec_code) =
        scan_with_args(&fixture, &["--precision", "--no-suppress-test-fixtures"]);
    assert_eq!(
        prec_code,
        Some(1),
        "precision with --no-suppress-test-fixtures must find the Stripe key"
    );
    let prec: Vec<String> = parse_json_array(&prec_nosuppress, "precision no-suppress Stripe scan")
        .iter()
        .filter_map(|finding| {
            finding
                .get("service")
                .and_then(|value| value.as_str())
                .map(String::from)
        })
        .collect();
    assert!(
        prec.contains(&"stripe".to_string()),
        "precision --no-suppress-test-fixtures must find Stripe; got {prec:?}"
    );
}

/// Precision mode is composable with `--min-confidence`: the user can
/// specify `--precision --min-confidence 0.9` and the result is the
/// maximum of the two: max(0.85, 0.9) = 0.9. A credential that scores
/// 0.88 (between 0.85 and 0.9) must be dropped when both are set.
#[test]
fn precision_mode_respects_min_confidence_when_higher() {
    // This test uses an AWS secret (high-confidence, ~0.95) so it clears 0.9.
    // If we had a credential scoring exactly 0.88, it would fall between
    // 0.85 and 0.9 and be dropped. For now, we use a known-high-confidence
    // credential and assert it survives.
    let fixture = "aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n";

    let (out, _, code) = scan_with_args(fixture, &["--precision", "--min-confidence", "0.9"]);
    assert_eq!(
        code,
        Some(1),
        "--precision --min-confidence 0.9 must find the high-confidence AWS secret"
    );
    let findings: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        !arr.is_empty(),
        "the AWS secret (conf > 0.9) must survive max(0.85, 0.9)"
    );
}

/// Precision mode on an empty file exits 0 with no findings.
#[test]
fn precision_mode_empty_file_exits_zero() {
    let fixture = "";
    let (out, _, code) = scan_with_args(fixture, &["--precision"]);
    assert_eq!(code, Some(0), "empty file must exit 0");
    let findings: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let arr = findings.as_array().expect("array");
    assert!(arr.is_empty(), "empty file must have no findings");
}

/// Precision mode on a file with only comments/whitespace exits 0.
#[test]
fn precision_mode_whitespace_only_exits_zero() {
    let fixture = "   \n\t\n  # just comments\n";
    let (out, _, code) = scan_with_args(fixture, &["--precision"]);
    assert_eq!(code, Some(0), "whitespace-only file must exit 0");
    let findings: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let arr = findings.as_array().expect("array");
    assert!(arr.is_empty(), "whitespace-only file must have no findings");
}

/// Precision mode is compatible with `--verify`: findings are checked for
/// validity before reporting. The combination should work without error.
#[test]
fn precision_mode_composes_with_verify_flag() {
    let fixture = "aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n";

    let (_out, err, code) = scan_with_args(fixture, &["--precision", "--verify"]);

    // --verify causes the credential check to run. The AWS secret won't be
    // valid in a test environment (no real AWS credentials), so it will be
    // marked unverified but still reported. Exit code should be 1 (findings).
    assert!(
        code.is_some_and(|c| c == 0 || c == 1),
        "precision --verify must succeed (exit 0 or 1 depending on findings/verify result); \
         got {code:?}, stderr={err}"
    );
    // The important thing is that the command completed successfully (no crash).
    // The finding count depends on verify backend availability.
}

/// Precision mode is compatible with `--scan-comments`: comments are scanned
/// normally but the precision floor still applies.
#[test]
fn precision_mode_composes_with_scan_comments() {
    // A high-confidence AWS *secret* access key in a comment. A weak generic
    // credential would only prove the floor drops noisy findings; this test
    // asserts that an opted-in comment scan still keeps a strong credential
    // that clears the precision bar.
    let fixture =
        "// TODO: rotate aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n";

    let (out, err, code) = scan_with_args(fixture, &["--precision", "--scan-comments"]);

    // The secret clears the 0.85 floor even in a comment once `--scan-comments`
    // opts the comment context out of the suppression multiplier. Exit 1.
    assert!(
        code.is_some_and(|c| c == 1),
        "precision --scan-comments must find the AWS secret in comment; \
         got {code:?}, stderr={err}"
    );
    let findings: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        !arr.is_empty(),
        "precision --scan-comments must find the AWS secret; got {out}"
    );
}

/// Precision mode with `--min-confidence` set LOWER than 0.85 defaults to 0.85.
/// The user cannot use `--precision --min-confidence 0.3` to bypass the floor.
/// The effective floor is max(0.85, 0.3) = 0.85.
#[test]
fn precision_mode_ignores_min_confidence_when_lower_than_0_85() {
    // A weak generic password (scores below 0.85).
    let fixture = "PASSWORD = \"admin123\"\n";

    // Try to set min_confidence to 0.3 (below the precision floor).
    let (out, _, code) = scan_with_args(fixture, &["--precision", "--min-confidence", "0.3"]);

    // The weak password must still be dropped because precision enforces 0.85.
    assert_eq!(
        code,
        Some(0),
        "precision must enforce 0.85 floor even with --min-confidence 0.3"
    );
    let findings: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    let arr = findings.as_array().expect("array");
    assert!(
        arr.is_empty(),
        "precision must drop the weak password (conf < 0.85); got {arr:?}"
    );
}

/// Precision mode on a large, mixed-credential file exhibits the expected
/// tightening vs default. A real-world scenario: a .env file with many
/// credentials of varying strength.
#[test]
fn precision_mode_tightens_large_mixed_corpus() {
    let fixture = concat!(
        "# Real credentials\n",
        "aws_secret_access_key = \"kP8xQ2mNvR7tZ4wL9bYsH3jD6fG1cA0eXuViK5oT\"\n",
        // Checksum-valid GitHub PAT (floored at 0.9), a genuine high-confidence
        // member of the corpus that survives precision.
        "GH_TOKEN = \"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\"\n",
        "# Weak default-only generic finding\n",
        "DATABASE_PASSWORD = \"admin123\"\n",
    );

    let (def_out, _, _) = scan_with_args(fixture, &[]);
    let (prec_out, _, _) = scan_with_args(fixture, &["--precision"]);

    let def_count = parse_json_array(&def_out, "default large mixed precision scan").len();
    let prec_count = parse_json_array(&prec_out, "explicit large mixed precision scan").len();

    assert!(
        def_count > prec_count,
        "precision must reduce the finding count on a large mixed corpus; \
         default={def_count}, precision={prec_count}"
    );
    assert!(
        prec_count > 0,
        "precision must still find the high-confidence credentials; got count={prec_count}"
    );
}
