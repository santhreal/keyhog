//! Regression contract for the `ScanArgs` field shape.
//!
//! A prior `ScanArgs` refactor moved the verifier-only timeout/concurrency flags
//! behind `#[cfg(feature = "verify")]`, but the `all_tests` aggregator (built
//! for the `ci` profile, which omits `verify`) still referenced `args.timeout`
//! / `args.verify_concurrency` unconditionally, so it failed to compile with four
//! `no field ... on ScanArgs` errors. These tests pin the CURRENT shape and
//! parsing contract of `ScanArgs` so a future rename/regate is caught with a
//! concrete assertion instead of a stale-field compile break.
//!
//! Every verifier-only assertion is `#[cfg(feature = "verify")]`-gated exactly
//! like the fields themselves, so this file compiles under both the full
//! desktop profile and the lean `ci`/`no-verify` profile.

use clap::error::ErrorKind;
use keyhog::args::{CliDedupScope, Command, OutputFormat, ScanArgs};
use std::path::PathBuf;

/// Parse `keyhog scan <extra...>` through the production parse path and return
/// the resolved `ScanArgs`. Panics if parsing fails or the subcommand is not
/// `scan` — the positive-path helper.
fn scan_args(extra: &[&str]) -> ScanArgs {
    let mut argv: Vec<String> = vec!["keyhog".to_string(), "scan".to_string()];
    argv.extend(extra.iter().copied().map(String::from));
    let cli = keyhog::args::try_parse_from(argv).expect("scan args must parse");
    match cli.command {
        Some(Command::Scan(args)) => *args,
        other => panic!("expected Command::Scan, got {}", other.is_some()),
    }
}

/// Parse attempt that is expected to fail; returns the `clap::Error` so tests
/// can assert the exact `ErrorKind` and message — the negative-path helper.
fn scan_parse_error(extra: &[&str]) -> clap::Error {
    let mut argv: Vec<String> = vec!["keyhog".to_string(), "scan".to_string()];
    argv.extend(extra.iter().copied().map(String::from));
    // `expect_err` would require `Cli: Debug` (to print the unexpected Ok); the
    // top-level clap struct does not derive it, so match instead.
    match keyhog::args::try_parse_from(argv) {
        Ok(_) => panic!("scan args must be rejected: {extra:?}"),
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// Defaults (present in every feature profile)
// ---------------------------------------------------------------------------

#[test]
fn default_detectors_dir_is_literal_detectors() {
    let args = scan_args(&[]);
    assert_eq!(args.detectors, PathBuf::from("detectors"));
}

#[test]
fn default_output_format_is_text() {
    let args = scan_args(&[]);
    assert_eq!(args.format, OutputFormat::Text);
}

#[test]
fn default_dedup_scope_is_credential() {
    let args = scan_args(&[]);
    assert_eq!(args.dedup, CliDedupScope::Credential);
}

#[test]
fn optional_tuning_fields_default_to_none() {
    let args = scan_args(&[]);
    assert_eq!(args.ml_threshold, None);
    assert_eq!(args.min_confidence, None);
    assert_eq!(args.threads, None);
    assert_eq!(args.max_file_size, None);
    assert_eq!(args.min_secret_len, None);
    assert_eq!(args.decode_depth, None);
}

// ---------------------------------------------------------------------------
// Enum flag parsing
// ---------------------------------------------------------------------------

#[test]
fn format_flag_parses_json_and_sarif() {
    assert_eq!(scan_args(&["--format", "json"]).format, OutputFormat::Json);
    assert_eq!(
        scan_args(&["--format", "sarif"]).format,
        OutputFormat::Sarif
    );
    assert_eq!(
        scan_args(&["--format", "jsonl"]).format,
        OutputFormat::Jsonl
    );
}

#[test]
fn format_flag_rejects_unknown_variant() {
    let err = scan_parse_error(&["--format", "yaml"]);
    assert_eq!(err.kind(), ErrorKind::InvalidValue);
}

#[test]
fn dedup_flag_parses_file_and_none() {
    assert_eq!(scan_args(&["--dedup", "file"]).dedup, CliDedupScope::File);
    assert_eq!(scan_args(&["--dedup", "none"]).dedup, CliDedupScope::None);
    assert_eq!(
        scan_args(&["--dedup", "credential"]).dedup,
        CliDedupScope::Credential
    );
}

// ---------------------------------------------------------------------------
// Numeric value-parser bounds (present in every feature profile)
// ---------------------------------------------------------------------------

#[test]
fn min_confidence_in_range_parses_exact() {
    assert_eq!(
        scan_args(&["--min-confidence", "0.85"]).min_confidence,
        Some(0.85)
    );
    assert_eq!(
        scan_args(&["--min-confidence", "0.0"]).min_confidence,
        Some(0.0)
    );
    assert_eq!(
        scan_args(&["--min-confidence", "1.0"]).min_confidence,
        Some(1.0)
    );
}

#[test]
fn min_confidence_out_of_range_rejected() {
    let err = scan_parse_error(&["--min-confidence", "1.5"]);
    assert_eq!(err.kind(), ErrorKind::ValueValidation);
    assert!(
        err.to_string().contains("must be between 0.0 and 1.0"),
        "message should name the range, got: {err}"
    );
}

#[test]
fn ml_threshold_nan_and_out_of_range_rejected_but_valid_accepted() {
    assert_eq!(
        scan_args(&["--ml-threshold", "0.5"]).ml_threshold,
        Some(0.5)
    );

    let nan = scan_parse_error(&["--ml-threshold", "NaN"]);
    assert_eq!(nan.kind(), ErrorKind::ValueValidation);
    assert!(
        nan.to_string().contains("finite"),
        "NaN rejection should mention finite, got: {nan}"
    );

    let hi = scan_parse_error(&["--ml-threshold", "2.0"]);
    assert_eq!(hi.kind(), ErrorKind::ValueValidation);
}

#[test]
fn decode_depth_zero_rejected_three_accepted() {
    assert_eq!(scan_args(&["--decode-depth", "3"]).decode_depth, Some(3));
    let err = scan_parse_error(&["--decode-depth", "0"]);
    assert_eq!(err.kind(), ErrorKind::ValueValidation);
    assert!(
        err.to_string().contains("decode depth must be between 1"),
        "got: {err}"
    );
}

#[test]
fn min_secret_len_zero_rejected_sixteen_accepted() {
    assert_eq!(
        scan_args(&["--min-secret-len", "16"]).min_secret_len,
        Some(16)
    );
    let err = scan_parse_error(&["--min-secret-len", "0"]);
    assert_eq!(err.kind(), ErrorKind::ValueValidation);
    assert!(err.to_string().contains(">= 1"), "got: {err}");
}

#[test]
fn threads_zero_rejected_positive_accepted() {
    assert_eq!(scan_args(&["--threads", "4"]).threads, Some(4));
    let err = scan_parse_error(&["--threads", "0"]);
    assert_eq!(err.kind(), ErrorKind::ValueValidation);
    assert!(
        err.to_string().contains("--threads must be >= 1"),
        "got: {err}"
    );
}

#[test]
fn unknown_flag_is_rejected_as_unknown_argument() {
    let err = scan_parse_error(&["--definitely-not-a-flag", "x"]);
    assert_eq!(err.kind(), ErrorKind::UnknownArgument);
}

// ---------------------------------------------------------------------------
// Verifier-only fields (only exist under the `verify` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "verify")]
#[test]
fn default_verify_timeout_and_rate_are_none() {
    let args = scan_args(&[]);
    assert_eq!(args.timeout, None);
    assert_eq!(args.verify_concurrency, None);
}

#[cfg(feature = "verify")]
#[test]
fn verify_rate_default_is_five_point_zero() {
    let args = scan_args(&[]);
    assert!(
        (args.verify_rate - 5.0).abs() < f64::EPSILON,
        "default --verify-rate must be 5.0, got {}",
        args.verify_rate
    );
}

#[cfg(feature = "verify")]
#[test]
fn oob_timeout_and_server_defaults() {
    let args = scan_args(&[]);
    assert_eq!(args.oob_timeout, 30);
    assert_eq!(args.oob_server, "oast.fun");
}

#[cfg(feature = "verify")]
#[test]
fn timeout_and_rate_flags_parse_exact_values() {
    let args = scan_args(&["--timeout", "42", "--verify-concurrency", "7"]);
    assert_eq!(args.timeout, Some(42));
    assert_eq!(args.verify_concurrency, Some(7));
}

#[cfg(feature = "verify")]
#[test]
fn timeout_non_numeric_value_rejected() {
    let err = scan_parse_error(&["--timeout", "abc"]);
    assert_eq!(err.kind(), ErrorKind::ValueValidation);
}

#[cfg(feature = "verify")]
#[test]
fn zero_verification_concurrency_is_rejected() {
    let err = scan_parse_error(&["--verify-concurrency", "0"]);
    assert_eq!(err.kind(), ErrorKind::ValueValidation);
    assert!(err.to_string().contains("value must be >= 1"));
}

#[cfg(feature = "verify")]
#[test]
fn ambiguous_legacy_rate_flag_is_not_an_alias() {
    let err = scan_parse_error(&["--rate", "7"]);
    assert_eq!(err.kind(), ErrorKind::UnknownArgument);
}

#[cfg(feature = "verify")]
#[test]
fn verify_rate_bounds_rejected_but_valid_accepted() {
    assert!(
        (scan_args(&["--verify-rate", "50"]).verify_rate - 50.0).abs() < f64::EPSILON,
        "in-range --verify-rate 50 must parse to 50.0"
    );

    let zero = scan_parse_error(&["--verify-rate", "0"]);
    assert_eq!(zero.kind(), ErrorKind::ValueValidation);
    assert!(zero.to_string().contains("> 0 rps"), "got: {zero}");

    let over = scan_parse_error(&["--verify-rate", "20000"]);
    assert_eq!(over.kind(), ErrorKind::ValueValidation);
    assert!(over.to_string().contains("10_000 rps"), "got: {over}");
}
