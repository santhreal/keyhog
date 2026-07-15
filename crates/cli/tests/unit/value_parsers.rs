use keyhog::testing::{CliTestApi as _, API};

use keyhog::args::OutputFormat;

#[test]
fn parse_min_confidence_accepts_valid_fraction() {
    assert_eq!(API.parse_min_confidence("0.75").unwrap(), 0.75);
}

#[test]
fn parse_min_confidence_rejects_out_of_range() {
    assert!(API.parse_min_confidence("1.5").is_err());
}

#[test]
fn parse_verify_rate_rejects_non_positive() {
    assert!(API.parse_verify_rate("0").is_err());
}

#[test]
fn parse_ml_threshold_rejects_nan() {
    assert!(API.parse_ml_threshold("NaN").is_err());
}

#[test]
fn parse_decode_depth_accepts_positive_integer() {
    assert_eq!(API.parse_decode_depth("3").unwrap(), 3);
}

#[test]
fn parse_min_secret_len_accepts_positive_integer() {
    assert_eq!(API.parse_min_secret_len("16").unwrap(), 16);
}

#[test]
fn parse_min_secret_len_rejects_zero() {
    assert!(API.parse_min_secret_len("0").is_err());
}

#[test]
fn parse_byte_size_parses_suffixes() {
    assert_eq!(API.parse_byte_size("1M").unwrap(), 1024 * 1024);
}

#[test]
fn parse_output_format_accepts_every_cli_format() {
    let cases = [
        ("text", OutputFormat::Text),
        ("json", OutputFormat::Json),
        ("json-envelope", OutputFormat::JsonEnvelope),
        ("jsonl", OutputFormat::Jsonl),
        ("jsonl-envelope", OutputFormat::JsonlEnvelope),
        ("sarif", OutputFormat::Sarif),
        ("csv", OutputFormat::Csv),
        ("github-annotations", OutputFormat::GithubAnnotations),
        ("gitlab-sast", OutputFormat::GitlabSast),
        ("html", OutputFormat::Html),
        ("junit", OutputFormat::Junit),
    ];

    for (input, expected) in cases {
        assert_eq!(
            API.parse_output_format(input),
            Some(expected),
            "config parser must accept format={input:?}"
        );
    }
}

#[test]
fn parse_output_format_rejects_unknown_format() {
    assert!(API.parse_output_format("yaml").is_none());
}

#[test]
fn verify_rate_accepts_typical_values() {
    assert_eq!(API.parse_verify_rate("5").unwrap(), 5.0);
    assert_eq!(API.parse_verify_rate("0.5").unwrap(), 0.5);
    assert_eq!(API.parse_verify_rate("100").unwrap(), 100.0);
    assert_eq!(API.parse_verify_rate("9999.9").unwrap(), 9999.9);
}

#[test]
fn verify_rate_rejects_garbage() {
    assert!(API.parse_verify_rate("abc").is_err());
    assert!(API.parse_verify_rate("").is_err());
    assert!(API.parse_verify_rate("--").is_err());
}

#[test]
fn verify_rate_rejects_non_positive_extended() {
    assert!(API.parse_verify_rate("0").is_err());
    assert!(API.parse_verify_rate("0.0").is_err());
    assert!(API.parse_verify_rate("-1").is_err());
    assert!(API.parse_verify_rate("-0.5").is_err());
}

#[test]
fn verify_rate_rejects_non_finite() {
    assert!(API.parse_verify_rate("nan").is_err());
    assert!(API.parse_verify_rate("NaN").is_err());
    assert!(API.parse_verify_rate("inf").is_err());
    assert!(API.parse_verify_rate("Infinity").is_err());
    assert!(API.parse_verify_rate("-inf").is_err());
}

#[test]
fn verify_rate_rejects_above_sanity_cap() {
    assert!(API.parse_verify_rate("10001").is_err());
    assert!(API.parse_verify_rate("1e6").is_err());
    assert!(API.parse_verify_rate("1e300").is_err());
}

#[test]
fn ml_threshold_accepts_in_range() {
    assert_eq!(API.parse_ml_threshold("0").unwrap(), 0.0);
    assert_eq!(API.parse_ml_threshold("0.5").unwrap(), 0.5);
    assert_eq!(API.parse_ml_threshold("1").unwrap(), 1.0);
}

#[test]
fn ml_threshold_rejects_out_of_range() {
    assert!(API.parse_ml_threshold("-0.001").is_err());
    assert!(API.parse_ml_threshold("1.001").is_err());
    assert!(API.parse_ml_threshold("2").is_err());
    assert!(API.parse_ml_threshold("-1").is_err());
}

#[test]
fn ml_threshold_rejects_non_finite() {
    assert!(API.parse_ml_threshold("nan").is_err());
    assert!(API.parse_ml_threshold("inf").is_err());
    assert!(API.parse_ml_threshold("-inf").is_err());
}

#[test]
fn ml_threshold_rejects_garbage() {
    assert!(API.parse_ml_threshold("").is_err());
    assert!(API.parse_ml_threshold("half").is_err());
}
