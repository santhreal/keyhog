use clap::ValueEnum;
use keyhog::args::{CliDedupScope, OutputFormat, SeverityFilter};
use keyhog::testing::{CliTestApi as _, API};

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

fn assert_roundtrips_every_value<T>(parse: impl Fn(&str) -> Option<T>, enum_name: &str)
where
    T: ValueEnum + Clone + std::fmt::Debug + PartialEq,
{
    for variant in T::value_variants() {
        let canonical = variant
            .to_possible_value()
            .expect("every config enum member must have a clap spelling");
        assert_eq!(
            parse(canonical.get_name()),
            Some(variant.clone()),
            "{enum_name} config parser must roundtrip canonical value {:?}",
            canonical.get_name()
        );
    }
}

#[test]
fn config_enum_parsers_roundtrip_every_cli_value() {
    assert_roundtrips_every_value(|value| API.parse_severity_filter(value), "SeverityFilter");
    assert_roundtrips_every_value(|value| API.parse_output_format(value), "OutputFormat");
    assert_roundtrips_every_value(|value| API.parse_dedup_scope(value), "CliDedupScope");

    assert_eq!(
        API.parse_severity_filter("CLIENT-SAFE"),
        Some(SeverityFilter::ClientSafe)
    );
    assert_eq!(
        API.parse_output_format("JSON-ENVELOPE"),
        Some(OutputFormat::JsonEnvelope)
    );
    assert_eq!(
        API.parse_dedup_scope("CREDENTIAL"),
        Some(CliDedupScope::Credential)
    );

    for variant in SeverityFilter::value_variants() {
        assert_eq!(
            variant
                .to_possible_value()
                .expect("severity clap spelling")
                .get_name_and_aliases()
                .count(),
            1
        );
    }
    for variant in CliDedupScope::value_variants() {
        assert_eq!(
            variant
                .to_possible_value()
                .expect("dedup scope clap spelling")
                .get_name_and_aliases()
                .count(),
            1
        );
    }
}

#[test]
fn parse_output_format_preserves_declared_underscore_aliases_only() {
    for variant in OutputFormat::value_variants() {
        let possible = variant
            .to_possible_value()
            .expect("output format must have clap metadata");
        for alias in possible.get_name_and_aliases().skip(1) {
            assert_eq!(
                API.parse_output_format(alias),
                Some(variant.clone()),
                "declared alias {alias:?} must parse as {variant:?}"
            );
        }
    }
    let aliases: Vec<_> = OutputFormat::value_variants()
        .iter()
        .flat_map(|variant| {
            variant
                .to_possible_value()
                .expect("output format must have clap metadata")
                .get_name_and_aliases()
                .skip(1)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(
        aliases.len(),
        4,
        "every accepted output-format alias needs an explicit compatibility decision"
    );

    for required in [
        "json_envelope",
        "jsonl_envelope",
        "github_annotations",
        "gitlab_sast",
    ] {
        assert!(
            aliases.iter().any(|spelling| spelling == required),
            "required compatibility alias {required:?} must remain enum metadata"
        );
    }

    for invalid in ["json__envelope", "github_annotation", "text_output"] {
        assert!(
            API.parse_output_format(invalid).is_none(),
            "undeclared alias {invalid:?} must be rejected"
        );
    }
}

#[test]
fn config_enum_parsers_reject_unknown_values() {
    assert!(API.parse_severity_filter("urgent").is_none());
    assert!(API.parse_output_format("yaml").is_none());
    assert!(API.parse_dedup_scope("repository").is_none());
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
