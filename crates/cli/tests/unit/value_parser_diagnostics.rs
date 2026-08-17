use super::value_enum_expected;
use clap::ValueEnum;
use std::collections::HashSet;

fn assert_expected_lists_every_canonical_value_once<T: ValueEnum>() {
    let diagnostic = value_enum_expected::<T>();
    let listed: Vec<_> = match diagnostic.strip_prefix("expected one of ") {
        Some(values) => values.split(", ").collect(),
        None => panic!("config enum diagnostic prefix is missing"),
    };
    let canonical: Vec<_> = T::value_variants()
        .iter()
        .map(|variant| match variant.to_possible_value() {
            Some(possible) => possible.get_name().to_owned(),
            None => panic!("config enum variant must have a clap spelling"),
        })
        .collect();
    let unique: HashSet<_> = listed.iter().copied().collect();

    assert_eq!(listed, canonical);
    assert_eq!(
        unique.len(),
        listed.len(),
        "accepted-value diagnostic contains duplicates: {diagnostic}"
    );
}

#[test]
fn config_enum_diagnostics_cover_every_canonical_value_uniquely() {
    assert_expected_lists_every_canonical_value_once::<crate::args::SeverityFilter>();
    assert_expected_lists_every_canonical_value_once::<crate::args::OutputFormat>();
    assert_expected_lists_every_canonical_value_once::<crate::args::CliDedupScope>();
}

#[test]
fn parse_decode_size_limit_rejects_empty_and_sub_4b() {
    use super::parse_decode_size_limit;
    assert!(parse_decode_size_limit("").is_err());
    assert!(parse_decode_size_limit("   ").is_err());
    assert!(parse_decode_size_limit("0B").is_err());
    assert!(parse_decode_size_limit("1B").is_err());
    assert!(parse_decode_size_limit("3B").is_err());

    assert_eq!(parse_decode_size_limit("4B").unwrap(), 4);
    assert_eq!(parse_decode_size_limit("512KB").unwrap(), 512 * 1024);
    assert_eq!(parse_decode_size_limit("1MB").unwrap(), 1024 * 1024);
}
