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
