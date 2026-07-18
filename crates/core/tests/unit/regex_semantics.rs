use keyhog_core::{CompanionSpec, PatternSpec};

#[test]
fn pattern_separator_semantics_round_trip_without_loader_broadening() {
    let pattern = toml::from_str::<PatternSpec>("regex = 'api[_-]?key'")
        .expect("detector pattern must parse");

    assert_eq!(pattern.regex, "api[_-]?key");
    let compiled = regex::Regex::new(&pattern.regex).expect("authored pattern must compile");
    assert!(compiled.is_match("api_key"));
    assert!(!compiled.is_match("api key"));
    assert!(!compiled.is_match("api__key"));
}

#[test]
fn companion_separator_semantics_round_trip_without_loader_broadening() {
    let companion = toml::from_str::<CompanionSpec>(
        "name = 'account'\nregex = 'account[-]id'\nwithin_lines = 2\n",
    )
    .expect("detector companion must parse");

    assert_eq!(companion.regex, "account[-]id");
    let compiled = regex::Regex::new(&companion.regex).expect("authored companion must compile");
    assert!(compiled.is_match("account-id"));
    assert!(!compiled.is_match("account_id"));
    assert!(!compiled.is_match("account  id"));
}
