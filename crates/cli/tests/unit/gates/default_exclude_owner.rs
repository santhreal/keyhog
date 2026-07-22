#[test]
fn default_exclude_classification_is_source_owned() {
    let cli_sources =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sources.rs"))
            .expect("CLI sources source readable");
    let source_filter = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sources/src/filesystem/filter.rs"
    ))
    .expect("source filesystem filter readable");
    let default_excludes = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../rules/default_excludes.toml"
    ))
    .expect("default excludes Tier-B data readable");
    let source_extract = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sources/src/filesystem/extract.rs"
    ))
    .expect("source filesystem extract readable");
    let source_reader = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sources/src/filesystem/reader.rs"
    ))
    .expect("source filesystem reader readable");

    assert!(
        !cli_sources.contains("DEFAULT_EXCLUDE_PATTERNS")
            && !cli_sources.contains("\"**/node_modules/**\"")
            && !cli_sources.contains("\"**/vendor/**\""),
        "CLI must not mirror source-owned default exclude patterns"
    );
    assert!(
        source_filter.contains("include_str!(concat!(")
            && source_filter.contains("env!(\"CARGO_MANIFEST_DIR\")")
            && source_filter.contains("\"/rules/default_excludes.toml\"")
            && source_filter.contains("fn parse_default_excludes")
            && source_filter.contains("fn is_default_excluded")
            && !source_filter.contains("const SKIP_DIRS")
            && !source_filter.contains("const SKIP_EXTENSIONS"),
        "filesystem filter must load the Tier-B default-exclude classifier owner without hardcoded policy arrays"
    );
    assert!(
        default_excludes.contains("[default_excludes]")
            && default_excludes.contains("\"node_modules\"")
            && default_excludes.contains("\"package-lock.json\"")
            && default_excludes.contains("prefix = \"tsconfig\""),
        "rules/default_excludes.toml must own directory, filename, and prefix/suffix default-exclude policy"
    );
    assert!(
        source_reader.contains("default_exclude_root: std::path::PathBuf")
            && source_extract.contains("default_exclude_root: &Path")
            && source_extract.contains("strip_prefix(default_exclude_root)")
            && source_extract.contains("SourceSkipEvent::Excluded"),
        "default excludes must classify root-relative paths and record the typed skip event"
    );
}
