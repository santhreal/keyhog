#[test]
fn maintenance_version_is_normalized_in_the_subcommand_scope() {
    // Why: the root identity flag and maintenance release selector share the
    // `--version` spelling; the subcommand value must not trigger root output.
    let cli = keyhog::args::try_parse_from(["keyhog", "update", "--version", "1.2.3"])
        .expect("parse exact update version");
    assert!(
        !cli.build_version,
        "subcommand version is not root identity"
    );
    let Some(keyhog::args::Command::Update(args)) = cli.command else {
        panic!("update subcommand must remain selected");
    };
    assert_eq!(args.version.as_deref(), Some("v1.2.3"));
}

#[test]
fn maintenance_version_rejects_non_semver_during_parsing() {
    // Why: malformed path/query fragments must never leave clap for the
    // network resolver.
    let error =
        keyhog::args::try_parse_from(["keyhog", "repair", "--version", "v1.2.3/../../latest"])
            .err()
            .expect("reject hostile version");
    let message = error.to_string();
    assert!(
        message.contains("not canonical SemVer") && message.contains("--version v1.2.3"),
        "parse error must include remediation: {message}"
    );
}
