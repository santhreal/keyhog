#[test]
fn args_maintenance_surfaces_have_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");
    let maintenance = std::fs::read_to_string(root.join("src/args/maintenance.rs"))
        .expect("args/maintenance.rs readable");

    assert!(
        args.contains("mod maintenance;")
            && args.contains(
                "pub use maintenance::{\n    BackendArgs, CompletionArgs, DoctorArgs, RepairArgs, UninstallArgs, UpdateArgs,"
            ),
        "args.rs must re-export maintenance command args from the maintenance module"
    );

    for owned in [
        "pub struct CompletionArgs",
        "pub struct BackendArgs",
        "pub struct DoctorArgs",
        "pub struct UpdateArgs",
        "pub struct RepairArgs",
        "pub struct UninstallArgs",
    ] {
        assert!(
            maintenance.contains(owned),
            "args/maintenance.rs must own `{owned}`"
        );
        assert!(
            !args.contains(owned),
            "args.rs must not re-own `{owned}` after the maintenance split"
        );
    }
}

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
