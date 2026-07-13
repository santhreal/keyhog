use clap::{CommandFactory, Parser};
use keyhog::args::{parse_space_bytes, Cli, Command};
use std::fs;
use std::path::PathBuf;

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn parse_space_bytes_resolves_gib_suffix_exactly() {
    assert_eq!(parse_space_bytes("50G"), Ok(50 * GIB));
    assert_eq!(parse_space_bytes("1T"), Ok(1024 * GIB));
    assert_eq!(parse_space_bytes("500M"), Ok(500 * 1024 * 1024));
}

#[test]
fn parse_space_bytes_handles_fractional() {
    assert_eq!(parse_space_bytes("1.5G"), Ok(GIB + GIB / 2));
}

#[test]
fn parse_space_bytes_rejects_bare_number() {
    assert!(
        parse_space_bytes("50").is_err(),
        "unitless input must not silently mean bytes"
    );
}

#[test]
fn parse_space_bytes_rejects_unknown_suffix() {
    assert!(parse_space_bytes("5Z").is_err());
}

#[test]
fn parse_space_bytes_empty_is_zero() {
    assert_eq!(parse_space_bytes(""), Ok(0));
}

#[test]
fn scan_system_space_flag_parses_through_clap() {
    let cli = Cli::parse_from(["keyhog", "scan-system", "--space", "2G"]);
    match cli.command {
        Some(Command::ScanSystem(args)) => assert_eq!(args.space, 2 * GIB),
        other => panic!(
            "expected ScanSystem command, got something else: {}",
            other.is_some()
        ),
    }
}

#[test]
fn scan_system_space_default_is_50_gib() {
    let cli = Cli::parse_from(["keyhog", "scan-system"]);
    match cli.command {
        Some(Command::ScanSystem(args)) => assert_eq!(args.space, 50 * GIB),
        _ => panic!("expected ScanSystem command"),
    }
}

#[test]
fn scan_system_rejects_unitless_space() {
    let err = Cli::try_parse_from(["keyhog", "scan-system", "--space", "50"]);
    assert!(
        err.is_err(),
        "unitless --space 50 must be rejected by the value_parser"
    );
}

#[test]
fn cli_definition_is_internally_consistent() {
    Cli::command().debug_assert();
}

#[test]
fn every_visible_long_flag_is_in_the_cli_reference() {
    let docs = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/src/reference/cli.md"),
    )
    .expect("read canonical CLI reference");
    let mut pending = vec![("keyhog".to_string(), Cli::command())];
    let mut missing = Vec::new();
    while let Some((path, command)) = pending.pop() {
        missing.extend(
            command
                .get_arguments()
                .filter(|arg| !arg.is_hide_set())
                .filter_map(|arg| arg.get_long())
                .filter(|long| !docs.contains(&format!("--{long}")))
                .map(|long| format!("{path} --{long}")),
        );
        pending.extend(command.get_subcommands().map(|subcommand| {
            (
                format!("{path} {}", subcommand.get_name()),
                subcommand.clone(),
            )
        }));
    }
    missing.sort();
    assert!(
        missing.is_empty(),
        "docs/src/reference/cli.md is missing visible long flags: {missing:?}"
    );
}
