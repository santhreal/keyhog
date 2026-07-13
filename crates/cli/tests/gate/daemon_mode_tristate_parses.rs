//! CLI-02 gate: `scan --daemon[=auto|on|off]` is the canonical tri-state, with
//! Every daemon-routing decision reads [`ScanArgs::daemon_mode`], so this gate
//! pins explicit values, the default, and the positional disambiguation that
//! `require_equals` protects.

use clap::Parser;
use keyhog::args::{Cli, Command, DaemonMode};

fn daemon_mode_of(argv: &[&str]) -> DaemonMode {
    let cli = Cli::try_parse_from(argv).expect("args parse");
    match cli.command {
        Some(Command::Scan(args)) => args.daemon_mode(),
        _ => panic!("expected Scan subcommand"),
    }
}

#[test]
fn absent_flag_resolves_to_auto() {
    assert_eq!(daemon_mode_of(&["keyhog", "scan", "."]), DaemonMode::Auto);
}

#[test]
fn explicit_auto_remains_distinguishable_from_the_absent_default() {
    for (argv, expected) in [
        (&["keyhog", "scan", "."][..], None),
        (
            &["keyhog", "scan", "--daemon=auto", "."][..],
            Some(DaemonMode::Auto),
        ),
    ] {
        let cli = Cli::try_parse_from(argv).expect("args parse");
        match cli.command {
            Some(Command::Scan(args)) => assert_eq!(args.daemon, expected),
            _ => panic!("expected Scan subcommand"),
        }
    }
}

#[test]
fn bare_daemon_flag_resolves_to_on() {
    // Bare `--daemon` is the concise spelling for "force on".
    assert_eq!(
        daemon_mode_of(&["keyhog", "scan", "--daemon", "."]),
        DaemonMode::On
    );
}

#[test]
fn explicit_values_resolve_one_to_one() {
    assert_eq!(
        daemon_mode_of(&["keyhog", "scan", "--daemon=on", "."]),
        DaemonMode::On
    );
    assert_eq!(
        daemon_mode_of(&["keyhog", "scan", "--daemon=off", "."]),
        DaemonMode::Off
    );
    assert_eq!(
        daemon_mode_of(&["keyhog", "scan", "--daemon=auto", "."]),
        DaemonMode::Auto
    );
}

#[test]
fn only_auto_and_on_require_the_unix_daemon_transport() {
    assert!(DaemonMode::Auto.may_use_daemon_transport());
    assert!(DaemonMode::On.may_use_daemon_transport());
    assert!(!DaemonMode::Off.may_use_daemon_transport());
}

#[test]
fn bare_daemon_does_not_swallow_positional_input() {
    // require_equals guards the optional value: a following positional path is
    // NOT consumed as the daemon value (would be an invalid-value error without
    // it). Bare `--daemon` => On, and `.` stays the scan input.
    let cli = Cli::try_parse_from(["keyhog", "scan", "--daemon", "src"]).expect("parse");
    match cli.command {
        Some(Command::Scan(args)) => {
            assert_eq!(args.daemon_mode(), DaemonMode::On);
            assert_eq!(args.input, vec![std::path::PathBuf::from("src")]);
        }
        _ => panic!("expected Scan subcommand"),
    }
}

#[test]
fn space_separated_value_is_rejected_by_require_equals() {
    // `--daemon on` (space) is NOT a value assignment; `on` would be read as a
    // positional. The attached form `--daemon=on` is the only value spelling.
    let cli = Cli::try_parse_from(["keyhog", "scan", "--daemon", "on"]).expect("parse");
    match cli.command {
        Some(Command::Scan(args)) => {
            assert_eq!(args.daemon_mode(), DaemonMode::On);
            assert_eq!(args.input, vec![std::path::PathBuf::from("on")]);
        }
        _ => panic!("expected Scan subcommand"),
    }
}
