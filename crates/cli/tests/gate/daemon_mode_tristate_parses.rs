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
fn bare_daemon_does_not_swallow_positional_input() {
    // require_equals guards the optional value: a following positional path is
    // NOT consumed as the daemon value (would be an invalid-value error without
    // it). Bare `--daemon` => On, and `.` stays the scan input.
    let cli = Cli::try_parse_from(["keyhog", "scan", "--daemon", "src"]).expect("parse");
    match cli.command {
        Some(Command::Scan(args)) => {
            assert_eq!(args.daemon_mode(), DaemonMode::On);
            assert_eq!(args.input.as_deref(), Some(std::path::Path::new("src")));
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
            assert_eq!(args.input.as_deref(), Some(std::path::Path::new("on")));
        }
        _ => panic!("expected Scan subcommand"),
    }
}
