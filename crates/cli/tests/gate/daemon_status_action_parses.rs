//! LR1-A8 replacement gate: `subcommands/daemon.rs` status action.

use clap::Parser;
use keyhog::args::{Cli, Command, DaemonAction};

#[test]
fn daemon_status_action_is_selected() {
    let cli = Cli::try_parse_from(["keyhog", "daemon", "status"]).unwrap();
    match cli.command {
        Some(Command::Daemon(args)) => {
            assert!(matches!(args.action, DaemonAction::Status { .. }));
        }
        other => panic!("expected Daemon subcommand"),
    }
}
