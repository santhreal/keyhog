//! LR1-A8 replacement gate: `subcommands/scan_system.rs`.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn scan_system_subcommand_is_selected() {
    let cli = Cli::try_parse_from(["keyhog", "scan-system"]).unwrap();
    assert!(matches!(cli.command, Some(Command::ScanSystem(_))));
}
