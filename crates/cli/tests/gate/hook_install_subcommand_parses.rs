//! LR1-A8 replacement gate: `subcommands/hook.rs` install.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn hook_install_subcommand_is_selected() {
    let cli = Cli::try_parse_from(["keyhog", "hook", "install"]).unwrap();
    match cli.command {
        Some(Command::Hook { command }) => {
            assert!(matches!(command, keyhog::args::HookCommand::Install { .. }));
        }
        _ => panic!("expected Hook subcommand"),
    }
}
