//! LR1-A8 replacement gate: `subcommands/completion.rs` bash shell.

use clap::Parser;
use clap_complete::Shell;
use keyhog::args::{Cli, Command};

#[test]
fn completion_bash_shell_is_selected() {
    let cli = Cli::try_parse_from(["keyhog", "completion", "bash"]).unwrap();
    match cli.command {
        Some(Command::Completion(args)) => assert_eq!(args.shell, Shell::Bash),
        _ => panic!("expected Completion subcommand"),
    }
}
