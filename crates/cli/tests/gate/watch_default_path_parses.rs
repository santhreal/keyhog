//! LR1-A8 replacement gate: `subcommands/watch.rs`.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn watch_subcommand_path_defaults_to_cwd() {
    let cli = Cli::try_parse_from(["keyhog", "watch", "."]).unwrap();
    match cli.command {
        Some(Command::Watch(args)) => assert_eq!(args.path, std::path::PathBuf::from(".")),
        other => panic!("expected Watch subcommand"),
    }
}
