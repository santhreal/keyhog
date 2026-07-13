//! LR1-A8 replacement gate: `subcommands/scan.rs`.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn scan_subcommand_default_input_is_dot() {
    let cli = Cli::try_parse_from(["keyhog", "scan", "."]).unwrap();
    match cli.command {
        Some(Command::Scan(args)) => {
            assert_eq!(args.input, vec![std::path::PathBuf::from(".")]);
        }
        _ => panic!("expected Scan subcommand"),
    }
}
