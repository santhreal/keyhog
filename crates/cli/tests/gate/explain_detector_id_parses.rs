//! LR1-A8 replacement gate: `subcommands/explain.rs`.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn explain_subcommand_carries_detector_id() {
    let cli = Cli::try_parse_from(["keyhog", "explain", "aws-access-key"]).unwrap();
    match cli.command {
        Some(Command::Explain(args)) => assert_eq!(args.detector_id, "aws-access-key"),
        _ => panic!("expected Explain subcommand"),
    }
}
