//! LR1-A8 replacement gate: `subcommands/detectors.rs`.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn detectors_subcommand_default_audit_off() {
    let cli = Cli::try_parse_from(["keyhog", "detectors"]).unwrap();
    match cli.command {
        Some(Command::Detectors(args)) => assert!(!args.audit),
        other => panic!("expected Detectors subcommand"),
    }
}
