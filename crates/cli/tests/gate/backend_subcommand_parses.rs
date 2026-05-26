//! LR1-A8 replacement gate: `subcommands/backend.rs` must parse to Backend variant.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn backend_subcommand_selects_backend_variant() {
    let cli = Cli::try_parse_from(["keyhog", "backend"]).unwrap();
    match cli.command {
        Some(Command::Backend(args)) => {
            assert!(args.probe_bytes.is_none());
            assert_eq!(args.patterns, 1509);
            assert!(!args.self_test);
        }
        other => panic!("expected Backend subcommand"),
    }
}
