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

#[test]
fn hook_run_subcommand_is_selected() {
    let cli = keyhog::args::try_parse_from(["keyhog", "hook", "run"]).unwrap();
    match cli.command {
        Some(Command::Hook { command }) => {
            assert!(matches!(command, keyhog::args::HookCommand::Run(..)));
        }
        _ => panic!("expected Hook subcommand"),
    }
}

#[test]
fn hook_run_validates_backend_and_gpu_flags() {
    // --no-gpu cannot be used with a GPU backend
    let res = keyhog::args::try_parse_from([
        "keyhog",
        "hook",
        "run",
        "--backend",
        "gpu-cuda",
        "--no-gpu",
    ]);
    match res {
        Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict),
        Ok(_) => panic!("expected ArgumentConflict error"),
    }

    #[cfg(not(target_os = "macos"))]
    {
        let res = keyhog::args::try_parse_from(["keyhog", "hook", "run", "--backend", "gpu-metal"]);
        match res {
            Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue),
            Ok(_) => panic!("expected InvalidValue error"),
        }
    }
}
