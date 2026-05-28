//! `keyhog uninstall` - remove the installed binary.
//!
//! Dry-run by default (prints what would be removed); `--yes` performs the
//! removal. On Unix the running binary's file can be unlinked while the
//! process keeps executing, so the delete succeeds immediately. keyhog never
//! edits your shell config - it points at the integration bits to clean up by
//! hand instead.

use crate::args::UninstallArgs;
use crate::installer;
use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::ExitCode;

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

pub fn run(args: UninstallArgs) -> Result<ExitCode> {
    let exe = installer::current_binary()?;
    println!("{BOLD}keyhog uninstall{RESET}");
    println!("  binary         {}", exe.display());

    if !args.yes {
        println!(
            "\n{YELLOW}{BOLD}dry run{RESET} - nothing removed. Re-run with {BOLD}--yes{RESET} to delete the binary above."
        );
        print_integration_hints(&exe);
        return Ok(ExitCode::SUCCESS);
    }

    remove_binary(&exe)?;
    println!("\n{GREEN}{BOLD}✓ removed {}{RESET}", exe.display());
    print_integration_hints(&exe);
    Ok(ExitCode::SUCCESS)
}

/// keyhog never silently mutates shell config; surface the integration points
/// for the user to remove themselves.
fn print_integration_hints(exe: &Path) {
    let dir = exe
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "the install dir".into());
    println!("\n{BOLD}manual cleanup (keyhog never edits your shell config):{RESET}");
    println!(
        "  {DIM}- PATH export for {dir} in your shell rc (~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish){RESET}"
    );
    println!("  {DIM}- shell completions you installed via `keyhog completion`{RESET}");
    println!("  {DIM}- the pre-commit hook in any repo where you ran `keyhog hook install`{RESET}");
}

#[cfg(unix)]
fn remove_binary(exe: &Path) -> Result<()> {
    // Unix lets you unlink a running executable's file: the kernel keeps the
    // open inode alive for this process, and the path is gone immediately.
    std::fs::remove_file(exe).map_err(|e| {
        anyhow!(
            "could not remove {} ({e}); if keyhog lives in a system path, re-run with sudo",
            exe.display()
        )
    })
}

#[cfg(windows)]
fn remove_binary(exe: &Path) -> Result<()> {
    // Windows refuses to delete a running .exe. Surface the path so the user
    // can remove it once this process exits.
    Err(anyhow!(
        "Windows can't delete a running .exe. After this process exits, remove: {}",
        exe.display()
    ))
}
