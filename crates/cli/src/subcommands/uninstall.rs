//! `keyhog uninstall` - remove the installed binary.
//!
//! Dry-run by default (prints what would be removed); `--yes` performs the
//! removal. On Unix the running binary's file can be unlinked while the
//! process keeps executing, so the delete succeeds immediately. keyhog never
//! edits your shell config - it points at the integration bits to clean up by
//! hand instead.

use crate::args::UninstallArgs;
use crate::installer;
use crate::style::{self, Palette};
use anyhow::{anyhow, Result};
use std::path::Path;
use std::process::ExitCode;

pub(crate) fn run(args: UninstallArgs) -> Result<ExitCode> {
    let palette = style::for_stdout();
    // `dim` is used only by print_integration_hints, which reads it from the
    // palette we pass in; run() itself uses the four below.
    let Palette {
        yellow,
        bold,
        reset,
        ..
    } = palette;
    let exe = installer::current_binary()?;
    println!("{bold}keyhog uninstall{reset}");
    println!("  binary         {}", exe.display());

    if !args.yes {
        println!(
            "\n{yellow}{bold}dry run{reset} - nothing removed. Re-run with {bold}--yes{reset} to delete the binary above."
        );
        print_integration_hints(&exe, &palette);
        return Ok(ExitCode::SUCCESS);
    }

    remove_binary(&exe)?;
    println!(
        "\n{} removed {}",
        style::pass("PASS", &palette),
        exe.display()
    );
    print_integration_hints(&exe, &palette);
    Ok(ExitCode::SUCCESS)
}

/// keyhog never silently mutates shell config; surface the integration points
/// for the user to remove themselves.
fn print_integration_hints(exe: &Path, palette: &Palette) {
    let Palette {
        dim, bold, reset, ..
    } = *palette;
    let dir = exe
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "the install dir".into()); // LAW10: absent name/label => display default; reporting-only, recall-safe
    println!("\n{bold}manual cleanup (keyhog never edits your shell config):{reset}");
    println!(
        "  {dim}- PATH export for {dir} in your shell rc (~/.bashrc, ~/.zshrc, ~/.config/fish/config.fish){reset}"
    );
    println!("  {dim}- shell completions you installed via `keyhog completion`{reset}");
    println!("  {dim}- the pre-commit hook in any repo where you ran `keyhog hook install`{reset}");
    // The on-disk cache (compiled GPU rule catalogs + the detector/merkle
    // cache) survives a binary removal and can be ~GB. A premium uninstall
    // names it with its real, current path so the user can reclaim the space —
    // it is NOT auto-deleted (a reinstall reuses it to skip the multi-second
    // catalog recompile), but leaving it unmentioned orphaned it silently.
    if let Some(cache) = dirs::cache_dir().map(|d| d.join("keyhog")) {
        if cache.is_dir() {
            println!(
                "  {dim}- the keyhog cache at {} (compiled catalogs; safe to delete, a reinstall rebuilds it){reset}",
                cache.display()
            );
        }
    }
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
