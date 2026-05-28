//! `keyhog repair` - restore a broken install.
//!
//! Runs the scan-engine self-test; if it fails (missing shared lib, corrupted
//! binary, partial install) - or with `--force` - it reinstalls a known-good
//! binary from GitHub releases via the shared [`crate::installer`] primitives,
//! then verifies the result by executing the freshly-installed binary's own
//! `doctor`. Exits non-zero if the reinstalled binary still isn't healthy.

use crate::args::RepairArgs;
use crate::installer;
use anyhow::Result;
use std::process::ExitCode;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// Exit code when repair ran but the reinstalled binary still fails its health
/// check - distinct so a CI/automation caller can fail closed.
const EXIT_REPAIR_FAILED: u8 = 4;

pub async fn run(args: RepairArgs) -> Result<ExitCode> {
    println!("{BOLD}keyhog repair{RESET}");

    // 1. Diagnose. The in-process self-test exercises the running binary's
    //    scan pipeline; if it works and the user didn't force, there's nothing
    //    to repair.
    let healthy = installer::scan_engine_self_test().unwrap_or(false);
    if healthy && !args.force {
        println!("  {GREEN}scan engine healthy{RESET} - nothing to repair.");
        println!("  {DIM}use --force to reinstall the latest release anyway.{RESET}");
        return Ok(ExitCode::SUCCESS);
    }
    if healthy {
        println!("  {DIM}--force: reinstalling a fresh binary.{RESET}");
    } else {
        println!("  {YELLOW}self-test failed{RESET} - reinstalling a fresh binary.");
    }

    // 2. Reinstall a known-good release binary (latest, or pinned --version).
    let client = installer::http_client()?;
    let release = installer::resolve_release(&client, args.version.as_deref()).await?;
    let want_cuda = args.variant.as_deref() == Some("cuda");
    let asset = installer::select_asset(&release, want_cuda)?;
    println!("  downloading    {} ({})", asset.name, release.tag_name);
    let bytes = installer::download_verified_asset(&client, asset).await?;
    let exe = installer::current_binary()?;
    installer::install_binary(&exe, &bytes)?;
    println!("  reinstalled    {}", exe.display());

    // 3. Verify the REINSTALLED binary (not the still-running old image): exec
    //    its own `doctor`. On Unix the rename swapped the file on disk, so
    //    `exe` now points at the new binary. Inherit stdio so the user sees
    //    the doctor report as the repair verification.
    println!("\n{DIM}verifying reinstalled binary...{RESET}\n");
    match std::process::Command::new(&exe).arg("doctor").status() {
        Ok(status) if status.success() => {
            println!(
                "\n{GREEN}{BOLD}✓ repaired: reinstalled {} and verified healthy.{RESET}",
                release.tag_name
            );
            Ok(ExitCode::SUCCESS)
        }
        Ok(_) => {
            eprintln!(
                "\n{RED}{BOLD}✗ reinstalled {} but it still reports issues above.{RESET} \
                 If a shared library is missing, install it (see the doctor/install output) and retry.",
                release.tag_name
            );
            Ok(ExitCode::from(EXIT_REPAIR_FAILED))
        }
        Err(e) => {
            eprintln!(
                "\n{RED}{BOLD}✗ reinstalled but could not run the new binary to verify:{RESET} {e}"
            );
            Ok(ExitCode::from(EXIT_REPAIR_FAILED))
        }
    }
}
