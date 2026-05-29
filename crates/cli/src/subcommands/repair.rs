//! `keyhog repair` - restore a broken install.
//!
//! Runs the scan-engine self-test; if it fails (missing shared lib, corrupted
//! binary, partial install) - or with `--force` - it reinstalls a known-good
//! binary from GitHub releases via the shared [`crate::installer`] primitives,
//! then verifies the result by executing the freshly-installed binary's own
//! `doctor`. Exits non-zero if the reinstalled binary still isn't healthy.

use crate::args::RepairArgs;
use crate::installer;
use crate::style::Palette;
use anyhow::Result;
use std::process::ExitCode;

/// Exit code when repair ran but the reinstalled binary still fails its health
/// check - distinct so a CI/automation caller can fail closed.
const EXIT_REPAIR_FAILED: u8 = 4;

pub async fn run(args: RepairArgs) -> Result<ExitCode> {
    let Palette {
        green,
        red,
        yellow,
        dim,
        bold,
        reset,
    } = Palette::for_stdout();
    println!("{bold}keyhog repair{reset}");

    // 1. Diagnose. The in-process self-test exercises the running binary's
    //    scan pipeline; if it works and the user didn't force, there's nothing
    //    to repair.
    let healthy = installer::scan_engine_self_test().unwrap_or(false);
    if healthy && !args.force {
        println!("  {green}scan engine healthy{reset} - nothing to repair.");
        println!("  {dim}use --force to reinstall the latest release anyway.{reset}");
        return Ok(ExitCode::SUCCESS);
    }
    if healthy {
        println!("  {dim}--force: reinstalling a fresh binary.{reset}");
    } else {
        println!("  {yellow}self-test failed{reset} - reinstalling a fresh binary.");
    }

    // 2. Reinstall a known-good release binary (latest, or pinned --version).
    let client = installer::http_client()?;
    let release = installer::resolve_release(&client, args.version.as_deref()).await?;
    let want_cuda = args.variant.as_deref() == Some("cuda");
    let asset = installer::select_asset(&release, want_cuda)?;
    println!("  downloading    {} ({})", asset.name, release.tag_name);
    let bytes = installer::download_verified_asset(&client, asset).await?;
    let exe = installer::current_binary()?;
    installer::reap_stale_binaries(&exe);

    // 3. Install with the recoverability invariant: back up the current binary,
    //    swap in the fresh one, then exec the NEW binary's `doctor` (inherits
    //    stdio so the user sees the report). If the reinstalled binary still
    //    can't run on this host, roll back to the backup. With `--force` on a
    //    HEALTHY install this matters most: a broken release must not brick a
    //    working tool. `install_with_rollback` returns Ok only when the new
    //    binary passed its own health check.
    println!("\n{dim}reinstalling and verifying the new binary...{reset}\n");
    match installer::install_with_rollback(&exe, &bytes, installer::verify_via_doctor) {
        Ok(()) => {
            println!(
                "\n{green}{bold}✓ repaired: reinstalled {} and verified healthy.{reset}",
                release.tag_name
            );
            Ok(ExitCode::SUCCESS)
        }
        // Health check failed (rolled back) or the install itself failed. Either
        // way a working binary is preserved where one existed; fail closed with
        // the dedicated code so CI/automation can branch on it.
        Err(e) => {
            eprintln!(
                "\n{red}{bold}✗ repair of {} did not produce a healthy binary:{reset} {e}\n\
                 {dim}If a shared library is missing, install it (see the doctor output above) \
                 and retry, or try `keyhog repair --version <older-tag>`.{reset}",
                release.tag_name
            );
            Ok(ExitCode::from(EXIT_REPAIR_FAILED))
        }
    }
}
