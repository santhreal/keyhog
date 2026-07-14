//! `keyhog repair` - restore a broken install.
//!
//! Runs the scan-engine self-test; if it fails (missing shared lib, corrupted
//! binary, partial install) - or with `--force` - it reinstalls a known-good
//! binary from GitHub releases via the shared [`crate::installer`] primitives,
//! then verifies the result by executing the freshly-installed binary's own
//! `doctor`. Exits non-zero if the reinstalled binary still isn't healthy.

use crate::args::RepairArgs;
use crate::exit_codes::EXIT_REPAIR_FAILED;
use crate::installer;
use crate::style::{self, Palette};
use anyhow::Result;
use std::process::ExitCode;

pub(crate) async fn run(args: RepairArgs) -> Result<ExitCode> {
    let palette = style::for_stdout();
    let Palette {
        yellow,
        dim,
        bold,
        reset,
        ..
    } = palette;
    println!("{bold}keyhog repair{reset}");

    // 1. Diagnose. The in-process self-test exercises the running binary's
    //    scan pipeline; if it works and the user didn't force, there's nothing
    //    to repair.
    let self_test = installer::scan_engine_self_test();
    let healthy = matches!(self_test, Ok(true));
    if healthy && !args.force {
        println!(
            "  {} scan engine healthy - nothing to repair.",
            style::pass("PASS", &palette)
        );
        println!("  {dim}use --force to reinstall the latest release anyway.{reset}");
        return Ok(ExitCode::SUCCESS);
    }
    if healthy {
        println!("  {dim}--force: reinstalling a fresh binary.{reset}");
    } else {
        match &self_test {
            Ok(false) => {
                println!(
                    "  {yellow}self-test failed{reset} (planted secret was not detected) - reinstalling a fresh binary."
                );
            }
            Err(error) => {
                println!(
                    "  {yellow}self-test failed{reset} ({error}) - reinstalling a fresh binary."
                );
            }
            Ok(true) => {}
        }
    }

    // 2. Reinstall a known-good release binary (latest, or pinned --version).
    let client = installer::http_client()?;
    let release = installer::resolve_release(&client, args.version.as_deref()).await?;
    let asset = installer::select_asset(&release)?;
    let expected_tag = release.tag_name.clone();
    let allow_explicit_downgrade = args.version.is_some();
    println!("  downloading    {} ({})", asset.name, release.tag_name);
    let bytes = installer::download_verified_asset(&client, &release, asset).await?;
    let gpu_literal_asset = installer::select_gpu_literal_asset(&release, asset)?;
    println!("  gpu literals   {}", gpu_literal_asset.name);
    let gpu_literal_bytes =
        installer::download_verified_gpu_literal_asset(&client, &release, gpu_literal_asset)
            .await?;
    let gpu_literal_files =
        installer::parse_gpu_literal_sidecar(&gpu_literal_bytes, &expected_tag)?;
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
    match installer::install_with_rollback_checked(&exe, &bytes, |candidate| {
        let gpu_transaction = installer::install_gpu_literal_files(&gpu_literal_files)?;
        installer::verify_candidate_release(
            candidate,
            &expected_tag,
            env!("CARGO_PKG_VERSION"),
            allow_explicit_downgrade,
        )?;
        gpu_transaction.commit();
        Ok(())
    }) {
        Ok(()) => {
            println!(
                "\n{} repaired: reinstalled {} and verified healthy.",
                style::pass("PASS", &palette),
                release.tag_name,
            );
            Ok(ExitCode::SUCCESS)
        }
        // Health check failed (rolled back) or the install itself failed. Either
        // way a working binary is preserved where one existed; fail closed with
        // the dedicated code so CI/automation can branch on it.
        Err(e) => {
            let stderr_palette = style::for_stderr();
            let Palette { dim, reset, .. } = stderr_palette;
            eprintln!(
                "\n{} repair of {} did not produce a healthy binary: {e}\n\
                 {dim}If a shared library is missing, install it (see the doctor output above) \
                 and retry, or try `keyhog repair --version <older-tag>`.{reset}",
                style::fail("FAIL", &stderr_palette),
                release.tag_name
            );
            Ok(ExitCode::from(EXIT_REPAIR_FAILED))
        }
    }
}
