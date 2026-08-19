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
    //    scan pipeline, and artifact freshness verifies that execution packs
    //    match current binary, target hardware, features, and detector corpus.
    let self_test = installer::scan_engine_self_test();
    let self_test_healthy = matches!(self_test, Ok(true));
    let freshness = crate::execution_pack_install::check_installed_artifacts_freshness();
    let packs_fresh = matches!(
        freshness,
        Ok(crate::execution_pack_install::ArtifactFreshnessStatus::Fresh)
    );

    if self_test_healthy && packs_fresh && !args.force && args.version.is_none() {
        println!(
            "  {} scan engine and execution packs healthy - nothing to repair.",
            style::pass("PASS", &palette)
        );
        println!("  {dim}use --force to reinstall the newest binary release asset anyway.{reset}");
        return Ok(ExitCode::SUCCESS);
    }
    let exe = installer::current_binary()?;
    installer::reap_stale_binaries(&exe);

    if self_test_healthy && !packs_fresh && !args.force && args.version.is_none() {
        println!(
            "  {yellow}installed execution packs missing or stale{reset} - regenerating generation."
        );
        match installer::install_execution_generation(&exe) {
            Ok(transaction) => {
                transaction.commit();
                println!(
                    "\n{} repaired: regenerated execution packs and autoroute calibration.",
                    style::pass("PASS", &palette)
                );
                return Ok(ExitCode::SUCCESS);
            }
            Err(error) => {
                println!(
                    "  {yellow}local execution pack generation failed{reset} ({error}) - downloading fresh release."
                );
            }
        }
    }

    if self_test_healthy && args.force {
        println!("  {dim}--force: reinstalling a fresh binary.{reset}");
    } else if !self_test_healthy {
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
    // The resolver sets an explicit version on this path only after canonical
    // SemVer validation and exact returned-tag binding, so downgrade permission
    // cannot authorize a substituted release.
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
    // Stale binaries already reaped during diagnosis.
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
        let execution_transaction = installer::install_execution_generation(candidate)?;
        installer::verify_candidate_release(
            candidate,
            &expected_tag,
            env!("CARGO_PKG_VERSION"),
            allow_explicit_downgrade,
        )?;
        execution_transaction.commit();
        gpu_transaction.commit();
        Ok(())
    }) {
        Ok(()) => {
            // Publication of the repair outcome.
            let _report_span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
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
