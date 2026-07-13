//! `keyhog update` - self-update from GitHub releases.
//!
//! A thin command over the shared [`crate::installer`] primitives (release
//! resolution, asset selection, verified download, atomic self-replace).
//! `--check` reports availability without installing.

use crate::args::UpdateArgs;
use crate::exit_codes::EXIT_UPDATE_AVAILABLE;
use crate::installer;
use crate::style::{self, Palette};
use anyhow::Result;
use std::process::ExitCode;

pub(crate) async fn run(args: UpdateArgs) -> Result<ExitCode> {
    let palette = style::for_stdout();
    let Palette {
        yellow,
        dim,
        bold,
        reset,
        ..
    } = palette;
    let current = env!("CARGO_PKG_VERSION");
    let client = installer::http_client()?;
    let release = installer::resolve_release(
        &client,
        args.version.as_deref(),
        args.release_api_base.as_deref(),
    )
    .await?;
    let latest = release.tag_name.clone();

    let asset = installer::select_asset(&release);

    println!("{bold}keyhog update{reset}");
    println!("  current        v{current}");
    println!("  latest         {latest}");
    match &asset {
        Ok(asset) => println!("  asset          {}", asset.name),
        Err(error) => println!("  asset          (unresolved for this platform: {error:#})"),
    }

    let newer = installer::is_newer(current, &latest);
    // A pinned --version always proceeds (downgrade/pin is intentional);
    // otherwise only act when latest is strictly newer.
    let allow_explicit_downgrade = args.version.is_some();
    if args.version.is_none() && !newer {
        println!(
            "\n{} already on the latest release.",
            style::pass("PASS", &palette)
        );
        return Ok(ExitCode::SUCCESS);
    }

    if args.check {
        println!(
            "\n{yellow}{bold}update available:{reset} v{current} to {latest}  {dim}(run `keyhog update`){reset}"
        );
        return Ok(ExitCode::from(EXIT_UPDATE_AVAILABLE));
    }

    let asset = asset?;
    let gpu_literal_asset = installer::select_gpu_literal_asset(&release, asset)?;
    println!("\n  downloading    {}", asset.browser_download_url);
    let bytes = installer::download_verified_asset(&client, &release, asset).await?;
    println!("  gpu literals   {}", gpu_literal_asset.name);
    let gpu_literal_bytes =
        installer::download_verified_gpu_literal_asset(&client, &release, gpu_literal_asset)
            .await?;
    let gpu_literal_files = installer::parse_gpu_literal_sidecar(&gpu_literal_bytes, &latest)?;
    let exe = installer::current_binary()?;
    // Clear any stash left locked by a prior self-replace (Windows keeps the
    // old image locked until its process exits; this is the next run).
    installer::reap_stale_binaries(&exe);

    // Recoverability invariant: back up the current binary, install, then run
    // the NEW binary's `doctor` as a health gate. If it can't run on this host
    // (wrong libc, broken release), roll back to the working binary instead of
    // leaving the user with a bricked install reporting success.
    println!("\n{dim}verifying the new binary on this host...{reset}\n");
    installer::install_with_rollback_checked(&exe, &bytes, |candidate| {
        let gpu_transaction = installer::install_gpu_literal_files(&gpu_literal_files)?;
        installer::verify_candidate_release(candidate, &latest, current, allow_explicit_downgrade)?;
        gpu_transaction.commit();
        Ok(())
    })?;

    println!(
        "\n{} updated v{current} to {latest}  {dim}{}{reset}",
        style::pass("PASS", &palette),
        exe.display(),
    );
    Ok(ExitCode::SUCCESS)
}
