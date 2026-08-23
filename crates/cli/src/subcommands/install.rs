//! `keyhog install` - compile, authenticate, calibrate, and install execution packs for the local host.

use crate::args::InstallArgs;
use crate::execution_pack_install::InstalledArtifactRegistry;
use crate::installer;
use crate::style::{self, Palette};
use anyhow::{Context, Result};
use std::process::ExitCode;

pub(crate) fn run(args: InstallArgs) -> Result<ExitCode> {
    let palette = style::for_stdout();
    let Palette { bold, reset, .. } = palette;
    println!("{bold}keyhog install{reset}");

    let exe = installer::current_binary().context("resolving current binary")?;
    let cache_root = dirs::cache_dir()
        .context("platform cache directory is unavailable")?
        .join("keyhog");

    if !args.force && InstalledArtifactRegistry::verify_installed_cache_root(&cache_root).is_ok() {
        println!(
            "{} already installed: execution packs, plans, matchers, policies, and autoroute calibration are valid for this binary (pass --force to reinstall).",
            style::pass("PASS", &palette),
        );
        return Ok(ExitCode::SUCCESS);
    }

    let transaction =
        installer::install_execution_generation(&exe).context("installing execution generation")?;

    InstalledArtifactRegistry::verify_installed_cache_root(&cache_root)
        .context("verifying newly installed artifacts")?;

    InstalledArtifactRegistry::assert_bidirectional_registry_equality()
        .context("verifying installed artifact registry")?;

    transaction.commit();

    println!(
        "{} installed: generated execution packs, plans, matchers, policies, and autoroute calibration.",
        style::pass("PASS", &palette),
    );
    Ok(ExitCode::SUCCESS)
}
