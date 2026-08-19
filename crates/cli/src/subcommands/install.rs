//! `keyhog install` - compile, authenticate, calibrate, and install execution packs for the local host.

use crate::args::InstallArgs;
use crate::execution_pack_install::InstalledArtifactRegistry;
use crate::installer;
use crate::style::{self, Palette};
use anyhow::{Context, Result};
use std::process::ExitCode;

pub(crate) fn run(_args: InstallArgs) -> Result<ExitCode> {
    let palette = style::for_stdout();
    let Palette { bold, reset, .. } = palette;
    println!("{bold}keyhog install{reset}");

    let exe = installer::current_binary().context("resolving current binary")?;
    let transaction =
        installer::install_execution_generation(&exe).context("installing execution generation")?;
    transaction.commit();

    InstalledArtifactRegistry::assert_bidirectional_registry_equality()
        .context("verifying installed artifact registry")?;

    println!(
        "{} installed: generated execution packs, plans, matchers, policies, and autoroute calibration.",
        style::pass("PASS", &palette),
    );
    Ok(ExitCode::SUCCESS)
}
