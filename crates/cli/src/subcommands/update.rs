//! `keyhog update` - self-update from GitHub releases.
//!
//! A thin command over the shared [`crate::installer`] primitives (release
//! resolution, asset selection, verified download, atomic self-replace).
//! `--check` reports availability without installing.

use crate::args::UpdateArgs;
use crate::installer;
use crate::style::Palette;
use anyhow::Result;
use std::process::ExitCode;

/// `--check` exit code when a newer release is available (0 = up-to-date).
/// Distinct so a cron/CI poller can branch on "update available" without
/// parsing stdout.
const EXIT_UPDATE_AVAILABLE: u8 = 10;

pub async fn run(args: UpdateArgs) -> Result<ExitCode> {
    let Palette {
        green,
        yellow,
        dim,
        bold,
        reset,
        ..
    } = Palette::for_stdout();
    let current = env!("CARGO_PKG_VERSION");
    let client = installer::http_client()?;
    let release = installer::resolve_release(&client, args.version.as_deref()).await?;
    let latest = release.tag_name.clone();

    // Default to the portable build unless `--variant cuda`; without an
    // install manifest we can't know the currently-installed variant, and the
    // portable build runs everywhere (still GPU-accelerated via WGPU).
    let want_cuda = args.variant.as_deref() == Some("cuda");
    let asset = installer::select_asset(&release, want_cuda)?;

    println!("{bold}keyhog update{reset}");
    println!("  current        v{current}");
    println!("  latest         {latest}");
    println!("  asset          {}", asset.name);

    let newer = installer::is_newer(current, &latest);
    // A pinned --version always proceeds (downgrade/pin is intentional);
    // otherwise only act when latest is strictly newer.
    if args.version.is_none() && !newer {
        println!("\n{green}{bold}✓ already on the latest release.{reset}");
        return Ok(ExitCode::SUCCESS);
    }

    if args.check {
        println!(
            "\n{yellow}{bold}update available:{reset} v{current} → {latest}  {dim}(run `keyhog update`){reset}"
        );
        return Ok(ExitCode::from(EXIT_UPDATE_AVAILABLE));
    }

    println!("\n  downloading    {}", asset.browser_download_url);
    let bytes = installer::download_verified_asset(&client, asset).await?;
    let exe = installer::current_binary()?;
    installer::install_binary(&exe, &bytes)?;

    println!(
        "\n{green}{bold}✓ updated v{current} → {latest}{reset}  {dim}{}{reset}",
        exe.display()
    );
    Ok(ExitCode::SUCCESS)
}
