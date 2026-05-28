//! `keyhog update` - self-update from GitHub releases.
//!
//! A thin command over the shared [`crate::installer`] primitives (release
//! resolution, asset selection, verified download, atomic self-replace).
//! `--check` reports availability without installing.

use crate::args::UpdateArgs;
use crate::installer;
use anyhow::Result;
use std::process::ExitCode;

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

/// `--check` exit code when a newer release is available (0 = up-to-date).
/// Distinct so a cron/CI poller can branch on "update available" without
/// parsing stdout.
const EXIT_UPDATE_AVAILABLE: u8 = 10;

pub async fn run(args: UpdateArgs) -> Result<ExitCode> {
    let current = env!("CARGO_PKG_VERSION");
    let client = installer::http_client()?;
    let release = installer::resolve_release(&client, args.version.as_deref()).await?;
    let latest = release.tag_name.clone();

    // Default to the portable build unless `--variant cuda`; without an
    // install manifest we can't know the currently-installed variant, and the
    // portable build runs everywhere (still GPU-accelerated via WGPU).
    let want_cuda = args.variant.as_deref() == Some("cuda");
    let asset = installer::select_asset(&release, want_cuda)?;

    println!("{BOLD}keyhog update{RESET}");
    println!("  current        v{current}");
    println!("  latest         {latest}");
    println!("  asset          {}", asset.name);

    let newer = installer::is_newer(current, &latest);
    // A pinned --version always proceeds (downgrade/pin is intentional);
    // otherwise only act when latest is strictly newer.
    if args.version.is_none() && !newer {
        println!("\n{GREEN}{BOLD}✓ already on the latest release.{RESET}");
        return Ok(ExitCode::SUCCESS);
    }

    if args.check {
        println!(
            "\n{YELLOW}{BOLD}update available:{RESET} v{current} → {latest}  {DIM}(run `keyhog update`){RESET}"
        );
        return Ok(ExitCode::from(EXIT_UPDATE_AVAILABLE));
    }

    println!("\n  downloading    {}", asset.browser_download_url);
    let bytes = installer::download_verified_asset(&client, asset).await?;
    let exe = installer::current_binary()?;
    installer::install_binary(&exe, &bytes)?;

    println!(
        "\n{GREEN}{BOLD}✓ updated v{current} → {latest}{RESET}  {DIM}{}{RESET}",
        exe.display()
    );
    Ok(ExitCode::SUCCESS)
}
