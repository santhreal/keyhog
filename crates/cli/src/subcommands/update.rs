//! `keyhog update` - self-update from GitHub releases.
//!
//! Resolves the latest release (or a pinned `--version` tag), selects the
//! raw-binary asset for this host + variant, downloads it over HTTPS, sanity-
//! checks it's a real executable for this platform, and atomically swaps the
//! running binary. `--check` reports availability without installing.
//!
//! Trust model today is HTTPS-to-GitHub-releases - the same model as the
//! `curl | sh` installer. minisign signature verification is a planned
//! hardening layer (it needs the release workflow to sign artifacts first);
//! the download path is structured so it can slot in without a rewrite.

use crate::args::UpdateArgs;
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::path::Path;
use std::process::ExitCode;

const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

const REPO: &str = "santhsecurity/keyhog";

/// `--check` exit code when a newer release is available (0 = up-to-date).
/// Distinct so a cron/CI poller can branch on "update available" without
/// parsing stdout.
const EXIT_UPDATE_AVAILABLE: u8 = 10;

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

pub async fn run(args: UpdateArgs) -> Result<ExitCode> {
    let current = env!("CARGO_PKG_VERSION");
    let client = reqwest::Client::builder()
        .user_agent(format!("keyhog/{current}"))
        .build()
        .context("build HTTP client")?;

    let release = resolve_release(&client, args.version.as_deref()).await?;
    let latest = release.tag_name.as_str();

    // Asset selection. Default to the portable (non-CUDA) build unless the
    // user asks for `--variant cuda`; without an install manifest we can't
    // know which variant is currently installed, and the portable build runs
    // everywhere (it still uses the GPU via WGPU). The manifest-aware variant
    // is tracked with `keyhog repair`.
    let want_cuda = args.variant.as_deref() == Some("cuda");
    let target = asset_name(std::env::consts::OS, std::env::consts::ARCH, want_cuda)
        .ok_or_else(|| {
            anyhow!(
                "no prebuilt asset for {}-{} (supported: linux-x86_64, macos-aarch64, macos-x86_64)",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        })?;
    // CUDA asset falls back to the portable build if a release didn't ship it.
    let fallback = asset_name(std::env::consts::OS, std::env::consts::ARCH, false);
    let asset = release
        .assets
        .iter()
        .find(|a| a.name == target)
        .or_else(|| {
            fallback
                .as_deref()
                .and_then(|f| release.assets.iter().find(|a| a.name == f))
        })
        .ok_or_else(|| {
            anyhow!("release {latest} has no asset named {target} (or its portable fallback)")
        })?;

    println!("{BOLD}keyhog update{RESET}");
    println!("  current        v{current}");
    println!("  latest         {latest}");
    println!("  asset          {}", asset.name);

    let newer = is_newer(current, latest);
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
    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("download asset")?
        .error_for_status()
        .context("download asset (HTTP status)")?
        .bytes()
        .await
        .context("read asset body")?;

    if !looks_like_native_executable(&bytes) {
        return Err(anyhow!(
            "downloaded asset is not a {} executable ({} bytes) - refusing to install. \
             The release asset may be missing or the download was intercepted.",
            std::env::consts::OS,
            bytes.len()
        ));
    }

    let exe = std::env::current_exe().context("locate current executable")?;
    // Resolve symlinks so we replace the real binary, not a symlink into it.
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    install_binary(&exe, &bytes)?;

    println!(
        "\n{GREEN}{BOLD}✓ updated v{current} → {latest}{RESET}  {DIM}{}{RESET}",
        exe.display()
    );
    Ok(ExitCode::SUCCESS)
}

/// GitHub release-asset name for `keyhog` on a given host. Mirrors the asset
/// naming the release workflow + install.sh use. Returns `None` for platforms
/// without a prebuilt asset.
fn asset_name(os: &str, arch: &str, cuda: bool) -> Option<String> {
    match (os, arch) {
        ("linux", "x86_64") => Some(if cuda {
            "keyhog-linux-x86_64-cuda".into()
        } else {
            "keyhog-linux-x86_64".into()
        }),
        ("macos", "aarch64") => Some("keyhog-macos-aarch64".into()),
        ("macos", "x86_64") => Some("keyhog-macos-x86_64".into()),
        _ => None,
    }
}

/// Parse a `vMAJOR.MINOR.PATCH` (or bare `MAJOR.MINOR.PATCH`) tag. Extra
/// pre-release/build suffixes after the patch number are ignored.
fn parse_semver(tag: &str) -> Option<(u64, u64, u64)> {
    let t = tag.trim().trim_start_matches('v');
    let mut it = t.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    // patch may carry a suffix like `3-rc1`; take the leading digits.
    let patch_field = it.next()?;
    let patch_digits: String = patch_field
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let patch = patch_digits.parse().ok()?;
    Some((major, minor, patch))
}

/// True if `latest` is a strictly newer semver than `current`. Unparseable
/// versions compare as "not newer" (fail safe: never auto-install on garbage).
fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Cheap guard against installing a non-executable (404 HTML page, truncated
/// download) as the binary: check the platform's executable magic bytes.
fn looks_like_native_executable(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    match std::env::consts::OS {
        // ELF: 0x7F 'E' 'L' 'F'
        "linux" => bytes.starts_with(&[0x7F, b'E', b'L', b'F']),
        // Mach-O: thin (0xFEEDFACE/CF) or fat/universal (0xCAFEBABE), either endianness.
        "macos" => matches!(
            bytes[..4],
            [0xFE, 0xED, 0xFA, 0xCE]
                | [0xCE, 0xFA, 0xED, 0xFE]
                | [0xFE, 0xED, 0xFA, 0xCF]
                | [0xCF, 0xFA, 0xED, 0xFE]
                | [0xCA, 0xFE, 0xBA, 0xBE]
                | [0xBE, 0xBA, 0xFE, 0xCA]
        ),
        // Unknown platform: don't block (we won't reach the install path on
        // Windows anyway - install_binary returns an error there).
        _ => true,
    }
}

#[cfg(unix)]
fn install_binary(exe: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?;
    // Stage in the SAME directory so the final rename is atomic (same
    // filesystem). Unix lets you replace a running executable's file: the
    // running process keeps the old (now-unlinked) inode, and the next run
    // picks up the new binary.
    let tmp = dir.join(format!(".keyhog-update-{}.tmp", std::process::id()));
    let cleanup = |e: std::io::Error| {
        let _ = std::fs::remove_file(&tmp);
        e
    };
    std::fs::write(&tmp, bytes)
        .map_err(cleanup)
        .with_context(|| {
            format!(
                "write new binary to {} (need write permission on the install dir; \
                 re-run with sudo or reinstall if keyhog lives in a system path)",
                dir.display()
            )
        })?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .map_err(cleanup)
        .context("chmod the new binary")?;
    std::fs::rename(&tmp, exe)
        .map_err(cleanup)
        .with_context(|| format!("atomically replace {}", exe.display()))?;
    Ok(())
}

#[cfg(windows)]
fn install_binary(_exe: &Path, _bytes: &[u8]) -> Result<()> {
    Err(anyhow!(
        "`keyhog update` self-replace is not implemented on Windows yet \
         (a running .exe can't be replaced in place). Re-run install.ps1 to update."
    ))
}

/// Resolve the release to install. With `version`, fetch that exact tag;
/// otherwise the most recent release that actually shipped assets (a release
/// can exist with zero assets if the workflow failed mid-upload).
async fn resolve_release(client: &reqwest::Client, version: Option<&str>) -> Result<Release> {
    if let Some(tag) = version {
        let url = format!("https://api.github.com/repos/{REPO}/releases/tags/{tag}");
        let release: Release = client
            .get(&url)
            .send()
            .await
            .context("query release tag")?
            .error_for_status()
            .with_context(|| format!("release tag {tag} not found"))?
            .json()
            .await
            .context("parse release JSON")?;
        return Ok(release);
    }
    let url = format!("https://api.github.com/repos/{REPO}/releases?per_page=10");
    let releases: Vec<Release> = client
        .get(&url)
        .send()
        .await
        .context("query releases")?
        .error_for_status()
        .context("query releases (HTTP status)")?
        .json()
        .await
        .context("parse releases JSON")?;
    releases
        .into_iter()
        .find(|r| !r.assets.is_empty())
        .ok_or_else(|| anyhow!("no recent GitHub release has any assets uploaded; pass --version"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_name_matches_release_convention() {
        assert_eq!(
            asset_name("linux", "x86_64", false).as_deref(),
            Some("keyhog-linux-x86_64")
        );
        assert_eq!(
            asset_name("linux", "x86_64", true).as_deref(),
            Some("keyhog-linux-x86_64-cuda")
        );
        assert_eq!(
            asset_name("macos", "aarch64", false).as_deref(),
            Some("keyhog-macos-aarch64")
        );
        assert_eq!(
            asset_name("macos", "x86_64", false).as_deref(),
            Some("keyhog-macos-x86_64")
        );
        // macOS has no CUDA build - cuda flag is ignored, no `-cuda` suffix.
        assert_eq!(
            asset_name("macos", "aarch64", true).as_deref(),
            Some("keyhog-macos-aarch64")
        );
        assert_eq!(asset_name("windows", "x86_64", false), None);
        assert_eq!(asset_name("linux", "riscv64", false), None);
    }

    #[test]
    fn semver_parsing_handles_v_prefix_and_suffix() {
        assert_eq!(parse_semver("v0.5.36"), Some((0, 5, 36)));
        assert_eq!(parse_semver("0.5.36"), Some((0, 5, 36)));
        assert_eq!(parse_semver("v1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_semver("garbage"), None);
        assert_eq!(parse_semver("v1.2"), None);
    }

    #[test]
    fn is_newer_compares_correctly() {
        assert!(is_newer("0.5.35", "v0.5.36"));
        assert!(is_newer("0.5.35", "0.6.0"));
        assert!(is_newer("0.5.35", "1.0.0"));
        assert!(!is_newer("0.5.36", "v0.5.36")); // equal
        assert!(!is_newer("0.5.36", "v0.5.35")); // older
        assert!(!is_newer("0.5.35", "garbage")); // fail-safe: never act on garbage
    }

    #[test]
    fn rejects_non_executable_download() {
        // A GitHub 404 HTML page must never be installed as the binary.
        assert!(!looks_like_native_executable(
            b"<!DOCTYPE html><html>Not Found"
        ));
        assert!(!looks_like_native_executable(b""));
        #[cfg(target_os = "linux")]
        assert!(looks_like_native_executable(&[
            0x7F, b'E', b'L', b'F', 2, 1, 1, 0
        ]));
    }
}
