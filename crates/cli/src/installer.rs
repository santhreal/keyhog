//! Shared self-install / self-update primitives.
//!
//! The in-crate seed of the planned standalone installer library: `keyhog
//! doctor`, `update`, and `repair` all build on these. Keeping them in one
//! place is what lets the premium installer commands stay thin and lets the
//! whole layer be lifted into a published crate later without re-deriving the
//! GitHub-release resolution, asset selection, version comparison, executable
//! sanity check, atomic self-replace, and end-to-end scan self-test.
//!
//! Trust model today: HTTPS to GitHub releases (the same model as the
//! `curl | sh` installer). minisign signature verification is a structured
//! follow-up - `download_verified_asset` is the seam it slots into.

use anyhow::{anyhow, Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;
use std::path::Path;

pub const REPO: &str = "santhsecurity/keyhog";

#[derive(Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

/// GitHub release-asset name for `keyhog` on a given host. Mirrors the asset
/// naming the release workflow + install.sh use. `None` for platforms without
/// a prebuilt asset.
pub fn asset_name(os: &str, arch: &str, cuda: bool) -> Option<String> {
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

/// Parse a `vMAJOR.MINOR.PATCH` (or bare) tag; pre-release/build suffixes after
/// the patch number are ignored.
pub fn parse_semver(tag: &str) -> Option<(u64, u64, u64)> {
    let t = tag.trim().trim_start_matches('v');
    let mut it = t.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
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
pub fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Cheap guard against installing a non-executable (404 HTML page, truncated
/// download): check the platform's executable magic bytes.
pub fn looks_like_native_executable(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    match std::env::consts::OS {
        "linux" => bytes.starts_with(&[0x7F, b'E', b'L', b'F']),
        "macos" => matches!(
            bytes[..4],
            [0xFE, 0xED, 0xFA, 0xCE]
                | [0xCE, 0xFA, 0xED, 0xFE]
                | [0xFE, 0xED, 0xFA, 0xCF]
                | [0xCF, 0xFA, 0xED, 0xFE]
                | [0xCA, 0xFE, 0xBA, 0xBE]
                | [0xBE, 0xBA, 0xFE, 0xCA]
        ),
        _ => true,
    }
}

/// An HTTP client with the keyhog User-Agent GitHub's API requires.
pub fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("keyhog/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build HTTP client")
}

/// Resolve the release to operate on. With `version`, fetch that exact tag;
/// otherwise the most recent release that actually shipped assets (a release
/// can exist with zero assets if the workflow failed mid-upload).
pub async fn resolve_release(
    client: &reqwest::Client,
    version: Option<&str>,
) -> Result<Release> {
    if let Some(tag) = version {
        let url = format!("https://api.github.com/repos/{REPO}/releases/tags/{tag}");
        return client
            .get(&url)
            .send()
            .await
            .context("query release tag")?
            .error_for_status()
            .with_context(|| format!("release tag {tag} not found"))?
            .json()
            .await
            .context("parse release JSON");
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

/// Pick the asset for this host. `want_cuda` selects the CUDA Linux build,
/// falling back to the portable build if a release didn't ship the CUDA asset.
pub fn select_asset(release: &Release, want_cuda: bool) -> Result<&Asset> {
    let target = asset_name(std::env::consts::OS, std::env::consts::ARCH, want_cuda).ok_or_else(
        || {
            anyhow!(
                "no prebuilt asset for {}-{} (supported: linux-x86_64, macos-aarch64, macos-x86_64)",
                std::env::consts::OS,
                std::env::consts::ARCH
            )
        },
    )?;
    let fallback = asset_name(std::env::consts::OS, std::env::consts::ARCH, false);
    release
        .assets
        .iter()
        .find(|a| a.name == target)
        .or_else(|| {
            fallback
                .as_deref()
                .and_then(|f| release.assets.iter().find(|a| a.name == f))
        })
        .ok_or_else(|| {
            anyhow!(
                "release {} has no asset named {target} (or its portable fallback)",
                release.tag_name
            )
        })
}

/// Download an asset over HTTPS and confirm it's a native executable for this
/// platform before handing the bytes back. The single seam where minisign
/// signature verification will slot in.
pub async fn download_verified_asset(
    client: &reqwest::Client,
    asset: &Asset,
) -> Result<Vec<u8>> {
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
    Ok(bytes.to_vec())
}

/// Resolve the running binary, following symlinks so we replace the real file.
pub fn current_binary() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe().context("locate current executable")?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
}

#[cfg(unix)]
pub fn install_binary(exe: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent directory"))?;
    // Stage in the SAME directory so the final rename is atomic (same
    // filesystem). Unix lets you replace a running executable's file: the
    // running process keeps the old (now-unlinked) inode; the next run picks
    // up the new binary.
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
pub fn install_binary(_exe: &Path, _bytes: &[u8]) -> Result<()> {
    Err(anyhow!(
        "self-replace is not implemented on Windows yet (a running .exe can't \
         be replaced in place). Re-run install.ps1 to update."
    ))
}

/// End-to-end scan-engine self-test: compile a synthetic one-detector scanner,
/// plant a matching secret, and confirm it round-trips through compile -> scan
/// -> extract -> report. Uses a unique non-generic prefix so it neither
/// collides with a real detector nor trips example/placeholder suppression.
pub fn scan_engine_self_test() -> Result<bool> {
    const PLANTED: &str = "KHDOCTOR_A1b2C3d4E5f6";
    let detector = DetectorSpec {
        id: "kh-doctor-selftest".into(),
        name: "doctor self-test".into(),
        service: "doctor".into(),
        severity: Severity::Low,
        patterns: vec![PatternSpec {
            regex: "KHDOCTOR_[A-Za-z0-9]{12}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        keywords: vec!["KHDOCTOR".into()],
        ..Default::default()
    };
    let scanner = CompiledScanner::compile(vec![detector])?;
    let chunk = Chunk {
        data: format!("api_secret = {PLANTED}").into(),
        metadata: ChunkMetadata {
            source_type: "doctor".into(),
            path: Some("doctor-selftest.txt".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk);
    Ok(matches.iter().any(|m| m.credential.as_ref() == PLANTED))
}
