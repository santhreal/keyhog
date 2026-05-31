//! Shared self-install / self-update primitives.
//!
//! The in-crate seed of the planned standalone installer library: `keyhog
//! doctor`, `update`, and `repair` all build on these. Keeping them in one
//! place is what lets the premium installer commands stay thin and lets the
//! whole layer be lifted into a published crate later without re-deriving the
//! GitHub-release resolution, asset selection, version comparison, executable
//! sanity check, atomic self-replace, and end-to-end scan self-test.
//!
//! Trust model: every release binary is signed with the keyhog minisign
//! secret key in the `sign` job of `.github/workflows/release.yml`, and
//! `download_verified_asset` verifies the downloaded binary against the
//! embedded [`RELEASE_PUBLIC_KEY`] before self-replacing. A missing `.minisig`
//! fails CLOSED (refuse to install) since a forged 404 would otherwise bypass
//! the whole gate; `KEYHOG_ALLOW_UNSIGNED_UPDATE=1` is the explicit opt-out.

use anyhow::{anyhow, Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;
use serde::Deserialize;
use std::path::{Path, PathBuf};

pub const REPO: &str = "santhsecurity/keyhog";

/// GitHub API base, overridable via `KEYHOG_RELEASE_API_BASE` so the
/// install/update/repair lifecycle can be driven end-to-end against a local
/// mock server (httpmock) with no network. Production default is the real
/// API. Asset download URLs are NOT derived from this: they come verbatim
/// from the release JSON's `browser_download_url`, so a mock that returns
/// asset URLs pointing at itself also controls the download + signature
/// fetch. This is the single seam the offline integration matrix relies on.
pub fn release_api_base() -> String {
    std::env::var("KEYHOG_RELEASE_API_BASE")
        .ok()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string())
}

/// minisign public key for keyhog release artifacts (key ID `DD4915EBE99F9CCF`).
/// The matching secret signs each release binary in CI. Rotating the key means
/// updating this constant and re-signing; clients keep trusting the old key
/// until they update to a build carrying the new one.
pub const RELEASE_PUBLIC_KEY: &str = "RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go";

/// Verify `data` against `signature` (the full body of a `.minisig` file)
/// using the embedded release public key. Errors on a malformed key, a
/// malformed signature, or a signature that does not match the data.
pub fn verify_release_signature(data: &[u8], signature: &str) -> Result<()> {
    use minisign_verify::{PublicKey, Signature};
    let pk = PublicKey::from_base64(RELEASE_PUBLIC_KEY)
        .map_err(|e| anyhow!("embedded release public key is invalid: {e}"))?;
    let sig =
        Signature::decode(signature).map_err(|e| anyhow!("release signature is malformed: {e}"))?;
    pk.verify(data, &sig, false)
        .map_err(|e| anyhow!("release signature verification failed: {e}"))
}

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
        // release.yml uploads keyhog-windows-x86_64.exe; without this arm
        // `select_asset` returned None on Windows and `update`/`repair`
        // could never resolve an asset there. CUDA has no Windows asset, so
        // the flag is ignored on this target.
        ("windows", "x86_64") => Some("keyhog-windows-x86_64.exe".into()),
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
pub async fn resolve_release(client: &reqwest::Client, version: Option<&str>) -> Result<Release> {
    let api = release_api_base();
    if let Some(tag) = version {
        let url = format!("{api}/repos/{REPO}/releases/tags/{tag}");
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
    let url = format!("{api}/repos/{REPO}/releases?per_page=10");
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

/// Download an asset over HTTPS, confirm it's a native executable for this
/// platform, and verify its minisign signature against the embedded release
/// public key before handing the bytes back.
pub async fn download_verified_asset(client: &reqwest::Client, asset: &Asset) -> Result<Vec<u8>> {
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

    // Signature: the release `sign` job uploads `<asset>.minisig` alongside
    // each binary. Fetch and verify it. A 404 means the release predates
    // signing; warn and fall back to HTTPS-only trust rather than blocking
    // the update. A present-but-bad signature is a hard failure: refuse.
    let sig_url = format!("{}.minisig", asset.browser_download_url);
    let sig_resp = client
        .get(&sig_url)
        .send()
        .await
        .context("download release signature")?;
    if sig_resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Fail CLOSED. A missing .minisig is indistinguishable from an active
        // attacker who serves a tampered binary and returns 404 for its
        // signature - the old "warn and install anyway" path silently bypassed
        // the entire minisign gate on a forged 404. Every release is signed by
        // the `sign` job, so a 404 here is a downgrade attack or a broken
        // release; refuse either way. `KEYHOG_ALLOW_UNSIGNED_UPDATE=1` is the
        // explicit, loud opt-out for intentionally installing a pre-signing
        // release.
        if std::env::var("KEYHOG_ALLOW_UNSIGNED_UPDATE").as_deref() == Ok("1") {
            eprintln!(
                "warning: release asset {} is unsigned (no .minisig) and \
                 KEYHOG_ALLOW_UNSIGNED_UPDATE=1 is set - installing on HTTPS-only trust.",
                asset.name
            );
            return Ok(bytes.to_vec());
        }
        return Err(anyhow!(
            "release asset {} has no .minisig signature - refusing to install. A missing \
             signature can mean a tampered download intercepted the signature fetch. Set \
             KEYHOG_ALLOW_UNSIGNED_UPDATE=1 to override for a known pre-signing release.",
            asset.name
        ));
    }
    let sig_text = sig_resp
        .error_for_status()
        .context("download release signature (HTTP status)")?
        .text()
        .await
        .context("read release signature body")?;
    verify_release_signature(&bytes, &sig_text)
        .with_context(|| format!("verifying release asset {}", asset.name))?;
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

/// Where the prior binary is stashed during a rename-away replace. PID-scoped
/// so concurrent updates don't collide; hidden + beside `exe` so the restore is
/// an atomic same-filesystem rename.
fn stash_path(exe: &Path) -> PathBuf {
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyhog".to_string());
    let parent = exe.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}.keyhog-old-{}", std::process::id()))
}

/// Write `bytes` to `path` and (on unix) mark it executable.
fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| {
        format!(
            "write new binary to {} (the install dir must be writable; re-run with \
             elevated permissions or reinstall if keyhog lives in a system path)",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .context("chmod the new binary")?;
    }
    Ok(())
}

/// Replace `exe` with `bytes` using the rename-away dance, verifying before
/// committing and rolling back on failure. Returns the stash path of the prior
/// binary on success (the caller reaps it; on Windows the still-running image
/// stays locked until the process exits, so deletion is deferred).
///
/// Why rename-away: on Windows you cannot overwrite or delete the RUNNING
/// `.exe`, but you CAN rename it within its directory - the running process
/// keeps executing from the renamed file while the original name is freed for
/// the new binary (the same mechanism rustup and the `self-replace` crate use).
/// The dance is equally correct on Unix, so this single routine backs the
/// Windows path while being exercised by tests on the Linux host - the Windows
/// self-replace is NOT a separate, untested codepath.
pub fn replace_running_binary<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<Option<PathBuf>>
where
    F: FnOnce(&Path) -> bool,
{
    let had_prior = exe.exists();
    let stash = stash_path(exe);

    if had_prior {
        std::fs::rename(exe, &stash).with_context(|| {
            format!(
                "stash the current binary to {} before replacing it (the install dir \
                 must be writable so a failed update can roll back)",
                stash.display()
            )
        })?;
    }

    if let Err(e) = write_executable(exe, bytes) {
        // Nothing new committed; put the original name back and bail.
        if had_prior {
            let _ = std::fs::rename(&stash, exe);
        }
        return Err(e);
    }

    if verify(exe) {
        return Ok(had_prior.then_some(stash));
    }

    // The new binary doesn't work on this host. It is NOT the running image
    // (the prior one, now at `stash`, is), so remove it and restore the stash.
    let _ = std::fs::remove_file(exe);
    if had_prior {
        std::fs::rename(&stash, exe).with_context(|| {
            format!(
                "ROLLBACK FAILED: the new binary failed its health check and the stashed \
                 working binary at {} could not be restored over {}. Restore it manually.",
                stash.display(),
                exe.display()
            )
        })?;
        return Err(anyhow!(
            "new binary failed its post-install health check; rolled back to the previous \
             working binary. The release may be broken for this host (libc/GPU driver) - \
             try `keyhog update --version <older-tag>` or report the release."
        ));
    }
    Err(anyhow!(
        "installed binary failed its post-install health check and was removed (no prior \
         binary to roll back to). The release may be broken for this host."
    ))
}

/// Best-effort reap of stash files left by a prior `replace_running_binary`
/// (e.g. a Windows update whose `.keyhog-old-*` stayed locked until the process
/// exited). Cheap and silent; called only from `update`/`repair`, never the
/// hot scan path, so it adds no per-scan cost.
pub fn reap_stale_binaries(exe: &Path) {
    let Some(parent) = exe.parent() else { return };
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyhog".to_string());
    let prefix = format!(".{name}.keyhog-old-");
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(prefix.as_str())
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(windows)]
pub fn install_binary(exe: &Path, bytes: &[u8]) -> Result<()> {
    // Rename-away replace without a health gate (that is install_with_rollback's
    // job). Leaves the prior image stashed; reaped by `reap_stale_binaries` on
    // the next update/repair once this process has exited and unlocked it.
    let _ = replace_running_binary(exe, bytes, |_| true)?;
    Ok(())
}

/// Path beside `exe` where the pre-overwrite binary is stashed so a broken or
/// interrupted update/repair can roll back. PID-scoped so two concurrent
/// updates don't clobber each other's backup. Same directory as `exe` so the
/// restore is an atomic same-filesystem rename.
pub fn backup_path(exe: &Path) -> PathBuf {
    let name = exe
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "keyhog".to_string());
    let parent = exe.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(".{name}.keyhog-bak-{}", std::process::id()))
}

/// Run the freshly-installed binary's own `doctor` as the post-install health
/// gate. Execs a separate process (not the in-proc self-test) so it catches a
/// binary that is signed and a valid executable but won't actually run on THIS
/// host (wrong glibc, missing shared lib). Inherits stdio so the user sees the
/// doctor report as the verification. `true` only on exit code 0.
pub fn verify_via_doctor(exe: &Path) -> bool {
    matches!(
        std::process::Command::new(exe).arg("doctor").status(),
        Ok(status) if status.success()
    )
}

/// Install `bytes` over `exe` and prove the result works before committing to
/// it, with automatic rollback on failure. This is the recoverability
/// invariant in code: no update/repair may leave the machine without a working
/// binary.
///
/// 1. If `exe` already exists, copy it to [`backup_path`] FIRST. If that copy
///    fails (read-only dir, no space), abort before touching `exe` - the
///    working binary stays untouched.
/// 2. Atomically replace `exe` with the new bytes (via [`install_binary`]).
/// 3. Run `verify(exe)`. On success, delete the backup and return `Ok`.
/// 4. On verify failure, restore the backup over `exe` (atomic rename) and
///    return an error. If there was no prior binary (fresh install) and verify
///    fails, remove the broken binary rather than leave it in place.
///
/// `verify` is injected so tests can drive the rollback path deterministically
/// without execing a real binary; production callers pass [`verify_via_doctor`].
#[cfg(unix)]
pub fn install_with_rollback<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> bool,
{
    use std::os::unix::fs::PermissionsExt;
    let had_prior = exe.exists();
    let backup = backup_path(exe);

    if had_prior {
        std::fs::copy(exe, &backup).with_context(|| {
            format!(
                "back up the current binary to {} before updating (the install dir must be \
                 writable so a failed update can roll back; re-run with sudo or reinstall if \
                 keyhog lives in a system path)",
                backup.display()
            )
        })?;
        // Backup must itself be runnable for the rollback to restore a working
        // tool; mirror the 0755 we set on installs.
        let _ = std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o755));
    }

    // Atomic replace. On error `exe` is untouched (write/rename either fully
    // succeed or leave the original), so just drop the backup and bail.
    if let Err(e) = install_binary(exe, bytes) {
        if had_prior {
            let _ = std::fs::remove_file(&backup);
        }
        return Err(e);
    }

    if verify(exe) {
        if had_prior {
            let _ = std::fs::remove_file(&backup);
        }
        return Ok(());
    }

    // Verify failed: the new binary does not work on this host. Restore.
    if had_prior {
        std::fs::rename(&backup, exe).with_context(|| {
            format!(
                "ROLLBACK FAILED: the new binary failed its health check and the backup at {} \
                 could not be restored over {}. Reinstall manually from {}",
                backup.display(),
                exe.display(),
                backup.display()
            )
        })?;
        Err(anyhow!(
            "new binary failed its post-install health check; rolled back to the previous \
             working binary. The release may be broken for this host (libc/GPU driver) - \
             try `keyhog update --version <older-tag>` or report the release."
        ))
    } else {
        // Fresh install with no prior binary: don't leave a broken executable.
        let _ = std::fs::remove_file(exe);
        Err(anyhow!(
            "installed binary failed its post-install health check and was removed (no prior \
             binary to roll back to). The release may be broken for this host."
        ))
    }
}

#[cfg(windows)]
pub fn install_with_rollback<F>(exe: &Path, bytes: &[u8], verify: F) -> Result<()>
where
    F: FnOnce(&Path) -> bool,
{
    // Rename-away self-replace with the new binary's `doctor` as the health
    // gate and automatic rollback - the same recoverability invariant as unix,
    // via the cross-platform `replace_running_binary` (covered by tests on the
    // Linux host). The prior binary is the still-running image, locked by
    // Windows until this process exits; best-effort reap now, then leave it for
    // the next `update`/`repair` to clear via `reap_stale_binaries`.
    let stash = replace_running_binary(exe, bytes, verify)?;
    if let Some(stash) = stash {
        let _ = std::fs::remove_file(&stash);
    }
    Ok(())
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
        min_confidence: None,
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
