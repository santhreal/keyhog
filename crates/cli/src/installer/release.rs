//! Release resolution, download, and signature verification.
//!
//! This is the NETWORK + TRUST half of the installer: it talks to the GitHub
//! releases API, selects the right asset for this host, compares semver, and -
//! crucially - verifies each downloaded binary against the embedded minisign
//! public key before any byte is handed to the local-install half
//! ([`super`]). It owns no on-disk replace logic; it produces verified bytes.
//!
//! Trust model: every release binary is signed with the keyhog minisign secret
//! key in the `sign` job of `.github/workflows/release.yml`, and
//! [`download_verified_asset`] verifies the downloaded binary against the
//! embedded [`RELEASE_PUBLIC_KEY`] before returning it. A missing `.minisig`
//! fails CLOSED (refuse to install) since a forged 404 would otherwise bypass
//! the whole gate. There is no opt-out: no environment variable can disable the
//! signature gate (config-policy mandate + security).

use anyhow::{anyhow, Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{hw_probe::ScanBackend, CompiledScanner};
use serde::Deserialize;

pub(crate) const REPO: &str = "santhsecurity/keyhog";

/// GitHub API base for update/repair release resolution.
///
/// Production callers pass `None`, which always resolves to the canonical
/// GitHub API. Offline tests may pass an explicit mock-server URL through the
/// hidden `--release-api-base` argv seam. This must not read an environment
/// variable: release metadata controls what binary gets downloaded, so ambient
/// shell/CI state cannot be authority over it.
pub(crate) fn release_api_base(explicit: Option<&str>) -> String {
    explicit
        .map(str::trim)
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://api.github.com".to_string()) // LAW10: empty/unset explicit test seam ⇒ canonical GitHub API default; no ambient fallback.
}

/// minisign public key for keyhog release artifacts (key ID `DD4915EBE99F9CCF`).
/// The matching secret signs each release binary in CI. Rotating the key means
/// updating this constant and re-signing; clients keep trusting the old key
/// until they update to a build carrying the new one.
pub(crate) const RELEASE_PUBLIC_KEY: &str =
    "RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go";

/// Verify `data` against `signature` (the full body of a `.minisig` file)
/// using the embedded release public key. Errors on a malformed key, a
/// malformed signature, or a signature that does not match the data.
pub(crate) fn verify_release_signature(data: &[u8], signature: &str) -> Result<()> {
    use minisign_verify::{PublicKey, Signature};
    let pk = PublicKey::from_base64(RELEASE_PUBLIC_KEY)
        .map_err(|e| anyhow!("embedded release public key is invalid: {e}"))?;
    let sig =
        Signature::decode(signature).map_err(|e| anyhow!("release signature is malformed: {e}"))?;
    pk.verify(data, &sig, false)
        .map_err(|e| anyhow!("release signature verification failed: {e}"))
}

#[derive(Deserialize)]
pub(crate) struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Deserialize)]
pub(crate) struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

/// GitHub release-asset name for `keyhog` on a given host. Mirrors the asset
/// naming the release workflow + install.sh use. `None` for platforms without
/// a prebuilt asset.
pub(crate) fn asset_name(os: &str, arch: &str) -> Option<String> {
    match (os, arch) {
        ("linux", "x86_64") => Some("keyhog-linux-x86_64".into()),
        ("macos", "aarch64") => Some("keyhog-macos-aarch64".into()),
        ("macos", "x86_64") => Some("keyhog-macos-x86_64".into()),
        // release.yml uploads keyhog-windows-x86_64.exe; without this arm
        // `select_asset` returned None on Windows and `update`/`repair`
        // could never resolve an asset there.
        ("windows", "x86_64") => Some("keyhog-windows-x86_64.exe".into()),
        _ => None,
    }
}

/// Parse a `vMAJOR.MINOR.PATCH` (or bare) tag; pre-release/build suffixes after
/// the patch number are ignored.
pub(crate) fn parse_semver(tag: &str) -> Option<(u64, u64, u64)> {
    let t = tag.trim().trim_start_matches('v');
    let mut it = t.split('.');
    let major = it.next()?.parse().ok()?; // LAW10: non-numeric segment ⇒ parse_semver returns None (propagated via ?), the function's honest "not a semver" — caller handles None, no silent default.
    let minor = it.next()?.parse().ok()?; // LAW10: as above — fail-closed to None on a non-numeric minor segment.
    let patch_field = it.next()?;
    let patch_digits: String = patch_field
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let patch = patch_digits.parse().ok()?; // LAW10: empty/overflow patch digits ⇒ None (propagated via ?); fail-closed at the function boundary, no silent default.
    Some((major, minor, patch))
}

/// True if `latest` is a strictly newer semver than `current`. Unparseable
/// versions compare as "not newer" (fail safe: never auto-install on garbage).
pub(crate) fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_semver(current), parse_semver(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Cheap guard against installing a non-executable (404 HTML page, truncated
/// download): check the platform's executable magic bytes.
pub(crate) fn looks_like_native_executable(bytes: &[u8]) -> bool {
    looks_like_native_executable_for_os(bytes, std::env::consts::OS)
}

pub(crate) fn looks_like_native_executable_for_os(bytes: &[u8], os: &str) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    match os {
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
        "windows" => bytes.starts_with(b"MZ"),
        _ => false,
    }
}

/// An HTTP client with the keyhog User-Agent GitHub's API requires.
pub(crate) fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("keyhog/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build HTTP client")
}

/// Resolve the release to operate on. With `version`, fetch that exact tag;
/// otherwise the most recent release that actually shipped assets (a release
/// can exist with zero assets if the workflow failed mid-upload).
pub(crate) async fn resolve_release(
    client: &reqwest::Client,
    version: Option<&str>,
    release_api_base_override: Option<&str>,
) -> Result<Release> {
    let api = release_api_base(release_api_base_override);
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

/// Pick the one platform asset for this host. Runtime accelerator selection is
/// performed by backend probing and autoroute, not by release filenames.
pub(crate) fn select_asset(release: &Release) -> Result<&Asset> {
    let target = asset_name(std::env::consts::OS, std::env::consts::ARCH).ok_or_else(|| {
        anyhow!(
            "no prebuilt asset for {}-{} (supported: linux-x86_64, macos-aarch64, macos-x86_64, windows-x86_64)",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    release
        .assets
        .iter()
        .find(|a| a.name == target)
        .ok_or_else(|| {
            anyhow!(
                "release {} has no platform asset named {target}",
                release.tag_name
            )
        })
}

/// Download an asset over HTTPS, confirm it's a native executable for this
/// platform, and verify its minisign signature against the embedded release
/// public key before handing the bytes back.
pub(crate) async fn download_verified_asset(
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

    // Signature: the release `sign` job uploads `<asset>.minisig` alongside
    // each binary. Fetch and verify it. A 404 is a hard failure: refuse.
    let sig_url = format!("{}.minisig", asset.browser_download_url);
    let sig_resp = client
        .get(&sig_url)
        .send()
        .await
        .context("download release signature")?;
    if sig_resp.status() == reqwest::StatusCode::NOT_FOUND {
        // Fail CLOSED, unconditionally. A missing .minisig is indistinguishable
        // from an active attacker who serves a tampered binary and returns 404
        // for its signature. Every release is signed by the `sign` job, so a 404
        // here is a downgrade attack or a broken release; refuse either way.
        // There is deliberately NO opt-out: an ambient environment variable must
        // never be able to disable the signature gate that stands between a
        // tampered download and arbitrary code execution (config-policy mandate
        // + security). The minisign signature is the only proof.
        return Err(anyhow!(
            "release asset {} has no .minisig signature - refusing to install. A missing \
             signature can mean a tampered download intercepted the signature fetch, or a \
             broken release. Re-run the update against a properly signed release.",
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

/// End-to-end scan-engine self-test: compile a synthetic one-detector scanner,
/// plant a matching secret, and confirm it round-trips through compile -> scan
/// -> extract -> report. Uses a unique non-generic prefix so it neither
/// collides with a real detector nor trips example/placeholder suppression.
pub(crate) fn scan_engine_self_test() -> Result<bool> {
    const PLANTED: &str = "KHDOCTOR_A1b2C3d4E5f6";
    let detector = DetectorSpec {
        tests: Vec::new(),
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
    let matches = scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback);
    Ok(matches.iter().any(|m| m.credential.as_ref() == PLANTED))
}
