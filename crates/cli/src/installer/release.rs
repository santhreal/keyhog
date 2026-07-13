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
use std::time::Duration;

pub(crate) const REPO: &str = "santhreal/keyhog";
const RELEASE_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const RELEASE_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_RELEASE_METADATA_BYTES: usize = 8 * 1024 * 1024;
const MAX_RELEASE_ASSET_BYTES: usize = 512 * 1024 * 1024;
const MAX_RELEASE_SIGNATURE_BYTES: usize = 64 * 1024;
const MAX_RELEASE_CHECKSUM_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_PREALLOC_BYTES: usize = 64 * 1024;

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

#[derive(Clone, Deserialize)]
pub(crate) struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Clone, Deserialize)]
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

pub(crate) fn parse_version(tag: &str) -> Option<semver::Version> {
    let trimmed = tag.trim();
    let value = trimmed.strip_prefix('v').unwrap_or(trimmed); // LAW10: intentional alternate spelling; an absent v prefix means parse the original tag unchanged
    semver::Version::parse(value).ok() // LAW10: malformed input returns None and fails closed because an invalid release tag is never selected
}

/// Parse the numeric core of a strict semantic version. Kept as the compact
/// tuple facade used by existing diagnostics/tests; ordering uses
/// [`parse_version`] so prerelease precedence is never discarded.
pub(crate) fn parse_semver(tag: &str) -> Option<(u64, u64, u64)> {
    let version = parse_version(tag)?;
    Some((version.major, version.minor, version.patch))
}

/// True if `latest` is a strictly newer semver than `current`. Unparseable
/// versions compare as "not newer" (fail safe: never auto-install on garbage).
pub(crate) fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) => l.cmp_precedence(&c).is_gt(),
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
        .connect_timeout(RELEASE_CONNECT_TIMEOUT)
        .timeout(RELEASE_REQUEST_TIMEOUT)
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
        let response = client.get(&url).send().await.context("query release tag")?;
        let bytes = read_limited_response(
            response,
            MAX_RELEASE_METADATA_BYTES,
            &format!("release tag {tag}"),
        )
        .await?;
        let release: Release = serde_json::from_slice(&bytes).context("parse release JSON")?;
        if release.draft {
            anyhow::bail!("release tag {tag} is still a draft and cannot be installed");
        }
        return Ok(release);
    }
    let url = format!("{api}/repos/{REPO}/releases?per_page=10");
    let response = client.get(&url).send().await.context("query releases")?;
    let bytes = read_limited_response(response, MAX_RELEASE_METADATA_BYTES, "release list").await?;
    let releases: Vec<Release> = serde_json::from_slice(&bytes).context("parse releases JSON")?;
    releases
        .into_iter()
        .find(|release| {
            !release.draft && !release.prerelease && release_has_complete_host_bundle(release)
        })
        .ok_or_else(|| {
            anyhow!(
                "no recent stable GitHub release has the complete signed asset bundle for this host; pass --version to diagnose an exact tag"
            )
        })
}

fn release_has_complete_host_bundle(release: &Release) -> bool {
    let Some(binary) = asset_name(std::env::consts::OS, std::env::consts::ARCH) else {
        return false;
    };
    let required = [
        binary.clone(),
        format!("{binary}.sha256"),
        format!("{binary}.minisig"),
        format!("{binary}.gpu-literals.tar.gz"),
        format!("{binary}.gpu-literals.tar.gz.sha256"),
        format!("{binary}.gpu-literals.tar.gz.minisig"),
    ];
    required
        .iter()
        .all(|name| find_unique_asset(release, name).is_ok())
}

fn find_unique_asset<'a>(release: &'a Release, name: &str) -> Result<&'a Asset> {
    let mut matches = release.assets.iter().filter(|asset| asset.name == name);
    let asset = matches
        .next()
        .ok_or_else(|| anyhow!("release {} has no asset named {name}", release.tag_name))?;
    if matches.next().is_some() {
        anyhow::bail!(
            "release {} contains duplicate assets named {name}; refusing ambiguous release metadata",
            release.tag_name
        );
    }
    Ok(asset)
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
    find_unique_asset(release, &target)
}

pub(crate) fn select_gpu_literal_asset<'a>(
    release: &'a Release,
    binary: &Asset,
) -> Result<&'a Asset> {
    find_unique_asset(release, &format!("{}.gpu-literals.tar.gz", binary.name))
}

/// Download an asset over HTTPS, confirm it is a native executable for this
/// platform, and verify both its detached minisign signature and exact
/// release-manifest SHA-256 entry before handing the bytes back.
pub(crate) async fn download_verified_asset(
    client: &reqwest::Client,
    release: &Release,
    asset: &Asset,
) -> Result<Vec<u8>> {
    let bytes = download_verified_payload(
        client,
        release,
        asset,
        MAX_RELEASE_ASSET_BYTES,
        "release asset",
    )
    .await?;
    if !looks_like_native_executable(&bytes) {
        return Err(anyhow!(
            "downloaded asset is not a {} executable ({} bytes) - refusing to install. \
             The release asset may be missing or the download was intercepted.",
            std::env::consts::OS,
            bytes.len()
        ));
    }

    Ok(bytes)
}

pub(crate) async fn download_verified_gpu_literal_asset(
    client: &reqwest::Client,
    release: &Release,
    asset: &Asset,
) -> Result<Vec<u8>> {
    download_verified_payload(
        client,
        release,
        asset,
        MAX_RELEASE_ASSET_BYTES,
        "GPU literal sidecar",
    )
    .await
}

async fn download_verified_payload(
    client: &reqwest::Client,
    release: &Release,
    asset: &Asset,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("download {label} {}", asset.name))?;
    let bytes = read_limited_response(response, max_bytes, label).await?;

    // Signature: the release `sign` job uploads `<asset>.minisig` alongside
    // each binary and sidecar. Fetch and verify it. A 404 is a hard failure.
    let signature_name = format!("{}.minisig", asset.name);
    let signature_asset = find_unique_asset(release, &signature_name)?;
    let sig_resp = client
        .get(&signature_asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("download release signature {signature_name}"))?;
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
    let sig_bytes =
        read_limited_response(sig_resp, MAX_RELEASE_SIGNATURE_BYTES, "release signature").await?;
    let sig_text = std::str::from_utf8(&sig_bytes).context("release signature is not UTF-8")?;
    verify_release_signature(&bytes, &sig_text)
        .with_context(|| format!("verifying release asset {}", asset.name))?;

    let checksum_name = format!("{}.sha256", asset.name);
    let checksum_asset = find_unique_asset(release, &checksum_name)?;
    let checksum_response = client
        .get(&checksum_asset.browser_download_url)
        .send()
        .await
        .with_context(|| format!("download release checksum {checksum_name}"))?;
    let checksum_bytes = read_limited_response(
        checksum_response,
        MAX_RELEASE_CHECKSUM_BYTES,
        "release checksum",
    )
    .await?;
    verify_release_checksum(&bytes, &asset.name, &checksum_bytes)?;
    Ok(bytes)
}

pub(crate) fn verify_release_checksum(
    data: &[u8],
    asset_name: &str,
    checksum_file: &[u8],
) -> Result<()> {
    use sha2::{Digest as _, Sha256};

    let text = std::str::from_utf8(checksum_file).context("release checksum is not UTF-8")?;
    let mut fields = text.split_whitespace();
    let expected = fields
        .next()
        .ok_or_else(|| anyhow!("release checksum for {asset_name} is empty"))?;
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("release checksum for {asset_name} is not a 64-digit SHA-256 digest");
    }
    if let Some(label) = fields.next() {
        let label = label.strip_prefix('*').unwrap_or(label); // LAW10: optional binary-mode `*` prefix; the same filename label is validated below
        if label != asset_name {
            anyhow::bail!(
                "release checksum labels `{label}` but payload is `{asset_name}`; refusing mismatched manifest"
            );
        }
    }
    if fields.next().is_some() {
        anyhow::bail!("release checksum for {asset_name} contains unexpected trailing fields");
    }
    let actual = keyhog_core::hex_encode(&Sha256::digest(data));
    if !actual.eq_ignore_ascii_case(expected) {
        anyhow::bail!(
            "release checksum mismatch for {asset_name}: expected {expected}, calculated {actual}"
        );
    }
    Ok(())
}

async fn read_limited_response(
    response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    use futures_util::StreamExt as _;

    let response = response
        .error_for_status()
        .with_context(|| format!("{label} HTTP status"))?;
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        anyhow::bail!("{label} exceeds the {max_bytes}-byte download limit");
    }
    let capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok()) // LAW10: perf-only allocation hint; streamed byte counting below enforces the hard response limit
        .map_or(0, |length| length.min(MAX_RESPONSE_PREALLOC_BYTES));
    let mut body = Vec::with_capacity(capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read {label} body"))?;
        if body.len().saturating_add(chunk.len()) > max_bytes {
            anyhow::bail!("{label} exceeds the {max_bytes}-byte download limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
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
