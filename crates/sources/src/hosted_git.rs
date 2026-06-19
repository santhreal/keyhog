//! Shared clone-and-scan machinery for hosted Git repository collections.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use keyhog_core::{Chunk, Source, SourceError};

use crate::FilesystemSource;

mod sanitize;
use sanitize::sanitize_git_error_message;

#[derive(Debug, Clone)]
pub(crate) struct HostedRepo {
    pub(crate) clone_dir_name: String,
    pub(crate) display_path: String,
    pub(crate) clone_url: String,
}

pub(crate) fn scan_hosted_repos(
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    token_username: &str,
    token_secret: &str,
    repos: &[HostedRepo],
) -> Result<Vec<Chunk>, SourceError> {
    use rayon::prelude::*;

    let temp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
    let temp_root = temp_dir.path().to_path_buf();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .build()
        .map_err(|e| SourceError::Other(format!("{platform}: rayon pool build failed: {e}")))?;

    let per_repo: Vec<Result<Vec<Chunk>, SourceError>> = pool.install(|| {
        repos
            .par_iter()
            .map(|repo| -> Result<Vec<Chunk>, SourceError> {
                validate_repo_name(platform, &repo.clone_dir_name)?;
                validate_display_path(platform, &repo.display_path)?;
                validate_clone_url(platform, &repo.clone_url)?;
                let clone_path = temp_root.join(&repo.clone_dir_name);
                clone_repo(
                    platform,
                    &repo.display_path,
                    &repo.clone_url,
                    token_username,
                    token_secret,
                    &clone_path,
                )?;
                scan_repo(
                    platform,
                    source_type,
                    namespace,
                    &repo.display_path,
                    &clone_path,
                )
            })
            .collect()
    });

    let mut chunks = Vec::new();
    for result in per_repo {
        chunks.extend(result?);
    }
    Ok(chunks)
}

/// Refuse repo directory names that escape the temp clone root: `..`, absolute
/// paths, path separators, or characters outside the forge repo-name alphabet.
pub(crate) fn validate_repo_name(platform: &str, name: &str) -> Result<(), SourceError> {
    if name.is_empty() || name.len() > 100 {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repo with out-of-range name length ({})",
            name.len()
        )));
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repo with traversal/separator in name: {name:?}"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repo with non-alphanumeric name: {name:?}"
        )));
    }
    Ok(())
}

/// Validate a slash-separated forge display path before it is copied into
/// finding paths. This may contain subgroup/project separators, but each segment
/// must still be a normal repo-name component.
pub(crate) fn validate_display_path(platform: &str, path: &str) -> Result<(), SourceError> {
    if path.is_empty() || path.len() > 512 || path.starts_with('/') || path.ends_with('/') {
        return Err(SourceError::Other(format!(
            "{platform}: refusing repository display path with invalid length or slash placement: {path:?}"
        )));
    }
    for segment in path.split('/') {
        validate_repo_name(platform, segment)?;
    }
    Ok(())
}

/// Refuse clone URLs that git would interpret as anything other than HTTPS.
pub(crate) fn validate_clone_url(platform: &str, url: &str) -> Result<(), SourceError> {
    if !url.starts_with("https://") {
        return Err(SourceError::Other(format!(
            "{platform}: refusing non-https clone URL (potential ext::/ssh:// RCE vector): {url:?}"
        )));
    }
    if url.contains(' ') || url.contains('\n') || url.contains('\r') || url.contains('\0') {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL with control characters: {url:?}"
        )));
    }
    if url.len() > 2048 {
        return Err(SourceError::Other(format!(
            "{platform}: refusing clone URL longer than 2048 chars ({})",
            url.len()
        )));
    }
    Ok(())
}

pub(crate) fn listing_truncated_error(
    platform: &str,
    owner_kind: &str,
    owner_name: &str,
    repo_count: usize,
    max_pages: usize,
) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::SourceTruncated);
    SourceError::Other(format!(
        "{platform} {owner_kind} repository listing for {owner_name} exceeded {max_pages} pages \
         ({repo_count} repositories); refusing to scan a partial {owner_kind} repository collection \
         because unseen repositories would be reported clean"
    ))
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
pub(crate) fn validated_api_endpoint(
    platform: &str,
    endpoint: &str,
) -> Result<reqwest::Url, SourceError> {
    let url = reqwest::Url::parse(endpoint).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: invalid API endpoint {endpoint:?}: {error}"
        ))
    })?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(SourceError::Other(format!(
            "{platform}: API endpoint must not include query or fragment: {endpoint:?}"
        )));
    }
    match url.scheme() {
        "https" => Ok(url),
        "http" if url.host_str().is_some_and(is_loopback_host) => Ok(url),
        scheme => Err(SourceError::Other(format!(
            "{platform}: refusing {scheme:?} API endpoint {endpoint:?}; use https, or loopback http only for local tests"
        ))),
    }
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
pub(crate) fn require_same_api_origin(
    platform: &str,
    base: &reqwest::Url,
    candidate: &reqwest::Url,
) -> Result<(), SourceError> {
    if base.scheme() == candidate.scheme()
        && base.host_str() == candidate.host_str()
        && base.port_or_known_default() == candidate.port_or_known_default()
    {
        return Ok(());
    }
    Err(SourceError::Other(format!(
        "{platform}: refusing pagination URL outside configured API origin: {candidate}"
    )))
}

pub(crate) fn scan_repo_chunks<I>(
    input_chunks: I,
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
) -> Result<Vec<Chunk>, SourceError>
where
    I: IntoIterator<Item = Result<Chunk, SourceError>>,
{
    let mut rewritten = Vec::new();

    for chunk in input_chunks.into_iter() {
        match chunk {
            Ok(chunk) => rewritten.push(rewrite_chunk_path(
                chunk,
                platform,
                source_type,
                namespace,
                repo_display_path,
                clone_path,
            )?),
            Err(error) => {
                return Err(SourceError::Other(format!(
                    "{platform}: failed to scan cloned repo {repo_display_path}: {error}"
                )));
            }
        }
    }

    Ok(rewritten)
}

pub(crate) fn rewrite_chunk_path(
    mut chunk: Chunk,
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
) -> Result<Chunk, SourceError> {
    let source_path = chunk.metadata.path.as_deref().ok_or_else(|| {
        SourceError::Other(format!(
            "{platform}: cloned repo {repo_display_path} produced a chunk without a file path"
        ))
    })?;
    let relative_path = make_relative_path(platform, source_path, clone_path)?;

    chunk.metadata.source_type = source_type.into();
    chunk.metadata.path = Some(match namespace {
        Some(namespace) if !namespace.is_empty() => {
            format!("{namespace}/{repo_display_path}/{relative_path}")
        }
        _ => format!("{repo_display_path}/{relative_path}"),
    });
    chunk.metadata.commit = None;
    chunk.metadata.author = None;
    chunk.metadata.date = None;

    Ok(chunk)
}

fn clone_repo(
    platform: &str,
    repo_display_path: &str,
    clone_url: &str,
    token_username: &str,
    token_secret: &str,
    clone_path: &Path,
) -> Result<(), SourceError> {
    let clone_target = clone_path.to_str().ok_or_else(|| {
        SourceError::Other(format!(
            "{platform}: non-UTF-8 clone path for repo {repo_display_path}"
        ))
    })?;
    let auth_material = GitAskpassAuth::create(platform, token_username, token_secret)?;

    let git_bin = keyhog_core::resolve_safe_bin("git").ok_or_else(|| {
        SourceError::Other(
            "git binary not found in trusted system bin dirs (refusing $PATH lookup)".into(),
        )
    })?;
    let child = Command::new(&git_bin)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", &auth_material.askpass_path)
        .env("SSH_ASKPASS", &auth_material.askpass_path)
        .args(["clone", "--depth", "1", "--quiet"])
        .arg("--end-of-options")
        .arg(clone_url)
        .arg(clone_target)
        .spawn()
        .map_err(SourceError::Io)?;

    let output = wait_for_command_with_timeout(child, crate::timeouts::GIT_CLONE)
        .map_err(|err| SourceError::Git(format!("failed to clone {repo_display_path}: {err}")))?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "failed to clone {repo_display_path}: {}",
            sanitize_git_error_message(&String::from_utf8_lossy(&output.stderr))
        )));
    }

    Ok(())
}

fn scan_repo(
    platform: &str,
    source_type: &str,
    namespace: Option<&str>,
    repo_display_path: &str,
    clone_path: &Path,
) -> Result<Vec<Chunk>, SourceError> {
    let source = FilesystemSource::new(clone_path.to_path_buf());
    scan_repo_chunks(
        source.chunks(),
        platform,
        source_type,
        namespace,
        repo_display_path,
        clone_path,
    )
}

fn make_relative_path(
    platform: &str,
    path: &str,
    clone_path: &Path,
) -> Result<String, SourceError> {
    let raw_path = Path::new(path);
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        clone_path.join(raw_path)
    };
    let normalized_path = std::fs::canonicalize(&candidate).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: cannot canonicalize cloned repo chunk path {}: {error}",
            candidate.display()
        ))
    })?;
    let normalized_clone_path = std::fs::canonicalize(clone_path).map_err(|error| {
        SourceError::Other(format!(
            "{platform}: cannot canonicalize cloned repo root {}: {error}",
            clone_path.display()
        ))
    })?;
    let relative = normalized_path
        .strip_prefix(&normalized_clone_path)
        .map_err(|_| {
            SourceError::Other(format!(
                "{platform}: cloned repo chunk path {} is outside clone root {}",
                normalized_path.display(),
                normalized_clone_path.display()
            ))
        })?
        .to_path_buf();
    Ok(relative.to_string_lossy().into_owned())
}

fn wait_for_command_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return child.wait_with_output().map_err(|e| e.to_string());
        }

        if start.elapsed() >= timeout {
            child.kill().map_err(|e| e.to_string())?;
            child.wait().map_err(|e| e.to_string())?;
            return Err(format!("git clone timed out after {}s", timeout.as_secs()));
        }

        thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Debug)]
struct GitAskpassAuth {
    _dir: tempfile::TempDir,
    askpass_path: PathBuf,
}

impl GitAskpassAuth {
    fn create(platform: &str, username: &str, secret: &str) -> Result<Self, SourceError> {
        validate_auth_part(platform, "username", username)?;
        validate_auth_part(platform, "token", secret)?;

        let dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let username_path = dir.path().join("username");
        let token_path = dir.path().join("token");
        write_secret_file(&username_path, username.as_bytes())?;
        write_secret_file(&token_path, secret.as_bytes())?;

        let askpass_path = if cfg!(unix) {
            let path = dir.path().join("askpass.sh");
            write_askpass_file(
                &path,
                b"#!/bin/sh\nset -eu\nDIR=\"$(dirname \"$0\")\"\ncase \"$1\" in\n*Username*) exec cat -- \"$DIR/username\" ;;\n*) exec cat -- \"$DIR/token\" ;;\nesac\n",
            )?;
            path
        } else {
            let path = dir.path().join("askpass.bat");
            let content = format!(
                "@echo off\r\necho %1 | findstr /I \"Username\" >nul\r\nif %errorlevel% == 0 (\r\n  type \"{}\"\r\n) else (\r\n  type \"{}\"\r\n)\r\n",
                username_path.display(),
                token_path.display()
            );
            write_askpass_file(&path, content.as_bytes())?;
            path
        };

        Ok(Self {
            _dir: dir,
            askpass_path,
        })
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    write_private_file(path, bytes, 0o600)
}

fn write_askpass_file(path: &Path, bytes: &[u8]) -> Result<(), SourceError> {
    write_private_file(path, bytes, 0o700)
}

fn write_private_file(
    path: &Path,
    bytes: &[u8],
    #[cfg_attr(not(unix), allow(unused_variables))] unix_mode: u32,
) -> Result<(), SourceError> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(unix_mode);
    }

    let mut file = options.open(path).map_err(SourceError::Io)?;
    file.write_all(bytes).map_err(SourceError::Io)
}

fn validate_auth_part(platform: &str, label: &str, value: &str) -> Result<(), SourceError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(SourceError::Other(format!(
            "{platform}: {label} contains unsafe characters"
        )));
    }
    Ok(())
}

#[cfg(any(feature = "gitlab", feature = "bitbucket"))]
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}
