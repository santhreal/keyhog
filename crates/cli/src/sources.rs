//! Source factory for the KeyHog CLI.

use crate::args::ScanArgs;
#[cfg(feature = "git")]
use anyhow::Context;
use anyhow::Result;
use keyhog_core::merkle_index::MerkleIndex;
use keyhog_core::Source;
#[cfg(feature = "git")]
use std::path::PathBuf;
use std::sync::Arc;

/// Built-in exclusion patterns applied unless `--no-default-excludes` is passed.
/// These are checked against file paths BEFORE reading file content.
const DEFAULT_EXCLUDE_PATTERNS: &[&str] = &[
    "**/package-lock.json*",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.bak",
    "**/*.swp",
    "**/*.tmp",
    "**/*.map",
    "**/node_modules/**",
    "**/.git/**",
    "**/__pycache__/**",
    "**/vendor/**",
    "**/dist/**",
    "**/build/**",
    "**/out/**",
    "**/*.cache",
    "**/cache.json",
    "**/Cargo.lock",
    "**/go.sum",
    "**/Gemfile.lock",
    "**/angular.json",
    "**/tsconfig*.json",
];

/// Merge default excludes, `.keyhogignore` paths, and `--exclude-paths`.
pub fn merge_scan_ignore_paths(args: &ScanArgs, allowlist_paths: Vec<String>) -> Vec<String> {
    let mut merged = if args.no_default_excludes {
        allowlist_paths
    } else {
        let mut paths: Vec<String> = DEFAULT_EXCLUDE_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect();
        paths.extend(allowlist_paths);
        paths
    };
    if let Some(exclude) = &args.exclude_paths {
        merged.extend(exclude.iter().cloned());
    }
    merged
}

pub fn build_sources(
    args: &ScanArgs,
    ignore_paths: Vec<String>,
    merkle: Option<Arc<MerkleIndex>>,
) -> Result<Vec<Box<dyn Source>>> {
    let mut sources: Vec<Box<dyn Source>> = Vec::new();

    #[cfg(feature = "git")]
    let mut staged_files = if args.git_staged {
        get_staged_files(args.path.as_deref())?
    } else {
        Vec::new()
    };
    #[cfg(feature = "git")]
    if args.git_staged {
        filter_staged_files_by_cli_excludes(&mut staged_files, args);
    }

    let merged_ignore_paths = merge_scan_ignore_paths(args, ignore_paths);

    if let Some(ref path) = args.path {
        // Existence + readability pre-flight. The codewalk-driven
        // walker swallows missing-path and permission-denied errors as
        // per-entry warns, then declares "no findings" with exit 0.
        // Per the documented exit-code contract these are runtime
        // errors (exit 2). Catch them here so the user gets the right
        // signal. kimi-dogfood-3 #137.
        match std::fs::metadata(path) {
            Ok(meta) => {
                // Readability probe: for a regular file, try open();
                // for a directory, the walk will surface per-entry
                // permission denied warns and a missing/permission-
                // denied root directory will fail the walker init.
                if meta.is_file() {
                    if let Err(e) = std::fs::File::open(path) {
                        anyhow::bail!(
                            "cannot read '{}': {}. Fix file permissions (`chmod +r {}`) and re-run.",
                            path.display(),
                            e,
                            path.display()
                        );
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                anyhow::bail!(
                    "path '{}' does not exist. Check the spelling and re-run.",
                    path.display()
                );
            }
            Err(e) => {
                anyhow::bail!(
                    "cannot stat '{}': {}. Likely a permissions or filesystem issue.",
                    path.display(),
                    e
                );
            }
        }

        // Non-UTF-8 path pre-flight. On Unix, `PathBuf` carries raw
        // OsString bytes; codewalk stringifies the path for error
        // reporting and loses the original bytes - the user sees a
        // confusing `No such file or directory (os error 2)` from
        // `stat()` on a garbled string, even though the file exists.
        // Catch the case at CLI boundary so the message points at
        // filename encoding, not at a missing-file rabbit hole.
        // kimi-dogfood-2 #134.
        if path.exists() && path.to_str().is_none() {
            anyhow::bail!(
                "path '{}' has a non-UTF-8 filename. keyhog requires UTF-8 paths so detection \
                 output stays valid JSON. Rename the file (e.g. `convmv -f latin1 -t utf8 --notest`) \
                 or scan its parent directory instead.",
                path.display()
            );
        }
        let mut fs_source = keyhog_sources::FilesystemSource::new(path.clone())
            .with_ignore_paths(merged_ignore_paths)
            // `--no-default-excludes` must reach the walker's built-in
            // lock/minified/vendored filter, not only the glob layer above.
            .with_default_excludes(!args.no_default_excludes);
        if let Some(limit) = args.max_file_size {
            fs_source = fs_source.with_max_file_size(limit as u64);
        }
        if let Some(idx) = merkle.as_ref() {
            fs_source = fs_source.with_merkle_skip(idx.clone());
        }
        #[cfg(feature = "git")]
        if args.git_staged && !staged_files.is_empty() {
            fs_source = fs_source.with_include_paths(staged_files);
        }
        sources.push(Box::new(fs_source));
        #[cfg(feature = "binary")]
        if args.binary {
            sources.push(Box::new(keyhog_sources::BinarySource::new(path.clone())));
        }
    }

    if args.stdin {
        sources.push(Box::new(keyhog_sources::StdinSource));
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git_blobs {
        sources.push(Box::new(
            keyhog_sources::GitSource::new(path.clone()).with_max_commits(args.max_commits),
        ));
    }

    #[cfg(feature = "git")]
    if let Some(ref base_ref) = args.git_diff {
        let repo_path = args
            .git_diff_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("."));
        sources.push(Box::new(keyhog_sources::GitDiffSource::new(
            repo_path,
            base_ref.clone(),
        )));
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git_history {
        sources.push(Box::new(
            keyhog_sources::GitHistorySource::new(path.clone()).with_max_commits(args.max_commits),
        ));
    }

    // Build a fresh HttpClientConfig from the global --proxy /
    // --insecure flags, parameterized only by the per-source UA suffix.
    // Used by every network-facing source so the proxy + TLS policy
    // reaches all of them, not just WebSource.
    #[allow(unused_macros)] // some feature combos compile no consumers
    macro_rules! http_cfg {
        ($ua:expr) => {
            keyhog_sources::http::HttpClientConfig {
                proxy: args.proxy.clone(),
                insecure_tls: args.insecure,
                ua_suffix: Some(($ua).into()),
                ..Default::default()
            }
        };
    }

    #[cfg(feature = "github")]
    if let (Some(org), Some(token)) = (&args.github_org, &args.github_token) {
        sources.push(Box::new(
            keyhog_sources::GitHubOrgSource::new(org.clone(), token.clone())
                .with_http_config(http_cfg!("github-org")),
        ));
    }

    #[cfg(feature = "s3")]
    if let Some(bucket) = &args.s3_bucket {
        let mut source =
            keyhog_sources::S3Source::new(bucket.clone()).with_http_config(http_cfg!("s3"));
        if let Some(prefix) = &args.s3_prefix {
            source = source.with_prefix(prefix.clone());
        }
        if let Some(endpoint) = &args.s3_endpoint {
            source = source.with_endpoint(endpoint.clone());
        }
        sources.push(Box::new(source));
    }

    #[cfg(feature = "docker")]
    if let Some(image) = &args.docker_image {
        sources.push(Box::new(keyhog_sources::DockerImageSource::new(
            image.clone(),
        )));
    }

    #[cfg(feature = "web")]
    if let Some(urls) = &args.url {
        sources.push(Box::new(
            keyhog_sources::WebSource::new(urls.clone()).with_http_config(http_cfg!("web")),
        ));
    }

    // Dynamic sources from the global registry / plugin factory
    keyhog_sources::register_plugins();

    if let Some(ref dynamic_sources) = args.source {
        for source_spec in dynamic_sources {
            let (source_name, params) = if let Some(idx) = source_spec.find(':') {
                (&source_spec[..idx], Some(&source_spec[idx + 1..]))
            } else {
                (source_spec.as_str(), None)
            };

            match keyhog_sources::create_source(source_name, params) {
                Ok(s) => {
                    sources.push(s);
                    continue;
                }
                Err(e) if e.to_string().contains("unknown source plugin") => {
                    // Fallback to global registry for static/pre-registered sources
                }
                // `{e:#}` preserves the full anyhow source chain instead
                // of the `.to_string()` that bare `anyhow::bail!(e)` would
                // produce - operators get the whole crash trace, not just
                // the outermost message.
                Err(e) => anyhow::bail!("failed to construct source '{source_name}': {e:#}"),
            }

            if let Some(reg_source) = keyhog_core::registry::get_source_registry().get(source_name)
            {
                sources.push(Box::new(RegistrySourceBridge { inner: reg_source }));
            } else {
                anyhow::bail!(
                    "custom source '{}' not found in registry (and factory failed)",
                    source_name
                );
            }
        }
    }

    Ok(sources)
}

#[cfg(feature = "git")]
fn get_staged_files(repo_path: Option<&std::path::Path>) -> Result<Vec<PathBuf>> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-git. Resolve git to a
    // trusted absolute path; refuse $PATH lookup.
    let git_bin = keyhog_core::safe_bin::resolve_safe_bin("git")
        .ok_or_else(|| anyhow::anyhow!("git binary not found in trusted system bin dirs"))?;
    let mut cmd = std::process::Command::new(&git_bin);
    cmd.args(["diff", "--cached", "--name-only", "--diff-filter=ACM"]);
    if let Some(path) = repo_path {
        cmd.current_dir(path);
    }

    let output = cmd
        .output()
        .context("failed to run `git diff --cached --name-only --diff-filter=ACM`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git diff failed: {stderr}");
    }

    let base = repo_path
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let base = base.canonicalize().unwrap_or(base);

    let stdout = String::from_utf8(output.stdout).context("git output is not valid UTF-8")?;
    let mut files: Vec<PathBuf> = Vec::new();
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let path = base.join(line);
        if path.exists() {
            files.push(path);
        }
    }

    if files.is_empty() {
        anyhow::bail!(
            "no staged files found in {}. Stage files first with `git add <path>`, \
             or drop --git-staged to scan the working tree.",
            base.display()
        );
    }

    Ok(files)
}

#[cfg(feature = "git")]
fn filter_staged_files_by_cli_excludes(files: &mut Vec<PathBuf>, args: &ScanArgs) {
    let Some(excludes) = args.exclude_paths.as_ref() else {
        return;
    };
    let base = args
        .path
        .as_deref()
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("."));
    files.retain(|path| {
        let rel = path.strip_prefix(&base).unwrap_or(path);
        let rel = rel.to_string_lossy().replace('\\', "/");
        !excludes.iter().any(|exclude| {
            let exclude = exclude.replace('\\', "/");
            rel == exclude || rel.ends_with(&format!("/{exclude}"))
        })
    });
    if files.is_empty() {
        files.push(base.join(".keyhog-empty-staged-include-set"));
    }
}

/// Bridge to allow Arc<dyn Source> from registry to be used as Box<dyn Source>.
struct RegistrySourceBridge {
    inner: Arc<dyn keyhog_core::Source>,
}

impl keyhog_core::Source for RegistrySourceBridge {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn chunks(
        &self,
    ) -> Box<dyn Iterator<Item = Result<keyhog_core::Chunk, keyhog_core::SourceError>> + '_> {
        self.inner.chunks()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self.inner.as_any()
    }
}
