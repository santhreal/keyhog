//! Source factory for the KeyHog CLI.

use crate::args::ScanArgs;
use anyhow::{Context, Result};
use keyhog_core::Source;
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

pub fn build_sources(args: &ScanArgs, ignore_paths: Vec<String>) -> Result<Vec<Box<dyn Source>>> {
    let mut sources: Vec<Box<dyn Source>> = Vec::new();

    #[cfg(feature = "git")]
    let staged_files = if args.git_staged {
        get_staged_files(args.path.as_deref())?
    } else {
        Vec::new()
    };

    let merged_ignore_paths = if args.no_default_excludes {
        ignore_paths
    } else {
        let mut merged: Vec<String> = DEFAULT_EXCLUDE_PATTERNS
            .iter()
            .map(|s| s.to_string())
            .collect();
        merged.extend(ignore_paths);
        merged
    };

    if let Some(ref path) = args.path {
        let mut fs_source = keyhog_sources::FilesystemSource::new(path.clone())
            .with_ignore_paths(merged_ignore_paths);
        if let Some(limit) = args.max_file_size {
            fs_source = fs_source.with_max_file_size(limit as u64);
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

    #[cfg(feature = "github")]
    if let (Some(org), Some(token)) = (&args.github_org, &args.github_token) {
        sources.push(Box::new(keyhog_sources::GitHubOrgSource::new(
            org.clone(),
            token.clone(),
        )));
    }

    #[cfg(feature = "s3")]
    if let Some(bucket) = &args.s3_bucket {
        let mut source = keyhog_sources::S3Source::new(bucket.clone());
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
        sources.push(Box::new(keyhog_sources::WebSource::new(urls.clone())));
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
                Err(e) => anyhow::bail!(e),
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
        anyhow::bail!("no staged files found");
    }

    Ok(files)
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
