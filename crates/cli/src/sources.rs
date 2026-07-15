//! Source factory for the KeyHog CLI.

use crate::args::ScanArgs;
use crate::orchestrator_config::ResolvedScanConfig;
use anyhow::{Context, Result};
use keyhog_core::MerkleIndex;
use keyhog_core::Source;
#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
use std::borrow::Cow;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

/// Resolve a hosted-source credential without letting ambient environment
/// variables select a source. Callers invoke this only after the operator has
/// explicitly selected the corresponding organization/group/workspace.
#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
#[derive(Clone, Copy)]
enum HostedCredentialEnv {
    #[cfg(feature = "github")]
    GithubToken,
    #[cfg(feature = "gitlab")]
    GitlabToken,
    #[cfg(feature = "bitbucket")]
    BitbucketUsername,
    #[cfg(feature = "bitbucket")]
    BitbucketToken,
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
impl HostedCredentialEnv {
    fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "github")]
            Self::GithubToken => "KEYHOG_GITHUB_TOKEN",
            #[cfg(feature = "gitlab")]
            Self::GitlabToken => "KEYHOG_GITLAB_TOKEN",
            #[cfg(feature = "bitbucket")]
            Self::BitbucketUsername => "KEYHOG_BITBUCKET_USERNAME",
            #[cfg(feature = "bitbucket")]
            Self::BitbucketToken => "KEYHOG_BITBUCKET_TOKEN",
        }
    }

    fn read(self) -> Option<std::ffi::OsString> {
        match self {
            #[cfg(feature = "github")]
            Self::GithubToken => std::env::var_os("KEYHOG_GITHUB_TOKEN"),
            #[cfg(feature = "gitlab")]
            Self::GitlabToken => std::env::var_os("KEYHOG_GITLAB_TOKEN"),
            #[cfg(feature = "bitbucket")]
            Self::BitbucketUsername => std::env::var_os("KEYHOG_BITBUCKET_USERNAME"),
            #[cfg(feature = "bitbucket")]
            Self::BitbucketToken => std::env::var_os("KEYHOG_BITBUCKET_TOKEN"),
        }
    }
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
fn hosted_source_credential<'a>(
    cli_value: Option<&'a str>,
    env: HostedCredentialEnv,
) -> Result<Option<Cow<'a, str>>> {
    let env_name = env.name();
    if let Some(value) = cli_value {
        anyhow::ensure!(
            !value.is_empty(),
            "{env_name} / CLI credential cannot be empty"
        );
        return Ok(Some(Cow::Borrowed(value)));
    }

    let Some(value) = env.read() else {
        return Ok(None);
    };
    let value = value.into_string().map_err(|_| {
        anyhow::anyhow!(
            "{env_name} is not valid UTF-8. Fix: replace it with the provider credential text."
        )
    })?;
    anyhow::ensure!(
        !value.is_empty(),
        "{env_name} is empty. Fix: set it to the provider credential or unset it and pass the matching token flag."
    );
    Ok(Some(Cow::Owned(value)))
}

/// Merge `.keyhogignore` paths and `--exclude-paths`.
///
/// Default excludes are owned by `keyhog_sources::FilesystemSource` so the
/// actual scanner path, not a CLI glob mirror, decides what is skipped and
/// records the surfaced skip reason.
pub(crate) fn merge_scan_ignore_paths(
    exclude_paths: &[String],
    allowlist_paths: Vec<String>,
) -> Vec<String> {
    let mut merged = allowlist_paths;
    merged.extend(exclude_paths.iter().cloned());
    merged
}

#[cfg(any(
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "s3",
    feature = "gcs",
    feature = "azure"
))]
fn source_http_config(args: &ScanArgs, ua_suffix: &str) -> keyhog_sources::http::HttpClientConfig {
    keyhog_sources::http::HttpClientConfig {
        proxy: args.proxy.clone(),
        insecure_tls: args.insecure,
        allow_private_endpoint: args.allow_private_cloud_endpoint,
        ua_suffix: Some(ua_suffix.to_owned()),
        ..Default::default()
    }
}

#[cfg(not(any(
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "s3",
    feature = "gcs",
    feature = "azure"
)))]
fn source_http_config(_args: &ScanArgs, ua_suffix: &str) -> keyhog_sources::http::HttpClientConfig {
    keyhog_sources::http::HttpClientConfig {
        ua_suffix: Some(ua_suffix.to_owned()),
        ..Default::default()
    }
}

/// Validate, then de-overlap, the requested filesystem scan roots.
///
/// Every root is first validated as a CLI path argument and canonicalized. A
/// root is then folded away when it is an exact duplicate of an earlier root or
/// nested inside another requested root: that subtree is already walked
/// recursively by its covering parent, so keeping it would double-report every
/// file under it. Exact duplicates keep their first occurrence; a nested root is
/// always absorbed by its ancestor regardless of argument order. Folds are
/// announced on stderr, never silent (Law 10), and the surviving roots are
/// returned in first-seen order so finding output stays deterministic. An empty
/// request yields an empty result (the caller then builds no filesystem source,
/// exactly as a path-less `--stdin`/remote-only scan expects).
pub(crate) fn resolve_scan_roots(requested: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if requested.is_empty() {
        return Ok(Vec::new());
    }
    for root in requested {
        crate::path_validation::validate_cli_path_arg(root, "scan path")?;
    }
    let canonical: Vec<PathBuf> = requested
        .iter()
        .map(|root| {
            root.canonicalize().with_context(|| {
                format!(
                    "canonicalize scan root {} for overlap detection",
                    root.display()
                )
            })
        })
        .collect::<Result<_>>()?;

    let mut kept: Vec<PathBuf> = Vec::new();
    let mut folded: Vec<(PathBuf, PathBuf)> = Vec::new();
    'roots: for i in 0..requested.len() {
        for j in 0..requested.len() {
            if i == j {
                continue;
            }
            let earlier_duplicate = canonical[i] == canonical[j] && j < i;
            let nested_in_other =
                canonical[i] != canonical[j] && canonical[i].starts_with(&canonical[j]);
            if earlier_duplicate || nested_in_other {
                folded.push((requested[i].clone(), requested[j].clone()));
                continue 'roots;
            }
        }
        kept.push(requested[i].clone());
    }

    if !folded.is_empty() {
        let palette = crate::style::for_stderr();
        for (child, parent) in &folded {
            eprintln!(
                "{}: folding overlapping scan root {} into {} (already walked recursively)",
                crate::style::warn("keyhog", &palette),
                child.display(),
                parent.display(),
            );
        }
    }
    Ok(kept)
}

pub(crate) fn build_sources(
    args: &ScanArgs,
    resolved: &ResolvedScanConfig,
    ignore_paths: Vec<String>,
    merkle: Option<Arc<MerkleIndex>>,
) -> Result<Vec<Box<dyn Source>>> {
    let mut sources: Vec<Box<dyn Source>> = Vec::new();
    let source_limits = resolved.source_limits;
    let requested_roots = args.scan_roots();
    #[cfg(feature = "git")]
    let scan_path = requested_roots.first();
    validate_source_flag_combinations(args, !requested_roots.is_empty())?;

    let merged_ignore_paths = merge_scan_ignore_paths(&resolved.exclude_paths, ignore_paths);

    #[cfg(feature = "git")]
    let use_staged_source = args.git_staged;

    #[cfg(not(feature = "git"))]
    let use_staged_source = false;

    if use_staged_source {
        #[cfg(feature = "git")]
        {
            let repo = scan_path.cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "--git-staged requires a repository path. Fix: run inside a repository or pass its path."
                )
            })?;
            sources.push(Box::new(
                keyhog_sources::GitStagedSource::try_new(repo)
                    .map_err(|error| {
                        anyhow::anyhow!("--git-staged input validation failed: {error}")
                    })?
                    .with_ignore_paths(merged_ignore_paths.clone())
                    .with_default_excludes(!resolved.no_default_excludes)
                    .with_limits(source_limits),
            ));
        }
    } else {
        // Each requested root becomes its own filesystem source, the scan
        // engine already merges this `Vec<Box<dyn Source>>`, so multi-root
        // (`keyhog scan a/ b/ c/`) needs no engine change. Overlapping/nested
        // roots are folded into their covering parent (loudly) so a subtree is
        // never walked twice.
        let roots = resolve_scan_roots(&requested_roots)?;
        for root in &roots {
            let mut fs_source = keyhog_sources::FilesystemSource::new(root.clone())
                .with_ignore_paths(merged_ignore_paths.clone())
                // Default excludes are source-owned. `--no-default-excludes` must
                // toggle the actual file classifier, not a CLI-side glob mirror.
                .with_default_excludes(!resolved.no_default_excludes);
            if let Some(limit) = resolved.max_file_size {
                fs_source = fs_source.with_max_file_size(limit as u64);
            }
            if let Some(threads) = resolved.reader_threads.and_then(NonZeroUsize::new) {
                fs_source = fs_source.with_reader_threads(threads);
            }
            if let Some(idx) = merkle.as_ref() {
                fs_source = fs_source.with_merkle_skip(idx.clone());
            }
            sources.push(Box::new(fs_source));
            #[cfg(feature = "binary")]
            if args.binary {
                sources.push(Box::new(
                    keyhog_sources::BinarySource::new(root.clone()).with_limits(source_limits),
                ));
            }
        }
    }

    if args.stdin {
        if let Some(bytes) = args.buffered_stdin.clone() {
            sources.push(Box::new(
                keyhog_sources::BufferedStdinSource::new(bytes).with_limits(source_limits),
            ));
        } else {
            sources.push(Box::new(
                keyhog_sources::StdinSource.with_limits(source_limits),
            ));
        }
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git_blobs {
        sources.push(Box::new(
            keyhog_sources::GitSource::new(path.clone())
                .with_max_commits(resolved.max_commits)
                .with_default_excludes(!resolved.no_default_excludes)
                .with_limits(source_limits),
        ));
    }

    #[cfg(feature = "git")]
    if let Some(ref base_ref) = args.git_diff {
        let repo_path = args
            .git_diff_path
            .clone()
            .unwrap_or_else(|| PathBuf::from(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
        sources.push(Box::new(
            keyhog_sources::GitDiffSource::new(repo_path, base_ref.clone())
                .with_default_excludes(!resolved.no_default_excludes)
                .with_limits(source_limits),
        ));
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git_history {
        sources.push(Box::new(
            keyhog_sources::GitHistorySource::new(path.clone())
                .with_max_commits(resolved.max_commits)
                .with_default_excludes(!resolved.no_default_excludes)
                .with_limits(source_limits),
        ));
    }

    #[cfg(feature = "github")]
    if let Some(org) = &args.github_org {
        let token = hosted_source_credential(
            args.github_token.as_deref(),
            HostedCredentialEnv::GithubToken,
        )?
        .context("GitHub organization source requires --github-token or KEYHOG_GITHUB_TOKEN")?;
        let params = format!("{org}\n{token}");
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "github-org",
                Some(&params),
                source_http_config(args, "github-org"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    #[cfg(feature = "github")]
    if let Some(repository) = &args.github_collaboration {
        let token = hosted_source_credential(
            args.github_token.as_deref(),
            HostedCredentialEnv::GithubToken,
        )?
        .context("GitHub collaboration source requires --github-token or KEYHOG_GITHUB_TOKEN")?;
        let selection = keyhog_sources::GitHubCollaborationSelection {
            issues: args.github_issues,
            pull_requests: args.github_pull_requests,
            discussions: args.github_discussions,
            wiki: args.github_wiki,
            gists: args.github_gists,
        };
        sources.push(Box::new(
            keyhog_sources::GitHubCollaborationSource::new(repository, token, selection)?
                .with_http_config(source_http_config(args, "github-collaboration"))
                .with_limits(source_limits),
        ));
    }

    #[cfg(feature = "gitlab")]
    if let Some(group) = &args.gitlab_group {
        let token = hosted_source_credential(
            args.gitlab_token.as_deref(),
            HostedCredentialEnv::GitlabToken,
        )?
        .context("GitLab group source requires --gitlab-token or KEYHOG_GITLAB_TOKEN")?;
        let params = format!("{group}\n{token}\n{}", args.gitlab_endpoint);
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "gitlab-group",
                Some(&params),
                source_http_config(args, "gitlab-group"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    #[cfg(feature = "bitbucket")]
    if let Some(workspace) = &args.bitbucket_workspace {
        let username = hosted_source_credential(
            args.bitbucket_username.as_deref(),
            HostedCredentialEnv::BitbucketUsername,
        )?
        .context(
            "Bitbucket workspace source requires --bitbucket-username or KEYHOG_BITBUCKET_USERNAME",
        )?;
        let token = hosted_source_credential(
            args.bitbucket_token.as_deref(),
            HostedCredentialEnv::BitbucketToken,
        )?
        .context(
            "Bitbucket workspace source requires --bitbucket-token or KEYHOG_BITBUCKET_TOKEN",
        )?;
        let params = format!(
            "{workspace}\n{username}\n{token}\n{}",
            args.bitbucket_endpoint
        );
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "bitbucket-workspace",
                Some(&params),
                source_http_config(args, "bitbucket-workspace"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    #[cfg(feature = "s3")]
    if let Some(bucket) = &args.s3_bucket {
        if args.allow_s3_credential_forward {
            eprintln!(
                "warning: --allow-s3-credential-forward is active; ambient AWS credentials may be sent to the configured non-AWS S3 endpoint"
            );
        }
        let s3_prefix = match args.s3_prefix.as_deref() {
            Some(prefix) => prefix,
            None => "",
        };
        let s3_endpoint = match args.s3_endpoint.as_deref() {
            Some(endpoint) => endpoint,
            None => "",
        };
        let params = format!(
            "{bucket}\n{}\n{}\n{}",
            s3_prefix, s3_endpoint, args.allow_s3_credential_forward
        );
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "s3",
                Some(&params),
                source_http_config(args, "s3"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    #[cfg(feature = "gcs")]
    if let Some(bucket) = &args.gcs_bucket {
        if args.allow_gcs_token_forward {
            eprintln!(
                "warning: --allow-gcs-token-forward is active; ambient GCS bearer tokens may be sent to the configured non-Google GCS endpoint"
            );
        }
        let gcs_prefix = match args.gcs_prefix.as_deref() {
            Some(prefix) => prefix,
            None => "",
        };
        let gcs_endpoint = match args.gcs_endpoint.as_deref() {
            Some(endpoint) => endpoint,
            None => "",
        };
        let params = format!(
            "{bucket}\n{}\n{}\n{}",
            gcs_prefix, gcs_endpoint, args.allow_gcs_token_forward
        );
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "gcs",
                Some(&params),
                source_http_config(args, "gcs"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    #[cfg(feature = "azure")]
    if let Some(container_url) = &args.azure_container_url {
        let azure_prefix = match args.azure_prefix.as_deref() {
            Some(prefix) => prefix,
            None => "",
        };
        let params = format!("{container_url}\n{azure_prefix}");
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "azure_blob",
                Some(&params),
                source_http_config(args, "azure-blob"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    #[cfg(feature = "docker")]
    if let Some(image) = &args.docker_image {
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "docker",
                Some(image),
                source_http_config(args, "docker"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    #[cfg(feature = "web")]
    if let Some(urls) = &args.url {
        let params = if args.autoroute_calibrate {
            format!("autoroute_loopback_calibration=true\n{}", urls.join("\n"))
        } else {
            urls.join("\n")
        };
        sources.push(
            keyhog_sources::create_source_with_http_config_limits_and_policy(
                "web",
                Some(&params),
                source_http_config(args, "web"),
                source_limits,
                !resolved.no_default_excludes,
            )?,
        );
    }

    if let Some(ref dynamic_sources) = args.source {
        for source_spec in dynamic_sources {
            let (source_name, params) = if let Some(idx) = source_spec.find(':') {
                (&source_spec[..idx], Some(&source_spec[idx + 1..]))
            } else {
                (source_spec.as_str(), None)
            };

            match keyhog_sources::create_source_with_http_config_limits_and_policy(
                source_name,
                params,
                source_http_config(args, source_name),
                source_limits,
                !resolved.no_default_excludes,
            ) {
                Ok(s) => {
                    sources.push(s);
                    continue;
                }
                Err(e) if e.to_string().contains("unknown source plugin") => {
                    anyhow::bail!(
                        "custom source '{source_name}' not found in the compiled source factory. \
                         Fix: use a compiled-in source name or a dedicated source flag from \
                         `keyhog scan --help`."
                    );
                }
                // `{e:#}` preserves the full anyhow source chain instead
                // of the `.to_string()` that bare `anyhow::bail!(e)` would
                // produce - operators get the whole crash trace, not just
                // the outermost message.
                Err(e) => anyhow::bail!(
                    "failed to construct source '{source_name}': {e:#}\n  \
                     Fix: check the `--source {source_name}:...` parameter format and required \
                     credentials, or use the dedicated source flags shown by `keyhog scan --help`."
                ),
            }
        }
    }

    Ok(sources)
}

#[cfg(any(
    feature = "binary",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "s3",
    feature = "gcs",
    feature = "azure"
))]
fn validate_source_flag_combinations(args: &ScanArgs, _has_path_source: bool) -> Result<()> {
    #[cfg(feature = "binary")]
    if args.binary && !_has_path_source {
        anyhow::bail!(
            "--binary was requested, but no filesystem path source was provided. \
             Fix: pass --path <PATH> or a positional PATH with --binary, or remove --binary."
        );
    }

    #[cfg(all(feature = "binary", feature = "git"))]
    if args.binary && args.git_staged {
        anyhow::bail!(
            "--binary cannot be combined with --git-staged: a binary scan reads filesystem artifacts, while a staged scan must read exact index blobs. \
             Fix: run `keyhog scan --git-staged` for the commit boundary and a separate `keyhog scan --binary <PATH>` for working-tree binaries."
        );
    }

    #[cfg(feature = "github")]
    let github_selected = args.github_org.is_some() || args.github_collaboration.is_some();
    #[cfg(feature = "github")]
    let github_token_present = args.github_token.is_some()
        || (github_selected
            && hosted_source_credential(None, HostedCredentialEnv::GithubToken)?.is_some());
    #[cfg(feature = "github")]
    if github_selected && !github_token_present {
        anyhow::bail!(
            "GitHub source requires --github-token or KEYHOG_GITHUB_TOKEN. Fix: provide a read-only token for the selected GitHub source."
        );
    }
    #[cfg(feature = "github")]
    if !github_selected && args.github_token.is_some() {
        anyhow::bail!(
            "--github-token does not select a source. Fix: add --github-org or --github-collaboration, or remove the unused token."
        );
    }
    #[cfg(feature = "github")]
    if args.github_collaboration.is_some()
        && !(args.github_issues
            || args.github_pull_requests
            || args.github_discussions
            || args.github_wiki
            || args.github_gists)
    {
        anyhow::bail!(
            "--github-collaboration requires an explicit surface. Fix: add one or more of --github-issues, --github-pull-requests, --github-discussions, --github-wiki, or --github-gists."
        );
    }

    #[cfg(feature = "gitlab")]
    let gitlab_token_present = args.gitlab_token.is_some()
        || (args.gitlab_group.is_some()
            && hosted_source_credential(None, HostedCredentialEnv::GitlabToken)?.is_some());
    #[cfg(feature = "gitlab")]
    validate_all_or_none_source_flags(
        "GitLab group source",
        &[
            ("--gitlab-group", args.gitlab_group.is_some()),
            (
                "--gitlab-token or KEYHOG_GITLAB_TOKEN",
                gitlab_token_present,
            ),
        ],
    )?;

    #[cfg(feature = "bitbucket")]
    let bitbucket_username_present = args.bitbucket_username.is_some()
        || (args.bitbucket_workspace.is_some()
            && hosted_source_credential(None, HostedCredentialEnv::BitbucketUsername)?.is_some());
    #[cfg(feature = "bitbucket")]
    let bitbucket_token_present = args.bitbucket_token.is_some()
        || (args.bitbucket_workspace.is_some()
            && hosted_source_credential(None, HostedCredentialEnv::BitbucketToken)?.is_some());
    #[cfg(feature = "bitbucket")]
    validate_all_or_none_source_flags(
        "Bitbucket workspace source",
        &[
            ("--bitbucket-workspace", args.bitbucket_workspace.is_some()),
            (
                "--bitbucket-username or KEYHOG_BITBUCKET_USERNAME",
                bitbucket_username_present,
            ),
            (
                "--bitbucket-token or KEYHOG_BITBUCKET_TOKEN",
                bitbucket_token_present,
            ),
        ],
    )?;

    #[cfg(feature = "s3")]
    {
        validate_primary_source_flag(
            "--s3-bucket",
            args.s3_bucket.is_some(),
            &[
                ("--s3-prefix", args.s3_prefix.is_some()),
                ("--s3-endpoint", args.s3_endpoint.is_some()),
                (
                    "--allow-s3-credential-forward",
                    args.allow_s3_credential_forward,
                ),
            ],
        )?;
        if args.allow_s3_credential_forward && args.s3_endpoint.is_none() {
            anyhow::bail!(
                "--allow-s3-credential-forward requires --s3-endpoint. \
                 Fix: pass the trusted S3-compatible endpoint explicitly or remove \
                 --allow-s3-credential-forward."
            );
        }
    }

    #[cfg(feature = "gcs")]
    {
        validate_primary_source_flag(
            "--gcs-bucket",
            args.gcs_bucket.is_some(),
            &[
                ("--gcs-prefix", args.gcs_prefix.is_some()),
                ("--gcs-endpoint", args.gcs_endpoint.is_some()),
                ("--allow-gcs-token-forward", args.allow_gcs_token_forward),
            ],
        )?;
        if args.allow_gcs_token_forward && args.gcs_endpoint.is_none() {
            anyhow::bail!(
                "--allow-gcs-token-forward requires --gcs-endpoint. \
                 Fix: pass the trusted GCS-compatible endpoint explicitly or remove \
                 --allow-gcs-token-forward."
            );
        }
    }

    #[cfg(feature = "azure")]
    validate_primary_source_flag(
        "--azure-container-url",
        args.azure_container_url.is_some(),
        &[("--azure-prefix", args.azure_prefix.is_some())],
    )?;

    Ok(())
}

#[cfg(not(any(
    feature = "binary",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "s3",
    feature = "gcs",
    feature = "azure"
)))]
fn validate_source_flag_combinations(_args: &ScanArgs, _has_path_source: bool) -> Result<()> {
    Ok(())
}

#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
fn validate_all_or_none_source_flags(
    source_name: &str,
    flags: &[(&'static str, bool)],
) -> Result<()> {
    let any_present = flags.iter().any(|(_, present)| *present);
    let all_present = flags.iter().all(|(_, present)| *present);
    if !any_present || all_present {
        return Ok(());
    }
    let missing = flags
        .iter()
        .filter_map(|(flag, present)| (!*present).then_some(*flag))
        .collect::<Vec<_>>()
        .join(", ");
    let present = flags
        .iter()
        .filter_map(|(flag, present)| (*present).then_some(*flag))
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "incomplete {source_name} configuration: {present} was provided but {missing} \
         is missing. Fix: provide the complete source flag set or remove the partial \
         source configuration."
    );
}

#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
fn validate_primary_source_flag(
    primary_flag: &'static str,
    primary_present: bool,
    companions: &[(&'static str, bool)],
) -> Result<()> {
    if primary_present {
        return Ok(());
    }
    let present = companions
        .iter()
        .filter_map(|(flag, present)| (*present).then_some(*flag))
        .collect::<Vec<_>>();
    if present.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "{} requires {primary_flag}. Fix: pass {primary_flag} or remove {}.",
        present.join(", "),
        present.join(", ")
    );
}
