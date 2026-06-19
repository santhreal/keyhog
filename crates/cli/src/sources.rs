//! Source factory for the KeyHog CLI.

use crate::args::ScanArgs;
#[cfg(feature = "git")]
use anyhow::Context;
use anyhow::Result;
use keyhog_core::MerkleIndex;
use keyhog_core::Source;
use std::num::NonZeroUsize;
#[cfg(feature = "git")]
use std::path::PathBuf;
use std::sync::Arc;

/// Merge `.keyhogignore` paths and `--exclude-paths`.
///
/// Default excludes are owned by `keyhog_sources::FilesystemSource` so the
/// actual scanner path, not a CLI glob mirror, decides what is skipped and
/// records the surfaced skip reason.
pub(crate) fn merge_scan_ignore_paths(
    args: &ScanArgs,
    allowlist_paths: Vec<String>,
) -> Vec<String> {
    let mut merged = allowlist_paths;
    if let Some(exclude) = &args.exclude_paths {
        merged.extend(exclude.iter().cloned());
    }
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

pub(crate) fn build_sources(
    args: &ScanArgs,
    ignore_paths: Vec<String>,
    merkle: Option<Arc<MerkleIndex>>,
) -> Result<Vec<Box<dyn Source>>> {
    let mut sources: Vec<Box<dyn Source>> = Vec::new();
    let source_limits = args.limits.to_source_limits();
    let scan_path = args.path.as_ref().or(args.input.as_ref());
    validate_source_flag_combinations(args, scan_path.is_some())?;

    #[cfg(feature = "git")]
    let mut staged_files = if args.git_staged {
        get_staged_files(scan_path.map(PathBuf::as_path))?
    } else {
        Vec::new()
    };
    #[cfg(feature = "git")]
    if args.git_staged {
        filter_staged_files_by_cli_excludes(&mut staged_files, args);
    }

    let merged_ignore_paths = merge_scan_ignore_paths(args, ignore_paths);

    if let Some(path) = scan_path {
        crate::path_validation::validate_cli_path_arg(path, "scan path")?;
        let mut fs_source = keyhog_sources::FilesystemSource::new(path.clone())
            .with_ignore_paths(merged_ignore_paths)
            // Default excludes are source-owned. `--no-default-excludes` must
            // toggle the actual file classifier, not a CLI-side glob mirror.
            .with_default_excludes(!args.no_default_excludes);
        if let Some(limit) = args.max_file_size {
            fs_source = fs_source.with_max_file_size(limit as u64);
        }
        if let Some(threads) = args.reader_threads.and_then(NonZeroUsize::new) {
            fs_source = fs_source.with_reader_threads(threads);
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
            sources.push(Box::new(
                keyhog_sources::BinarySource::new(path.clone()).with_limits(source_limits),
            ));
        }
    }

    if args.stdin {
        sources.push(Box::new(
            keyhog_sources::StdinSource.with_limits(source_limits),
        ));
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git_blobs {
        sources.push(Box::new(
            keyhog_sources::GitSource::new(path.clone())
                .with_max_commits(args.max_commits)
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
                .with_limits(source_limits),
        ));
    }

    #[cfg(feature = "git")]
    if let Some(ref path) = args.git_history {
        sources.push(Box::new(
            keyhog_sources::GitHistorySource::new(path.clone())
                .with_max_commits(args.max_commits)
                .with_limits(source_limits),
        ));
    }

    #[cfg(feature = "github")]
    if let (Some(org), Some(token)) = (&args.github_org, &args.github_token) {
        let params = format!("{org}\n{token}");
        sources.push(keyhog_sources::create_source_with_http_config(
            "github-org",
            Some(&params),
            source_http_config(args, "github-org"),
        )?);
    }

    #[cfg(feature = "gitlab")]
    if let (Some(group), Some(token)) = (&args.gitlab_group, &args.gitlab_token) {
        let params = format!("{group}\n{token}\n{}", args.gitlab_endpoint);
        sources.push(keyhog_sources::create_source_with_http_config(
            "gitlab-group",
            Some(&params),
            source_http_config(args, "gitlab-group"),
        )?);
    }

    #[cfg(feature = "bitbucket")]
    if let (Some(workspace), Some(username), Some(token)) = (
        &args.bitbucket_workspace,
        &args.bitbucket_username,
        &args.bitbucket_token,
    ) {
        let params = format!(
            "{workspace}\n{username}\n{token}\n{}",
            args.bitbucket_endpoint
        );
        sources.push(keyhog_sources::create_source_with_http_config(
            "bitbucket-workspace",
            Some(&params),
            source_http_config(args, "bitbucket-workspace"),
        )?);
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
        sources.push(keyhog_sources::create_source_with_http_config_and_limits(
            "s3",
            Some(&params),
            source_http_config(args, "s3"),
            source_limits,
        )?);
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
        sources.push(keyhog_sources::create_source_with_http_config_and_limits(
            "gcs",
            Some(&params),
            source_http_config(args, "gcs"),
            source_limits,
        )?);
    }

    #[cfg(feature = "azure")]
    if let Some(container_url) = &args.azure_container_url {
        let azure_prefix = match args.azure_prefix.as_deref() {
            Some(prefix) => prefix,
            None => "",
        };
        let params = format!("{container_url}\n{azure_prefix}");
        sources.push(keyhog_sources::create_source_with_http_config_and_limits(
            "azure_blob",
            Some(&params),
            source_http_config(args, "azure-blob"),
            source_limits,
        )?);
    }

    #[cfg(feature = "docker")]
    if let Some(image) = &args.docker_image {
        sources.push(keyhog_sources::create_source_with_http_config_and_limits(
            "docker",
            Some(image),
            source_http_config(args, "docker"),
            source_limits,
        )?);
    }

    #[cfg(feature = "web")]
    if let Some(urls) = &args.url {
        let params = if args.autoroute_calibrate {
            format!("autoroute_loopback_calibration=true\n{}", urls.join("\n"))
        } else {
            urls.join("\n")
        };
        sources.push(keyhog_sources::create_source_with_http_config_and_limits(
            "web",
            Some(&params),
            source_http_config(args, "web"),
            source_limits,
        )?);
    }

    if let Some(ref dynamic_sources) = args.source {
        for source_spec in dynamic_sources {
            let (source_name, params) = if let Some(idx) = source_spec.find(':') {
                (&source_spec[..idx], Some(&source_spec[idx + 1..]))
            } else {
                (source_spec.as_str(), None)
            };

            match keyhog_sources::create_source_with_http_config_and_limits(
                source_name,
                params,
                source_http_config(args, source_name),
                source_limits,
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
fn validate_source_flag_combinations(args: &ScanArgs, has_path_source: bool) -> Result<()> {
    #[cfg(feature = "binary")]
    if args.binary && !has_path_source {
        anyhow::bail!(
            "--binary was requested, but no filesystem path source was provided. \
             Fix: pass --path <PATH> or a positional PATH with --binary, or remove --binary."
        );
    }

    #[cfg(feature = "github")]
    validate_all_or_none_source_flags(
        "GitHub organization source",
        &[
            ("--github-org", args.github_org.is_some()),
            ("--github-token", args.github_token.is_some()),
        ],
    )?;

    #[cfg(feature = "gitlab")]
    validate_all_or_none_source_flags(
        "GitLab group source",
        &[
            ("--gitlab-group", args.gitlab_group.is_some()),
            ("--gitlab-token", args.gitlab_token.is_some()),
        ],
    )?;

    #[cfg(feature = "bitbucket")]
    validate_all_or_none_source_flags(
        "Bitbucket workspace source",
        &[
            ("--bitbucket-workspace", args.bitbucket_workspace.is_some()),
            ("--bitbucket-username", args.bitbucket_username.is_some()),
            ("--bitbucket-token", args.bitbucket_token.is_some()),
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

#[cfg(feature = "git")]
fn get_staged_files(repo_path: Option<&std::path::Path>) -> Result<Vec<PathBuf>> {
    // SECURITY: kimi-wave1 audit finding 3.PATH-git. Resolve git to a
    // trusted absolute path; refuse $PATH lookup.
    let git_bin = keyhog_core::resolve_safe_bin("git")
        .ok_or_else(|| anyhow::anyhow!("git binary not found in trusted system bin dirs"))?;

    // DF-03: detect "not a git repository" BEFORE running `git diff --cached`,
    // so the operator gets a clean, actionable message instead of a raw git
    // error leaking out of the diff invocation. `rev-parse --is-inside-work-tree`
    // is the canonical probe — it succeeds inside a repo (incl. worktrees /
    // submodules / subdirectories where a bare `.git` filesystem check would
    // miss) and exits non-zero with "fatal: not a git repository" outside one.
    {
        let mut probe = std::process::Command::new(&git_bin);
        probe.args(["rev-parse", "--is-inside-work-tree"]);
        if let Some(path) = repo_path {
            probe.current_dir(path);
        }
        let inside = probe
            .output()
            .context("failed to run `git rev-parse --is-inside-work-tree`")?;
        let is_repo =
            inside.status.success() && String::from_utf8_lossy(&inside.stdout).trim() == "true";
        if !is_repo {
            let where_ = repo_path
                .map(|p| p.display().to_string())
                .or_else(|| {
                    std::env::current_dir()
                        .ok() // LAW10: cwd probe for an ERROR-MESSAGE string only (the "not a git repository" bail); absent => '.' below, recall-irrelevant
                        .map(|p| p.display().to_string())
                })
                .unwrap_or_else(|| ".".to_string()); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
            anyhow::bail!(
                "'{where_}' is not a git repository — `--git-staged` scans the git \
                 staging area, which only exists inside a repo. Run keyhog from inside \
                 a git repository (or pass a repo path), or drop `--git-staged` to scan \
                 the working tree directly."
            );
        }
    }

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
        .or_else(|| std::env::current_dir().ok()) // LAW10: optional env/cwd probe; absent => None (intended config/probe), recall-irrelevant
        .unwrap_or_else(|| PathBuf::from(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    let base = base.canonicalize().unwrap_or(base); // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe

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
        .or_else(|| std::env::current_dir().ok()) // LAW10: optional env/cwd probe; absent => None (intended config/probe), recall-irrelevant
        .unwrap_or_else(|| PathBuf::from(".")) // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(".")); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    files.retain(|path| {
        let rel = path.strip_prefix(&base).unwrap_or(path); // LAW10: no prefix/BOM to strip => value unchanged (intended), recall-safe
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
