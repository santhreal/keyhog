//! Logic for the `scan` subcommand.
//!
//! Default scans build a [`ScanOrchestrator`] and run in process. The warm
//! daemon route serves bounded stdin or one regular file. The explicit mass
//! route keeps local filesystem payloads daemon-local while streaming protected
//! chunks for credential-bound remote sources. Both paths use bounded batches
//! and reuse one compiled CPU, Hyperscan, CUDA, or WGPU scanner across complete
//! partitions. `--daemon=on` and `--daemon=mass` are hard contracts and never
//! fall back.

use crate::args::{DaemonMode, ScanArgs};
#[cfg(unix)]
use crate::exit_codes::{EXIT_CREDENTIALS_FOUND, EXIT_LIVE_CREDENTIALS, EXIT_SOURCE_FAILED};
// Daemon module is unix-only - Windows has no `tokio::net::UnixListener`
// or `std::os::unix::net::UnixStream`, so the whole `crate::daemon`
// subtree is `#[cfg(unix)]`. See `lib.rs` for the rationale. On
// Windows, an absent daemon flag or explicit `--daemon=off` runs in-process;
// explicit `--daemon=auto|on` fails loudly because no daemon transport exists.
#[cfg(unix)]
use crate::daemon::client;
#[cfg(unix)]
use crate::daemon::protocol::{
    response_kind, Request, RequestProfile, RequiredOption, Response, SourceCoverageGaps,
    MASS_BATCH_BYTES, MASS_BATCH_CHUNKS,
};
#[cfg(unix)]
use crate::daemon::server::default_socket_path;
use crate::orchestrator::ScanOrchestrator;
use anyhow::{bail, Result};
// The daemon-only result-massaging path (unwrap_scan_results,
// finalize_for_report) is the only consumer of `RawMatch` /
// `VerifiedFinding` in this file. The in-process orchestrator path
// handles its own conversion inside `ScanOrchestrator::run`, and shared
// postprocess helpers own dedup/redaction. Cfg-gate the imports so Windows
// builds don't trip the unused-imports denial.
#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use keyhog_core::{Chunk, RawMatch, RuleSuppressor, ScanCompletionStatus, VerifiedFinding};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) async fn run(mut args: ScanArgs) -> Result<ExitCode> {
    crate::runtime_preflight::validate_scan_runtime_config()?;
    crate::action_report::validate_scan_paths(&args)?;
    guard_multi_root_combinations(&args)?;
    if args.daemon_mode() == DaemonMode::Off && args.daemon_socket.is_some() {
        bail!("`--daemon-socket` cannot be combined with `--daemon=off`; remove the socket or choose `--daemon=auto|on|mass`");
    }

    // On Windows, the daemon transport is unavailable. An explicitly selected
    // auto, warm, or mass mode therefore fails instead of rewriting execution.
    // An absent flag and explicit off both run in process.
    #[cfg(not(unix))]
    {
        let mode = args.daemon_mode();
        if args.daemon.is_some() && mode.may_use_daemon_transport() {
            let requested = match mode {
                DaemonMode::Auto => "auto",
                DaemonMode::On => "on",
                DaemonMode::Mass => "mass",
                DaemonMode::Off => unreachable!("off cannot use daemon transport"),
            };
            bail!(
                "`--daemon={requested}` is a unix-only mode (the daemon serves scans \
                 over a Unix-domain socket). Drop the flag to run \
                 in-process, or pass `--daemon=off` to be explicit."
            );
        }
        let orchestrator = ScanOrchestrator::new(args)?;
        return orchestrator.run().await;
    }
    // Resolve the routing-relevant `.keyhog.toml` policy BEFORE deciding the
    // route. The orchestrator's `.keyhog.toml` merge runs LATER (inside
    // `ScanOrchestrator::new`) and only on the in-process path, so a policy set
    // via the config file rather than a CLI flag was invisible to
    // `daemon_route`: letting a config min_confidence floor, a config
    // `[lockdown] require = true` fail-closed guard, or a config
    // `show_secrets` be silently bypassed whenever a daemon happened to be
    // live. Merge onto a throwaway clone so the real `args` the orchestrator
    // consumes is untouched (it re-merges identically), then route on the
    // EFFECTIVE values.
    //
    // That probe re-reads and re-parses `.keyhog.toml` a SECOND time (the
    // orchestrator parses it again in `ScanOrchestrator::new`). It is only
    // load-bearing when a daemon could actually take the scan: `--daemon=on`, or
    // an auto route with a live socket at the address we would connect to. When
    // no daemon is reachable, the common case (`--daemon=off`, or auto with no
    // socket), the route is Forbidden regardless, so skip the probe entirely
    // and go straight to the in-process orchestrator, which resolves the config
    // exactly ONCE. `effective_daemon_socket` is the same address `daemon_route`
    // and `run_via_daemon` use, so this gate never diverges from the real route.
    #[cfg(unix)]
    {
        let mode = args.daemon_mode();
        if mode == DaemonMode::Mass {
            return run_via_mass_daemon(&mut args).await;
        }
        let daemon_reachable = mode == DaemonMode::On
            || (mode != DaemonMode::Off && effective_daemon_socket(&args).exists());
        if !daemon_reachable {
            announce_in_process_route(
                &args,
                &format!(
                    "no daemon is listening on {}",
                    effective_daemon_socket(&args).display()
                ),
            );
            let orchestrator = ScanOrchestrator::new(args)?;
            return orchestrator.run().await;
        }
        let mut policy = EffectivePolicy::resolve(&args);
        match daemon_route(&args, &policy) {
            DaemonRoute::Required => {
                #[cfg(feature = "git")]
                if policy.effective_args.git_staged {
                    let socket_path = effective_daemon_socket(&policy.effective_args);
                    let repo_path = policy
                        .effective_args
                        .path
                        .as_deref()
                        .unwrap_or_else(|| std::path::Path::new("."));
                    let digest = keyhog_core::detector_digest().to_string();
                    let result = crate::daemon::guard_commit::run_guard_commit(
                        &socket_path,
                        repo_path,
                        &digest,
                    )
                    .await
                    .context("--daemon=on guard commit transaction failed")?;
                    return finish_guard_commit_scan(result, &policy.effective_args);
                }
                run_via_daemon(&mut policy.effective_args).await
            }
            DaemonRoute::Opportunistic => {
                // Guard commit transaction for --git-staged.
                #[cfg(feature = "git")]
                if policy.effective_args.git_staged {
                    let socket_path = effective_daemon_socket(&policy.effective_args);
                    let repo_path = policy
                        .effective_args
                        .path
                        .as_deref()
                        .unwrap_or_else(|| std::path::Path::new("."));
                    let digest = keyhog_core::detector_digest().to_string();
                    match crate::daemon::guard_commit::run_guard_commit(
                        &socket_path,
                        repo_path,
                        &digest,
                    )
                    .await
                    {
                        Ok(result) => {
                            return finish_guard_commit_scan(result, &policy.effective_args);
                        }
                        Err(e) => {
                            if policy.effective_args.daemon_mode() == DaemonMode::Auto {
                                let palette = crate::style::for_stderr();
                                eprintln!(
                                    "{}: guard daemon unavailable ({e:#}); running in-process scanner",
                                    crate::style::warn("keyhog", &palette)
                                );
                            }
                            let orchestrator = ScanOrchestrator::new(args)?;
                            return orchestrator.run().await;
                        }
                    }
                }
                match acquire_via_daemon(&mut policy.effective_args).await {
                    Ok(scan) => finish_daemon_scan(scan, &policy.effective_args),
                    Err(e) => {
                        if policy.effective_args.daemon_mode() == DaemonMode::Auto {
                            let palette = crate::style::for_stderr();
                            eprintln!(
                                "{}: daemon auto route unavailable ({e:#}); running in-process scanner",
                                crate::style::warn("keyhog", &palette)
                            );
                        }
                        tracing::debug!(
                            error = %e,
                            "daemon auto route unavailable; running in-process scanner"
                        );
                        let mut retry_args = args.clone();
                        retry_args.buffered_stdin = policy.effective_args.buffered_stdin.clone();
                        let orchestrator = ScanOrchestrator::new(retry_args)?;
                        orchestrator.run().await
                    }
                }
            }
            DaemonRoute::Rejected(reason) => bail!("{reason}"),
            DaemonRoute::Forbidden(reason) => {
                if let Some(reason) = reason {
                    announce_in_process_route(&args, &reason);
                }
                let orchestrator = ScanOrchestrator::new(args)?;
                orchestrator.run().await
            }
        }
    }
}

#[cfg(unix)]
enum DaemonRoute {
    Required,
    Opportunistic,
    /// Run in process. `Some(reason)` when a daemon route was in play and could
    /// not be honored, so the operator can be told why; `None` when the daemon
    /// was never a candidate (`--daemon=off`).
    Forbidden(Option<String>),
    Rejected(String),
}

/// Tell an operator who ASKED for the daemon that this scan is running in
/// process, and why.
///
/// Only fires when `--daemon` was passed explicitly AND asked for a daemon. The
/// flag defaults to `auto`, and most scans (any directory, any Git or remote
/// source) can never use the warm daemon, so announcing on the default would
/// put a line of noise on almost every scan. `--daemon=off` already said "run
/// in process", so repeating it back is noise too. Someone who typed
/// `--daemon=auto` asked a question and deserves the answer: a silently
/// in-process scan is indistinguishable from a daemon-served one, which makes
/// timing results meaningless and hides a daemon that is not being used at all.
///
/// stderr only, so `--format json` stdout stays byte-identical.
#[cfg(unix)]
fn announce_in_process_route(args: &ScanArgs, reason: &str) {
    tracing::debug!(reason, "daemon route not used; running in-process scanner");
    if args.daemon.is_none() || args.daemon_mode() == DaemonMode::Off {
        return;
    }
    let palette = crate::style::for_stderr();
    eprintln!(
        "{}: daemon route not used ({reason}); running in-process scanner",
        crate::style::warn("keyhog", &palette)
    );
}

/// Fail closed when several positional roots are combined with a mode that has
/// no unambiguous meaning over more than one root.
///
/// keyhog now scans multiple roots per invocation (`keyhog scan a/ b/ c/`):
/// each becomes its own filesystem source and the engine merges the multi-
/// source `Vec` it already consumes. The only positional-root mode that breaks
/// is `--git-staged`, whose exact index blobs are resolved from a SINGLE
/// repository; with several roots there is no one index to read, and silently
/// staged-scanning only the first root while
/// walking the rest in full would be a confusing, asymmetric result (Law 10).
/// Every other source (`--stdin`, `--git-blobs/-diff/-history`, the remote
/// providers, `--binary`) carries its own origin and composes cleanly, so they
/// are deliberately NOT rejected here.
pub(crate) fn guard_multi_root_combinations(args: &ScanArgs) -> Result<()> {
    let roots = args.scan_roots();
    if roots.len() <= 1 {
        return Ok(());
    }
    #[cfg(feature = "git")]
    if args.git_staged {
        let list = roots
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "`--git-staged` resolves staged files from one repository working \
             tree, so it cannot span the {n} roots given ({list}).\n\
             Run `keyhog scan --git-staged <repo>` once per repository, or drop \
             `--git-staged` to walk every root on disk.",
            n = roots.len(),
            list = list,
        );
    }
    Ok(())
}

/// The routing-relevant policy AFTER merging `.keyhog.toml`, so the daemon
/// route decision sees config-file values (not just raw CLI flags). Built by
/// merging a throwaway clone of `ScanArgs` through the same
/// [`crate::config::apply_config_file`] the orchestrator uses, so the
/// effective floor / lockdown-require / secret-output policy is identical to
/// what the in-process path will enforce.
#[cfg(unix)]
struct EffectivePolicy {
    /// Routing clone after the quiet config merge. The daemon path must consume
    /// this, not the raw CLI args, for knobs it can enforce client-side
    /// (dedup, output, stdin byte limit) to match the in-process route.
    effective_args: ScanArgs,
    /// `min_confidence` after the config merge (CLI flag OR `.keyhog.toml` /
    /// `[scan]` floor). When `Some`, the daemon's floor-less finalize would
    /// surface findings the in-process path suppresses, so force in-process.
    min_confidence: Option<f64>,
    /// `show_secrets` after the merge (CLI flag OR `.keyhog.toml`). The daemon
    /// finalize redacts unconditionally, so a config-driven value would render
    /// credentials differently by route.
    show_secrets: bool,
    /// Live verification after the merge (CLI flag OR `.keyhog.toml`). The
    /// daemon returns scanner matches only, so a config-driven verify request
    /// must route in-process exactly like `--verify`.
    #[cfg(feature = "verify")]
    verify: bool,
    /// Minimum-severity filter after the merge (CLI flag OR `.keyhog.toml`).
    severity: bool,
    /// `[lockdown] require = true` from `.keyhog.toml`: a fail-closed control
    /// the daemon cannot enforce. Forces in-process so the orchestrator's
    /// `bail!` fires when `--lockdown` was not passed.
    require_lockdown: bool,
    /// Semantic config errors detected by the quiet config probe. Forces
    /// in-process so the real orchestrator emits the precise error once.
    has_config_errors: bool,
    /// Extra AWS canary/knockoff account IDs from `.keyhog.toml`. The daemon
    /// process owns its own scanner state and cannot consume per-client config.
    custom_aws_canary_accounts: bool,
    /// `[allowlist]` file/governance policy from `.keyhog.toml`. The daemon
    /// route intentionally loads only the default local `.keyhogignore`, so a
    /// configured allowlist policy must stay in-process.
    has_allowlist_config: bool,
    /// Per-detector confidence policy from `.keyhog.toml`. The daemon owns a
    /// long-lived scanner compiled without the client's local detector policy,
    /// and client-side finalization cannot recover findings an engine floor
    /// already dropped. Any such policy therefore requires the in-process path.
    has_detector_min_confidence: bool,
    /// Disabled detector policy changes the compiled corpus and cannot be applied
    /// after the daemon has scanned. Keep it on the in-process path.
    has_disabled_detectors: bool,
}

#[cfg(unix)]
impl EffectivePolicy {
    fn resolve(args: &ScanArgs) -> EffectivePolicy {
        let mut probe = args.clone();
        // Mirror `ScanOrchestrator::new`'s path normalization BEFORE the config
        // merge: the positional path binds to `input`, but config discovery
        // (`find_config_file`) walks up from `path`. Without promoting
        // `input` -> `path` here, `apply_config_file` would look in the CWD
        // instead of the scanned file's directory and miss the `.keyhog.toml`
        // whose policy we are trying to honour (the exact bug this resolves).
        if probe.path.is_none() {
            probe.path = probe.input.first().cloned();
        }
        // Quiet (diagnostics-free) merge: this probe applies the config to a
        // throwaway clone only to read the resolved routing knobs. The real
        // orchestrator merge emits any read/parse warning exactly once; the loud
        // `apply_config_file` here would warn TWICE on a malformed `.keyhog.toml`
        // over the daemon route (HUNT-2).
        let outcome = crate::config::apply_config_file_quiet(&mut probe);
        let min_confidence = probe.min_confidence;
        let show_secrets = probe.show_secrets;
        #[cfg(feature = "verify")]
        let verify = probe.verify;
        let severity = probe.severity.is_some();
        EffectivePolicy {
            effective_args: probe,
            min_confidence,
            show_secrets,
            #[cfg(feature = "verify")]
            verify,
            severity,
            require_lockdown: outcome.require_lockdown,
            has_config_errors: !outcome.config_errors.is_empty(),
            custom_aws_canary_accounts: !outcome.aws_canary_accounts.is_empty(),
            has_allowlist_config: outcome.allowlist_file.is_some()
                || outcome.allowlist_require_reason
                || outcome.allowlist_require_approved_by
                || outcome.allowlist_max_expires_days.is_some(),
            has_detector_min_confidence: !outcome.detector_min_confidence.is_empty(),
            has_disabled_detectors: !outcome.disabled_detectors.is_empty(),
        }
    }
}

#[cfg(unix)]
fn daemon_route(args: &ScanArgs, policy: &EffectivePolicy) -> DaemonRoute {
    let mode = args.daemon_mode();
    if mode == DaemonMode::Off {
        return DaemonRoute::Forbidden(None);
    }
    let forced_on = mode == DaemonMode::On;

    // Daemon path doesn't run verification - the daemon process holds a
    // scanner but not the verifier engine. Trying to honour `--verify` or
    // config `verify = true` over a daemon-only result set would silently drop
    // every API-call-backed live-credential check; the orchestrator is the
    // only honest answer.
    #[cfg(feature = "verify")]
    if policy.verify {
        return daemon_cannot_serve(
            forced_on,
            "verification requires the in-process verifier; the daemon only returns scanner matches",
        );
    }
    if args.baseline.is_some() {
        return daemon_cannot_serve(
            forced_on,
            "--baseline requires the in-process baseline filter; the daemon has no baseline state",
        );
    }

    // The daemon's client-side finalize mirrors allowlist/rule suppression,
    // inline suppression, match resolution, and dedup for daemon-eligible scans.
    // It still does NOT run live verification or enforce the policy/security
    // gates below (lockdown protections, secret-output policy, severity hiding,
    // client-safe hiding, or explicit confidence-floor policy). Routing a scan
    // that requests any of those over the daemon would silently change results
    // or bypass a hard security guard, and the opportunistic route flips on
    // merely because a daemon socket exists. Force the in-process path whenever
    // such policy is in play, so behavior never depends on whether a daemon
    // happens to be running.
    //
    // Critically, the floor / lockdown-require / show_secrets / severity checks
    // read the EFFECTIVE post-`.keyhog.toml`-merge policy, not just the raw CLI
    // flags: a `.keyhog.toml` `min_confidence`, `[lockdown] require = true`, or
    // `show_secrets` set via the config file (with no matching CLI flag) must
    // forbid the daemon route too, otherwise scan RESULTS and a fail-closed
    // SECURITY GUARD would change purely on whether a daemon is live.
    // `hide_client_safe` has no config-file surface, so the CLI flag is the
    // effective value.
    if args.lockdown
        || policy.require_lockdown
        || policy.show_secrets
        || policy.severity
        || policy.min_confidence.is_some()
        || policy.has_config_errors
        || policy.custom_aws_canary_accounts
        || policy.has_allowlist_config
        || policy.has_detector_min_confidence
        || policy.has_disabled_detectors
        || args.hide_client_safe
    {
        return daemon_cannot_serve(
            forced_on,
            "this scan requests filtering, lockdown, secret-output, AWS canary config, allowlist governance, or config policy the daemon cannot enforce",
        );
    }

    if let Some(reason) = daemon_incompatible_scan_options(&policy.effective_args) {
        return daemon_cannot_serve(forced_on, reason);
    }

    // Guard commit transaction: when --git-staged is used and a compatible
    // guard daemon is available, route through the staged-object guard
    // transaction instead of the in-process scanner. The daemon's clean
    // attestation cache skips blobs whose content and policy identity are
    // unchanged. Security policy checks above already ran, so lockdown,
    // show_secrets, and verification are still enforced. This runs before
    // the single-file/primary-source gate because --git-staged is a
    // multi-object source the guard transaction handles natively.
    #[cfg(feature = "git")]
    if args.git_staged {
        if forced_on {
            return DaemonRoute::Required;
        }
        if effective_daemon_socket(args).exists() {
            return DaemonRoute::Opportunistic;
        }
        return DaemonRoute::Forbidden(Some(format!(
            "no daemon is listening on {}",
            effective_daemon_socket(args).display()
        )));
    }

    let single_file = match effective_single_file_path(args) {
        Ok(path) => path.is_some(),
        Err(error) => {
            return daemon_cannot_serve(
                forced_on,
                format!(
                    "the daemon single-file route cannot inspect the requested path: {error:#}"
                ),
            );
        }
    };
    let primary_sources = usize::from(args.stdin) + usize::from(single_file);
    if primary_sources != 1 || has_daemon_incompatible_extra_sources(args) {
        return daemon_cannot_serve(
            forced_on,
            "the daemon only supports exactly one source: --stdin or a single regular file; directories, git, remote, binary, dynamic, and multi-source scans require the in-process scanner",
        );
    }

    if forced_on {
        return DaemonRoute::Required;
    }

    // Opportunistic route flips on only when a live daemon is actually at the
    // socket we'd connect to, the `--daemon-socket` override when present, else
    // the default. Probing the default while a scan targeted an override socket
    // would mis-route (treat an unrelated daemon as ours, or miss the real one).
    if effective_daemon_socket(args).exists() {
        DaemonRoute::Opportunistic
    } else {
        DaemonRoute::Forbidden(Some(format!(
            "no daemon is listening on {}",
            effective_daemon_socket(args).display()
        )))
    }
}

/// The socket the daemon route connects to: the `--daemon-socket` override when
/// the operator points the scan at a non-default daemon, else the default
/// (`$XDG_RUNTIME_DIR/keyhog.sock`). The single source of truth shared by the
/// route decision and the connect in [`run_via_daemon`], so they never diverge.
#[cfg(unix)]
fn effective_daemon_socket(args: &ScanArgs) -> std::path::PathBuf {
    args.daemon_socket
        .clone()
        // LAW10: intentional_default, absent --daemon-socket => documented default
        // socket; Tier-A transport knob, recall-irrelevant.
        .unwrap_or_else(default_socket_path)
}

/// Resolve one "the daemon cannot serve this scan" finding into a route.
///
/// `--daemon=on` is a hard contract, so it becomes a refusal the caller turns
/// into an error. Every other mode runs in process and CARRIES the reason, so
/// the operator can be told why instead of silently getting a scan that never
/// touched the daemon they started.
#[cfg(unix)]
fn daemon_cannot_serve(forced_on: bool, reason: impl Into<String>) -> DaemonRoute {
    let reason = reason.into();
    if forced_on {
        return DaemonRoute::Rejected(format!(
            "--daemon=on cannot be honored: {reason}. Drop `--daemon=on`, or pass \
             `--daemon=off` to run the in-process scanner explicitly."
        ));
    }
    DaemonRoute::Forbidden(Some(reason))
}

#[cfg(unix)]
fn has_daemon_incompatible_extra_sources(args: &ScanArgs) -> bool {
    #[cfg(feature = "binary")]
    if args.binary {
        return true;
    }
    #[cfg(feature = "git")]
    if args.git_blobs.is_some() || args.git_diff.is_some() || args.git_history.is_some() {
        return true;
    }
    #[cfg(feature = "github")]
    if args.github_org.is_some() {
        return true;
    }
    #[cfg(feature = "gitlab")]
    if args.gitlab_group.is_some() {
        return true;
    }
    #[cfg(feature = "bitbucket")]
    if args.bitbucket_workspace.is_some() {
        return true;
    }
    #[cfg(feature = "s3")]
    if args.s3_bucket.is_some() {
        return true;
    }
    #[cfg(feature = "gcs")]
    if args.gcs_bucket.is_some() {
        return true;
    }
    #[cfg(feature = "azure")]
    if args.azure_container_url.is_some() {
        return true;
    }
    #[cfg(feature = "docker")]
    if args.docker_image.is_some() {
        return true;
    }
    #[cfg(feature = "web")]
    if args.url.as_ref().is_some_and(|urls| !urls.is_empty()) {
        return true;
    }
    args.source
        .as_ref()
        .is_some_and(|sources| !sources.is_empty())
}

#[cfg(unix)]
fn daemon_incompatible_scan_options(args: &ScanArgs) -> Option<&'static str> {
    let custom_corpus_selected =
        args.detectors_cli_explicit || args.detectors != PathBuf::from("detectors");
    if args.detectors_mode == Some(crate::args::DetectorMode::Overlay) {
        return Some(
            "`--detectors-mode=overlay` cannot use the daemon because its precompiled scanner cannot compose a per-scan overlay; start the daemon with the exact replacement corpus and scan in replace mode, or use `--daemon=off`",
        );
    }
    if args.detectors_mode.is_some() && !custom_corpus_selected {
        return Some(
            "`--detectors-mode` requires a custom detector corpus and cannot alter the daemon's precompiled scanner",
        );
    }
    if args.fast
        || args.deep
        || args.precision
        || args.no_decode
        || args.no_entropy
        || args.no_entropy_ml_scoring
        || args.no_keyword_low_entropy
        || args.entropy_source_files
        || args.no_unicode_norm
        || args.no_ml
        || args.scan_comments
        || args.benchmark
    {
        return Some(
            "this scan sets scan-mode, engine, or benchmark options that require the in-process scanner",
        );
    }
    if args.backend.is_some()
        || args.autoroute_cache.is_some()
        || args.autoroute_calibrate
        || args.autoroute_gpu
        || args.no_autoroute_gpu
        || args.no_gpu
        || args.require_gpu
        || args.batch_pipeline
        || args.no_batch_pipeline
    {
        return Some(
            "this scan sets backend, GPU, batch-pipeline, or autoroute controls the daemon protocol cannot honor per request",
        );
    }
    if args.decode_depth.is_some()
        || args.decode_size_limit.is_some()
        || args.entropy_threshold.is_some()
        || args.entropy_bpe_max_bytes_per_token.is_some()
        || args.min_secret_len.is_some()
        || args.ml_weight.is_some()
        || args.max_file_size.is_some()
        || args.regex_dfa_limit.is_some()
        || args.gpu_batch_input_limit.is_some()
        || args.cache_dir.is_some()
        // Directory override relocates MatcherArtifact persistence; daemon
        // cannot honor a per-request path. `off`/`0`/empty already matches the
        // daemon's precompiled scanner (no MatcherArtifact consult).
        || matcher_cache_directory_override(args.matcher_cache.as_deref())
        || args.ml_threshold.is_some()
        // Per-chunk timeout is compiled into the daemon's long-lived scanner
        // config. A daemon-served scan would silently run without the deadline
        // the operator asked for, so the request cannot be honored per request.
        || args.per_chunk_timeout_ms.is_some()
    {
        return Some(
            "this scan changes scanner or source-limit configuration that the precompiled daemon scanner cannot honor",
        );
    }
    // `--perf-trace` writes per-pattern and backend timing to the CLIENT's
    // stderr from process-global scanner state the daemon owns and never
    // enables. Over the daemon route the flag produced no trace at all, so the
    // operator saw a successful scan and an empty diagnostic (KH-423).
    if args.perf_trace {
        return Some(
            "`--perf-trace` needs the in-process scanner: the daemon holds the traced engine state and the protocol carries no trace stream",
        );
    }
    if args.no_default_excludes || args.exclude_paths.is_some() {
        return Some(
            "this scan changes path exclusion policy that the daemon single-file route cannot honor",
        );
    }
    if !args.known_prefixes.is_empty()
        || !args.secret_keywords.is_empty()
        || !args.test_keywords.is_empty()
        || !args.placeholder_keywords.is_empty()
    {
        return Some(
            "this scan changes detector confidence vocabulary that the precompiled daemon scanner cannot honor",
        );
    }
    None
}

#[cfg(unix)]
fn matcher_cache_directory_override(raw: Option<&str>) -> bool {
    raw.is_some_and(|value| {
        let trimmed = value.trim();
        !(trimmed.is_empty() || trimmed.eq_ignore_ascii_case("off") || trimmed == "0")
    })
}

#[cfg(unix)]
struct ExpectedDaemonDetectorCorpus {
    rules_digest: Option<String>,
    corpus_digest: String,
    provenance: crate::orchestrator_config::DetectorCorpusProvenance,
    detector_count: usize,
}

#[cfg(unix)]
fn expected_daemon_detector_corpus(args: &ScanArgs) -> Result<ExpectedDaemonDetectorCorpus> {
    let custom_corpus_selected =
        args.detectors_cli_explicit || args.detectors != PathBuf::from("detectors");
    if !custom_corpus_selected {
        return Ok(ExpectedDaemonDetectorCorpus {
            rules_digest: Some(keyhog_core::detector_digest().to_owned()),
            corpus_digest: keyhog_core::detector_digest().to_owned(),
            provenance: crate::orchestrator_config::DetectorCorpusProvenance {
                mode: "embedded",
                source: "embedded (daemon)".to_string(),
                embedded_count: keyhog_core::embedded_detector_count(),
                custom_count: 0,
            },
            detector_count: keyhog_core::embedded_detector_count(),
        });
    }

    let requested_mode = args.detectors_mode.map(Into::into);
    crate::orchestrator_config::validate_detector_mode_selection(true, requested_mode)?;
    crate::orchestrator_config::validate_explicit_detector_path(&args.detectors, true)?;
    if args.detectors_mode == Some(crate::args::DetectorMode::Overlay) {
        bail!(
            "daemon route cannot honor `--detectors-mode=overlay`; start the daemon with the exact replacement corpus and scan in replace mode, or use `--daemon=off`"
        );
    }
    let detectors_path = crate::orchestrator_config::auto_discover_detectors(&args.detectors)?;
    let loaded = crate::orchestrator_config::load_effective_detector_corpus(
        &detectors_path,
        requested_mode,
        true,
    )
    .with_context(|| {
        format!(
            "daemon route: load expected replacement detector corpus from {}",
            detectors_path.display()
        )
    })?;
    let detector_count = loaded.detectors.len();
    let rules_digest = keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(&loaded.detectors));
    let corpus_digest = keyhog_core::hex_encode(
        &keyhog_core::compute_detector_corpus_digest_for_schema(
            &loaded.detectors,
            loaded.schema_version,
        )
        .context("serializing replacement daemon detector corpus identity")?,
    );
    Ok(ExpectedDaemonDetectorCorpus {
        rules_digest: Some(rules_digest),
        corpus_digest,
        provenance: loaded.provenance,
        detector_count,
    })
}

#[cfg(unix)]
fn effective_single_file_path(args: &ScanArgs) -> Result<Option<&Path>> {
    // Several positional roots are never a daemon single-file candidate. Reading
    // only `path`/`input` here would see the FIRST root, route the scan over the
    // single-path daemon protocol, and silently drop every surplus root (Law 10).
    if args.input.len() > 1 {
        return Ok(None);
    }
    let Some(raw) = args
        .path
        .as_deref()
        .or_else(|| args.input.first().map(PathBuf::as_path))
    else {
        return Ok(None);
    };
    let meta = std::fs::metadata(raw)
        .with_context(|| format!("inspect {} as daemon single-file input", raw.display()))?;
    if !meta.is_file() {
        return Ok(None);
    }
    Ok(Some(raw))
}

#[cfg(unix)]
async fn run_via_mass_daemon(args: &mut ScanArgs) -> Result<ExitCode> {
    crate::reset_scan_runtime_state();
    if args.dogfood {
        keyhog_scanner::telemetry::enable_dogfood();
    }
    let wall_start = chrono::Utc::now();
    let mut resolved = crate::orchestrator_config::resolve_scan_config(args)?;
    if resolved.threads.is_none() {
        resolved.threads = Some(crate::orchestrator_config::keyhog_worker_threads());
    }
    validate_mass_daemon_policy(args, &resolved)?;
    let ExpectedDaemonDetectorCorpus {
        rules_digest,
        corpus_digest: detector_corpus_digest,
        provenance: detector_corpus_provenance,
        detector_count,
    } = expected_daemon_detector_corpus(args)?;

    let socket = effective_daemon_socket(args);
    let mut conn = match rules_digest {
        Some(digest) => client::connect_with_detector_rules_digest(&socket, digest).await,
        None => client::connect(&socket).await,
    }
    .with_context(|| {
        format!(
            "mass daemon route: connect to {}. Start it with `keyhog daemon start --mass{}`",
            socket.display(),
            socket_flag(args)
        )
    })?;
    if !conn.is_mass_service() {
        bail!(
            "mass daemon route: {} is a warm-only service. Restart it with \
             `keyhog daemon stop{} && keyhog daemon start --mass{}`.",
            socket.display(),
            socket_flag(args),
            socket_flag(args)
        );
    }
    let require_gpu_primary = conn.mass_gpu_primary_required();

    let allowlist_paths: Vec<String> = load_daemon_allowlist(args)?
        .ignored_paths
        .iter()
        .cloned()
        .collect();
    let mass_ignore_paths =
        crate::sources::merge_scan_ignore_paths(&resolved.exclude_paths, allowlist_paths.clone());
    let sources = crate::sources::build_sources(args, &resolved, allowlist_paths, None)?;
    let filesystem_requests = mass_filesystem_requests(&sources, &resolved, mass_ignore_paths);
    if sources.is_empty() {
        bail!(
            "mass daemon route: no source was selected. Pass a path, --stdin, or a remote source flag."
        );
    }

    match conn
        .round_trip(&Request::MassBegin {
            dogfood: args.dogfood,
            profile: args.profile,
        })
        .await?
    {
        Response::MassReady => {}
        Response::Error { message } => bail!("mass daemon route: {message}"),
        other => bail!(
            "mass daemon route: expected MassReady, got {}",
            response_kind(&other)
        ),
    }

    let (matches, expected_wire_payload, source_coverage_gaps) =
        if let Some(requests) = filesystem_requests {
            let (matches, gaps) = scan_daemon_local_filesystems(&mut conn, requests).await?;
            (matches, None, gaps)
        } else {
            let before_skips = keyhog_sources::skip_counts();
            let mut source_failed = 0usize;
            let mut batcher = MassDaemonBatcher::new(&mut conn);
            for source in sources {
                let mut source_chunks = 0usize;
                let mut source_errored = false;
                for chunk_result in source.chunks() {
                    match chunk_result {
                        Ok(chunk) => {
                            source_chunks = source_chunks.saturating_add(1);
                            match split_chunk_for_mass(chunk) {
                                Ok(chunks) => {
                                    for chunk in chunks {
                                        batcher.push(chunk).await?;
                                    }
                                }
                                Err(error) => {
                                    source_errored = true;
                                    source_failed = source_failed.saturating_add(1);
                                    let _receipt = crate::record_source_error();
                                    tracing::warn!("mass daemon source chunk skipped: {error:#}");
                                    eprintln!(
                                        "{}: mass daemon source chunk was not scanned: {error:#}",
                                        crate::style::warn("warning", &crate::style::for_stderr())
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            source_errored = true;
                            source_failed = source_failed.saturating_add(1);
                            let _receipt = crate::record_source_error();
                            tracing::warn!("mass daemon source: {error}");
                        }
                    }
                }
                batcher.flush().await?;
                if source_chunks == 0 && source_errored {
                    let _receipt = crate::record_failed_source();
                }
            }
            batcher.flush().await?;
            let (matches, chunks, bytes, mut gaps) = batcher.finish();
            merge_source_coverage(
                &mut gaps,
                source_coverage_since(before_skips, source_failed),
            );
            (matches, Some((chunks, bytes)), gaps)
        };

    let mass_stats = match conn.round_trip(&Request::MassEnd).await? {
        Response::MassComplete { stats } => stats,
        Response::Error { message } => bail!("mass daemon route: {message}"),
        other => bail!(
            "mass daemon route: expected MassComplete, got {}",
            response_kind(&other)
        ),
    };
    if mass_stats.gpu_chunks > mass_stats.chunks || mass_stats.gpu_bytes > mass_stats.bytes {
        bail!(
            "mass daemon route: inconsistent execution receipt: daemon reported \
             {} total chunks/{} total bytes with {} GPU chunks/{} GPU bytes",
            mass_stats.chunks,
            mass_stats.bytes,
            mass_stats.gpu_chunks,
            mass_stats.gpu_bytes
        );
    }
    if let Some((expected_chunks, expected_bytes)) = expected_wire_payload {
        if mass_stats.chunks != expected_chunks as u64 || mass_stats.bytes != expected_bytes {
            bail!(
                "mass daemon route: inconsistent execution receipt: client sent \
                 {expected_chunks} chunks/{expected_bytes} bytes, daemon reported \
                 {} chunks/{} bytes",
                mass_stats.chunks,
                mass_stats.bytes,
            );
        }
    }
    let source_chunks_scanned = usize::try_from(mass_stats.chunks)
        .context("mass daemon receipt chunk count exceeds this platform's usize")?;
    let source_bytes_scanned = mass_stats.bytes;
    if require_gpu_primary && mass_stats.bytes > 0 && !mass_stats.gpu_is_primary() {
        bail!(
            "mass daemon route: GPU-primary contract failed: GPU processed {} of {} bytes \
             ({:.1}%), but this service requires more than 50%. Recalibrate autoroute for \
             this mass workload or restart the daemon without --mass-gpu-primary.",
            mass_stats.gpu_bytes,
            mass_stats.bytes,
            100.0 * mass_stats.gpu_bytes as f64 / mass_stats.bytes as f64,
        );
    }
    crate::TOTAL_CHUNKS.store(source_chunks_scanned, std::sync::atomic::Ordering::Relaxed);
    crate::SCANNED_CHUNKS.store(source_chunks_scanned, std::sync::atomic::Ordering::Relaxed);
    crate::SCANNED_BYTES.store(source_bytes_scanned, std::sync::atomic::Ordering::Relaxed);
    crate::GPU_SCANNED_CHUNKS.store(
        mass_stats.gpu_chunks.min(usize::MAX as u64) as usize,
        std::sync::atomic::Ordering::Relaxed,
    );
    let elapsed_secs = (mass_stats.duration_ms as f64 / 1_000.0).max(0.001);
    eprintln!(
        "mass daemon: {} batches, {} chunks, {} bytes; GPU {} batches, {} chunks, {} bytes ({:.1}%, primary: {}); {:.1} MiB/s; transport={}",
        mass_stats.batches,
        mass_stats.chunks,
        mass_stats.bytes,
        mass_stats.gpu_batches,
        mass_stats.gpu_chunks,
        mass_stats.gpu_bytes,
        if mass_stats.bytes == 0 {
            0.0
        } else {
            100.0 * mass_stats.gpu_bytes as f64 / mass_stats.bytes as f64
        },
        if mass_stats.gpu_is_primary() {
            "yes"
        } else {
            "no"
        },
        mass_stats.bytes as f64 / (1024.0 * 1024.0) / elapsed_secs,
        if expected_wire_payload.is_some() {
            "protected-chunks"
        } else {
            "daemon-local-path"
        },
    );

    finish_daemon_scan(
        DaemonScan {
            matches,
            source_coverage_gaps,
            source_bytes_scanned,
            source_chunks_scanned,
            wall_start,
            detector_corpus_digest,
            detector_corpus_provenance,
            detector_count,
            // Mass batch profiles were rendered per batch as each ScanResults
            // arrived; there is no transaction-level payload to replay here.
            profile: None,
        },
        args,
    )
}

#[cfg(unix)]
fn socket_flag(args: &ScanArgs) -> String {
    match &args.daemon_socket {
        Some(path) => format!(" --socket {}", path.display()),
        None => String::new(),
    }
}

#[cfg(unix)]
fn validate_mass_daemon_policy(
    args: &ScanArgs,
    resolved: &crate::orchestrator_config::ResolvedScanConfig,
) -> Result<()> {
    if args.baseline.is_some() || args.update_baseline.is_some() {
        bail!("--daemon=mass cannot apply baseline state. Run this scan with --daemon=off.");
    }
    if resolved.incremental || resolved.incremental_cache_path.is_some() {
        bail!(
            "--daemon=mass cannot apply Merkle incremental state. Run this scan with --daemon=off."
        );
    }
    if resolved.report.verify {
        bail!("--daemon=mass cannot run live verification. Run this scan with --daemon=off.");
    }
    if resolved.report.lockdown || resolved.require_lockdown {
        bail!("--daemon=mass cannot enforce lockdown. Run this scan with --daemon=off.");
    }
    if resolved.report.severity.is_some()
        || !resolved.detector_min_confidence.is_empty()
        || !resolved.disabled_detectors.is_empty()
    {
        bail!(
            "--daemon=mass cannot apply per-request severity or detector policy. \
             Run this scan with --daemon=off."
        );
    }
    if resolved.allowlist.file.is_some()
        || resolved.allowlist.require_reason
        || resolved.allowlist.require_approved_by
        || resolved.allowlist.max_expires_days.is_some()
    {
        bail!(
            "--daemon=mass cannot apply configured allowlist governance. \
             Run this scan with --daemon=off."
        );
    }
    if args.detectors_mode == Some(crate::args::DetectorMode::Overlay) {
        bail!(
            "--daemon=mass cannot compose a per-request detector overlay. Start the \
             daemon with the exact replacement corpus or run with --daemon=off."
        );
    }
    // `--profile` is a per-request diagnostic that rides the v12 wire; it does
    // not change scanner semantics, so it must not poison the policy digest.
    let mut policy_resolved = resolved.clone();
    policy_resolved.scanner.profile = false;
    let resolved_identity = format!(
        "{:016x}",
        crate::orchestrator_config::autoroute_config_digest(&policy_resolved)
    );
    let daemon_identity = crate::orchestrator::autoroute_default_config_identity();
    if resolved_identity != daemon_identity {
        bail!(
            "--daemon=mass resolved scanner policy {resolved_identity}, but the mass \
             daemon owns default scanner policy {daemon_identity}. Remove per-scan engine, \
             backend, preset, confidence, or detector-vocabulary overrides, or run with \
             --daemon=off."
        );
    }
    Ok(())
}

#[cfg(unix)]
fn mass_filesystem_requests(
    sources: &[Box<dyn keyhog_core::Source>],
    resolved: &crate::orchestrator_config::ResolvedScanConfig,
    ignore_paths: Vec<String>,
) -> Option<Vec<Request>> {
    let mut requests = Vec::with_capacity(sources.len());
    for source in sources {
        let filesystem = source
            .as_any()
            .downcast_ref::<keyhog_sources::FilesystemSource>()?;
        let root = filesystem.root_path().to_str()?.to_owned();
        requests.push(Request::MassFilesystemBegin {
            root,
            max_file_size: resolved
                .max_file_size
                .map_or(keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES, |bytes| {
                    bytes as u64
                }),
            ignore_paths: ignore_paths.clone(),
            respect_default_excludes: !resolved.no_default_excludes,
            reader_threads: resolved.reader_threads,
        });
    }
    Some(requests)
}

#[cfg(unix)]
async fn scan_daemon_local_filesystems(
    conn: &mut client::Client,
    requests: Vec<Request>,
) -> Result<(Vec<RawMatch>, SourceCoverageGaps)> {
    let mut matches = Vec::new();
    let mut gaps = SourceCoverageGaps::default();
    for request in requests {
        match conn.round_trip(&request).await? {
            Response::MassFilesystemReady => {}
            Response::Error { message } => {
                bail!("mass daemon local filesystem route: {message}")
            }
            other => bail!(
                "mass daemon local filesystem route: expected MassFilesystemReady, got {}",
                response_kind(&other)
            ),
        }
        loop {
            match conn.round_trip(&Request::MassFilesystemNext).await? {
                response @ Response::ScanResults { .. } => {
                    if let Some(profile) = request_profile_of(&response) {
                        crate::orchestrator::render_daemon_request_profile(&profile);
                    }
                    let (batch_matches, batch_gaps) = unwrap_scan_results(response)?;
                    matches.extend(batch_matches);
                    merge_source_coverage(&mut gaps, batch_gaps);
                }
                Response::MassFilesystemComplete {
                    source_coverage_gaps,
                } => {
                    merge_source_coverage(&mut gaps, source_coverage_gaps);
                    break;
                }
                Response::Error { message } => {
                    bail!("mass daemon local filesystem route: {message}")
                }
                other => bail!(
                    "mass daemon local filesystem route: expected ScanResults or \
                     MassFilesystemComplete, got {}",
                    response_kind(&other)
                ),
            }
        }
    }
    Ok((matches, gaps))
}

#[cfg(unix)]
struct MassDaemonBatcher<'a> {
    conn: &'a mut client::Client,
    chunks: Vec<Chunk>,
    bytes: usize,
    source_bytes_scanned: u64,
    source_chunks_scanned: usize,
    matches: Vec<RawMatch>,
    source_coverage_gaps: SourceCoverageGaps,
}

#[cfg(unix)]
impl<'a> MassDaemonBatcher<'a> {
    fn new(conn: &'a mut client::Client) -> Self {
        Self {
            conn,
            chunks: Vec::with_capacity(MASS_BATCH_CHUNKS),
            bytes: 0,
            source_bytes_scanned: 0,
            source_chunks_scanned: 0,
            matches: Vec::new(),
            source_coverage_gaps: SourceCoverageGaps::default(),
        }
    }

    async fn push(&mut self, chunk: Chunk) -> Result<()> {
        let next_bytes = self
            .bytes
            .checked_add(chunk.data.len())
            .context("mass daemon batch byte count overflow")?;
        if !self.chunks.is_empty()
            && (self.chunks.len() >= MASS_BATCH_CHUNKS || next_bytes > MASS_BATCH_BYTES)
        {
            self.flush().await?;
        }
        self.bytes = self
            .bytes
            .checked_add(chunk.data.len())
            .context("mass daemon batch byte count overflow")?;
        self.source_bytes_scanned = self
            .source_bytes_scanned
            .saturating_add(chunk.data.len() as u64);
        self.source_chunks_scanned = self.source_chunks_scanned.saturating_add(1);
        self.chunks.push(chunk);
        if self.chunks.len() >= MASS_BATCH_CHUNKS || self.bytes >= MASS_BATCH_BYTES {
            self.flush().await?;
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<()> {
        if self.chunks.is_empty() {
            return Ok(());
        }
        let chunks = std::mem::take(&mut self.chunks);
        self.bytes = 0;
        let response = self.conn.round_trip(&Request::MassBatch { chunks }).await?;
        if let Some(profile) = request_profile_of(&response) {
            crate::orchestrator::render_daemon_request_profile(&profile);
        }
        let (matches, gaps) = unwrap_scan_results(response)?;
        self.matches.extend(matches);
        merge_source_coverage(&mut self.source_coverage_gaps, gaps);
        Ok(())
    }

    fn finish(self) -> (Vec<RawMatch>, usize, u64, SourceCoverageGaps) {
        (
            self.matches,
            self.source_chunks_scanned,
            self.source_bytes_scanned,
            self.source_coverage_gaps,
        )
    }
}

#[cfg(unix)]
pub(crate) fn split_chunk_for_mass(chunk: Chunk) -> Result<Vec<Chunk>> {
    if chunk.data.len() <= MASS_BATCH_BYTES {
        return Ok(vec![chunk]);
    }
    if chunk.metadata.decoded_span.is_some() {
        bail!(
            "decoded source chunk at {} is {} bytes, above the {} byte mass-batch limit",
            chunk.metadata.path.as_deref().unwrap_or("<unknown>"), // LAW10: absent path => reporting-only error label; the oversized decoded chunk still fails closed.
            chunk.data.len(),
            MASS_BATCH_BYTES
        );
    }

    let text = chunk.data.as_ref();
    let mut pieces = Vec::with_capacity(text.len().div_ceil(MASS_BATCH_BYTES));
    let mut start = 0usize;
    let mut line_offset = 0usize;
    while start < text.len() {
        let mut end = start.saturating_add(MASS_BATCH_BYTES).min(text.len());
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            bail!("mass daemon could not split a UTF-8 chunk at a valid character boundary");
        }
        let mut metadata = chunk.metadata.clone();
        metadata.base_offset = metadata
            .base_offset
            .checked_add(start)
            .context("mass daemon chunk base offset overflow")?;
        metadata.base_line = metadata
            .base_line
            .checked_add(line_offset)
            .context("mass daemon chunk base line overflow")?;
        pieces.push(Chunk {
            data: text[start..end].to_owned().into(),
            metadata,
        });
        line_offset = line_offset.saturating_add(
            text[start..end]
                .as_bytes()
                .iter()
                .filter(|byte| **byte == b'\n')
                .count(),
        );
        start = end;
    }
    Ok(pieces)
}

#[cfg(unix)]
fn source_coverage_since(
    before: keyhog_sources::SkipCounts,
    source_failed: usize,
) -> SourceCoverageGaps {
    let after = keyhog_sources::skip_counts();
    SourceCoverageGaps {
        over_max_size: after.over_max_size.saturating_sub(before.over_max_size),
        binary: after.binary.saturating_sub(before.binary),
        unreadable: after.unreadable.saturating_sub(before.unreadable),
        git_object_unreadable: after
            .git_object_unreadable
            .saturating_sub(before.git_object_unreadable),
        archive_truncated: after
            .archive_truncated
            .saturating_sub(before.archive_truncated),
        binary_section_name_unresolved: after
            .binary_section_name_unresolved
            .saturating_sub(before.binary_section_name_unresolved),
        source_truncated: after
            .source_truncated
            .saturating_sub(before.source_truncated),
        structured_source_parse_failures: after
            .structured_source_parse_failures
            .saturating_sub(before.structured_source_parse_failures),
        archive_duplicate_scan_unavailable: after
            .archive_duplicate_scan_unavailable
            .saturating_sub(before.archive_duplicate_scan_unavailable),
        git_lfs_pointer: after.git_lfs_pointer.saturating_sub(before.git_lfs_pointer),
        source_failed,
    }
}

#[cfg(unix)]
fn merge_source_coverage(target: &mut SourceCoverageGaps, source: SourceCoverageGaps) {
    target.over_max_size = target.over_max_size.saturating_add(source.over_max_size);
    target.binary = target.binary.saturating_add(source.binary);
    target.unreadable = target.unreadable.saturating_add(source.unreadable);
    target.git_object_unreadable = target
        .git_object_unreadable
        .saturating_add(source.git_object_unreadable);
    target.archive_truncated = target
        .archive_truncated
        .saturating_add(source.archive_truncated);
    target.binary_section_name_unresolved = target
        .binary_section_name_unresolved
        .saturating_add(source.binary_section_name_unresolved);
    target.source_truncated = target
        .source_truncated
        .saturating_add(source.source_truncated);
    target.structured_source_parse_failures = target
        .structured_source_parse_failures
        .saturating_add(source.structured_source_parse_failures);
    target.archive_duplicate_scan_unavailable = target
        .archive_duplicate_scan_unavailable
        .saturating_add(source.archive_duplicate_scan_unavailable);
    target.git_lfs_pointer = target
        .git_lfs_pointer
        .saturating_add(source.git_lfs_pointer);
    target.source_failed = target.source_failed.saturating_add(source.source_failed);
}

#[cfg(unix)]
async fn run_via_daemon(args: &mut ScanArgs) -> Result<ExitCode> {
    let scan = acquire_via_daemon(args).await?;
    finish_daemon_scan(scan, args)
}

#[cfg(unix)]
struct DaemonScan {
    matches: Vec<RawMatch>,
    source_coverage_gaps: SourceCoverageGaps,
    source_bytes_scanned: u64,
    source_chunks_scanned: usize,
    wall_start: chrono::DateTime<chrono::Utc>,
    detector_corpus_digest: String,
    detector_corpus_provenance: crate::orchestrator_config::DetectorCorpusProvenance,
    detector_count: usize,
    /// Isolated per-request profile returned by a v12 daemon when
    /// `--profile` was forwarded; `None` when profiling was not requested.
    profile: Option<RequestProfile>,
}

#[cfg(unix)]
async fn acquire_via_daemon(args: &mut ScanArgs) -> Result<DaemonScan> {
    crate::reset_scan_runtime_state();
    if args.dogfood {
        keyhog_scanner::telemetry::enable_dogfood();
    }
    let wall_start = chrono::Utc::now();
    let socket = effective_daemon_socket(args);
    let ExpectedDaemonDetectorCorpus {
        rules_digest,
        corpus_digest: detector_corpus_digest,
        provenance: detector_corpus_provenance,
        detector_count,
    } = expected_daemon_detector_corpus(args)?;
    let mut conn = match rules_digest {
        Some(digest) => client::connect_with_detector_rules_digest(&socket, digest).await,
        None => client::connect(&socket).await,
    }
    .with_context(|| {
        format!(
            "daemon route: connect to {} (start one with `keyhog daemon start{}` or pass --daemon=off)",
            socket.display(),
            match &args.daemon_socket {
                Some(path) => format!(" --socket {}", path.display()),
                None => String::new(),
            },
        )
    })?;

    let (matches, source_coverage_gaps, source_bytes_scanned, profile) = if args.stdin {
        let bytes: std::sync::Arc<[u8]> = read_stdin_bytes(args)?.into();
        let source_bytes_scanned = bytes.len() as u64;
        // Keep a shared exact payload until the daemon route completes. An
        // automatic fallback reuses it without copying the bounded stdin body.
        args.buffered_stdin = Some(std::sync::Arc::clone(&bytes));
        let stdin_cap_bytes = args.limits.to_source_limits().stdin_bytes;
        if bytes.len() > stdin_cap_bytes {
            bail!(
                "daemon route: stdin exceeds {stdin_cap_bytes} byte limit. +                 Drop `--daemon` to use the streaming in-process path."
            );
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let resp = conn
            .round_trip(&Request::ScanText {
                path: None,
                text,
                dogfood: args.dogfood,
                profile: args.profile,
            })
            .await?;
        let profile = request_profile_of(&resp);
        let (matches, gaps) = unwrap_scan_results(resp)?;
        (matches, gaps, source_bytes_scanned, profile)
    } else if let Some(path) = effective_single_file_path(args)? {
        let source_bytes_scanned = std::fs::metadata(path)
            .with_context(|| format!("stat daemon input {}", path.display()))?
            .len();
        let working_dir = std::env::current_dir()
            .ok() // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
            .map(|p| p.to_string_lossy().into_owned());
        let resp = conn
            .round_trip(&Request::ScanPath {
                path: path.to_string_lossy().into_owned(),
                working_dir,
                dogfood: args.dogfood,
                profile: args.profile,
            })
            .await?;
        let profile = request_profile_of(&resp);
        let (matches, gaps) = unwrap_scan_results(resp)?;
        (matches, gaps, source_bytes_scanned, profile)
    } else {
        bail!(
            "daemon route requires either --stdin or a single file path. \
             For directory scans, pass `--daemon=off` to use the in-process scanner."
        );
    };

    Ok(DaemonScan {
        matches,
        source_coverage_gaps,
        source_bytes_scanned,
        source_chunks_scanned: 1,
        wall_start,
        detector_corpus_digest,
        detector_corpus_provenance,
        detector_count,
        profile,
    })
}

#[cfg(unix)]
fn finish_daemon_scan(scan: DaemonScan, args: &ScanArgs) -> Result<ExitCode> {
    let DaemonScan {
        matches,
        source_coverage_gaps,
        source_bytes_scanned,
        source_chunks_scanned,
        wall_start,
        detector_corpus_digest,
        detector_corpus_provenance,
        detector_count,
        profile,
    } = scan;
    let findings = finalize_for_report(matches, args)?;
    crate::TOTAL_CHUNKS.store(source_chunks_scanned, std::sync::atomic::Ordering::Relaxed);
    crate::SCANNED_CHUNKS.store(source_chunks_scanned, std::sync::atomic::Ordering::Relaxed);
    crate::SCANNED_BYTES.store(source_bytes_scanned, std::sync::atomic::Ordering::Relaxed);
    let report_finished_at = chrono::Utc::now();
    let mut report_metadata = crate::reporting::report_metadata_from_scan_run_with_corpus(
        args,
        wall_start,
        report_finished_at,
        (report_finished_at - wall_start).num_milliseconds().max(0) as u128,
        source_chunks_scanned,
        source_bytes_scanned,
        detector_count,
        &detector_corpus_digest,
        &detector_corpus_provenance,
        None,
    );
    // Merge daemon wire gaps into process-local skip counters so
    // CoverageCounts / SARIF notifications match in-process scans (KH-1369).
    if !source_coverage_gaps.is_empty() {
        keyhog_sources::merge_skip_count_deltas(&keyhog_sources::SkipCounts {
            over_max_size: source_coverage_gaps.over_max_size,
            binary: source_coverage_gaps.binary,
            excluded: 0,
            unreadable: source_coverage_gaps.unreadable,
            git_object_unreadable: source_coverage_gaps.git_object_unreadable,
            archive_truncated: source_coverage_gaps.archive_truncated,
            binary_section_name_unresolved: source_coverage_gaps.binary_section_name_unresolved,
            source_truncated: source_coverage_gaps.source_truncated,
            structured_source_parse_failures: source_coverage_gaps.structured_source_parse_failures,
            archive_duplicate_scan_unavailable: source_coverage_gaps
                .archive_duplicate_scan_unavailable,
            git_lfs_pointer: source_coverage_gaps.git_lfs_pointer,
        });
    }
    // Partial status when any gap (WARN or FAIL) was observed; exit 13 only
    // for FAIL-class gaps so daemon matches local scan (KH-1368).
    if !source_coverage_gaps.is_empty() {
        report_metadata.scan_status = ScanCompletionStatus::Partial;
    }
    crate::reporting::report_findings_with_metadata(&findings, args, &report_metadata)?;
    if let Some(profile) = &profile {
        crate::orchestrator::render_daemon_request_profile(profile);
    }
    if args.dogfood {
        crate::orchestrator::reporting::dump_dogfood_trace();
    }

    let fail_gaps = source_coverage_gaps.fail_class_total();
    if fail_gaps > 0 {
        let palette = crate::style::for_stderr();
        eprintln!(
            "{}: daemon input coverage was incomplete ({} FAIL-class gap(s), {} total gap(s)); some requested bytes were not scanned.",
            crate::style::warn("warning", &palette),
            fail_gaps,
            source_coverage_gaps.total()
        );
    }

    let exit = if findings.is_empty() && fail_gaps > 0 {
        let palette = crate::style::for_stderr();
        eprintln!(
            "{}: not reporting \"clean\" after incomplete daemon input coverage.",
            crate::style::fail("error", &palette)
        );
        EXIT_SOURCE_FAILED
    } else if findings.is_empty() {
        crate::exit_codes::EXIT_SUCCESS
    } else {
        // Same live-vs-findings precedence as in-process `resolve_scan_exit`
        // (KH-1379): a Live finding must exit 10, not collapse to exit 1.
        let code = crate::orchestrator::scan_exit_code(&findings);
        if code == EXIT_LIVE_CREDENTIALS {
            EXIT_LIVE_CREDENTIALS
        } else {
            EXIT_CREDENTIALS_FOUND
        }
    };
    crate::action_report::write_scan_receipt(
        args,
        findings.len(),
        exit,
        report_metadata.scan_status,
    )?;
    Ok(ExitCode::from(exit))
}

/// Finish a guard commit transaction scan. Maps the daemon's
/// finding count and coverage gaps to the same exit codes as
/// the in-process and daemon scan paths.
#[cfg(all(unix, feature = "git"))]
fn finish_guard_commit_scan(
    result: crate::daemon::guard_commit::GuardCommitResult,
    args: &ScanArgs,
) -> Result<ExitCode> {
    use crate::exit_codes::{EXIT_CREDENTIALS_FOUND, EXIT_SOURCE_FAILED, EXIT_SUCCESS};

    // Report cache hit statistics to stderr.
    let palette = crate::style::for_stderr();
    eprintln!(
        "{} guard: {} cache hit(s), {} blob(s) scanned, {} byte(s) scanned",
        crate::style::pass("OK", &palette),
        result.cache_hits,
        result.blobs_scanned,
        result.bytes_scanned
    );

    let exit = if result.fingerprint_changed {
        eprintln!(
            "{}: guard commit: staged index changed during transaction; the scanned content may not match what is now staged.",
            crate::style::fail("error", &palette)
        );
        EXIT_SOURCE_FAILED
    } else if result.coverage_gaps > 0 && result.findings_count == 0 {
        eprintln!(
            "{}: guard commit: {} coverage gap(s); not reporting clean after incomplete coverage.",
            crate::style::fail("error", &palette),
            result.coverage_gaps
        );
        EXIT_SOURCE_FAILED
    } else if result.findings_count > 0 {
        eprintln!(
            "{}: guard commit: {} unsuppressed finding(s).",
            crate::style::fail("error", &palette),
            result.findings_count
        );
        EXIT_CREDENTIALS_FOUND
    } else {
        EXIT_SUCCESS
    };
    crate::action_report::write_scan_receipt(
        args,
        result.findings_count as usize,
        exit,
        keyhog_core::ScanCompletionStatus::from_coverage_gaps(result.coverage_gaps > 0),
    )?;
    Ok(ExitCode::from(exit))
}

#[cfg(unix)]
fn read_stdin_bytes(args: &ScanArgs) -> Result<Vec<u8>> {
    use std::io::Read;
    let stdin_cap_bytes = args.limits.to_source_limits().stdin_bytes;
    let mut buf = Vec::with_capacity(8 * 1024);
    std::io::stdin()
        .lock()
        .take(stdin_cap_bytes.saturating_add(1) as u64)
        .read_to_end(&mut buf)
        .context("daemon route: reading stdin")?;
    Ok(buf)
}

/// Extract the isolated per-request profile a v12 daemon attached to a
/// `ScanResults` frame, without consuming the response. `None` for any other
/// response kind and for requests that did not ask for a profile.
#[cfg(unix)]
fn request_profile_of(resp: &Response) -> Option<RequestProfile> {
    match resp {
        Response::ScanResults { profile, .. } => profile.clone().into(),
        _ => None,
    }
}

#[cfg(unix)]
pub(crate) fn unwrap_scan_results(resp: Response) -> Result<(Vec<RawMatch>, SourceCoverageGaps)> {
    match resp {
        Response::ScanResults {
            matches,
            engine_example_suppressions,
            dogfood_events,
            static_recovery_rejections,
            static_recovery_status,
            dogfood_detail_events_dropped,
            source_coverage_gaps,
            backend_recovery,
            ..
        } => {
            // Merge daemon-side telemetry into the CLI's process-local
            // counters. The reporter and `dump_dogfood_trace()` both
            // read these, so without the merge the count would stay
            // at 0 (the OnceLock cell here is distinct from the
            // daemon's). Wire v4 requires exact aggregates on every
            // ScanResults frame; the Hello handshake rejects older peers
            // before a scan request is sent.
            // Validate the reason vocabulary before mutating any client-side
            // telemetry. A newer daemon must not leave partial replay state in
            // this process when its aggregate schema is incompatible.
            keyhog_scanner::telemetry::merge_daemon_aggregates(
                &static_recovery_rejections,
                static_recovery_status,
                dogfood_detail_events_dropped,
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "daemon returned incompatible dogfood telemetry: {error}. Restart it with `keyhog daemon stop && keyhog daemon start`, or pass `--daemon=off`."
                )
            })?;
            if engine_example_suppressions > 0 {
                keyhog_scanner::telemetry::add_example_suppressions(
                    engine_example_suppressions as usize,
                );
            }
            if !dogfood_events.is_empty() {
                keyhog_scanner::telemetry::append_daemon_events(dogfood_events);
            }
            if let RequiredOption::Some(recovery) = backend_recovery {
                let failed_backend = keyhog_scanner::hw_probe::parse_backend_str(
                    &recovery.failed_backend,
                )
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "daemon returned unknown failed backend {:?}; restart it with this KeyHog build",
                        recovery.failed_backend
                    )
                })?;
                let recovery_backend = keyhog_scanner::hw_probe::parse_backend_str(
                    &recovery.recovery_backend,
                )
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "daemon returned unknown recovery backend {:?}; restart it with this KeyHog build",
                        recovery.recovery_backend
                    )
                })?;
                let receipt = keyhog_scanner::BackendRecoveryReceipt::new(
                    failed_backend,
                    recovery_backend,
                    recovery
                        .recovered_ranges
                        .into_iter()
                        .map(|range| {
                            keyhog_scanner::RecoveredInputRange::new(
                                range.chunk_index,
                                range.byte_start,
                                range.byte_end,
                            )
                        })
                        .collect(),
                    recovery.reason,
                );
                if receipt.recovered_chunks() != recovery.recovered_chunks
                    || receipt.recovered_bytes() != recovery.recovered_bytes
                {
                    bail!(
                        "daemon returned inconsistent backend-recovery totals; restart it with this KeyHog build"
                    );
                }
                crate::orchestrator::record_completed_backend_recovery(&receipt);
            }
            Ok((matches, source_coverage_gaps))
        }
        Response::Error { message } => bail!("daemon: {message}"),
        other => bail!("daemon route: expected ScanResults, got {other:?}"),
    }
}

#[cfg(unix)]
fn finalize_for_report(matches: Vec<RawMatch>, args: &ScanArgs) -> Result<Vec<VerifiedFinding>> {
    // Test-fixture suppression mirrors the orchestrator's
    // pipeline_tests::* filter: known-public example credentials
    // (Stripe's sk_live_4eC39…, GitHub's ghp_… README sample, …) get
    // suppressed unless the user explicitly opts out with
    // --no-suppress-test-fixtures.
    let fixtures = if args.no_suppress_test_fixtures {
        crate::test_fixture_suppressions::TestFixtureSuppressions::empty()
    } else {
        crate::test_fixture_suppressions::TestFixtureSuppressions::bundled()
    };

    // The daemon process runs only the scanner: it does NOT load the
    // CLI-side `.keyhogignore` allowlist, the `.keyhogignore.toml`
    // declarative rule suppressor, or apply inline `keyhog:ignore`
    // comment directives. The in-process orchestrator applies all three
    // (`filter_and_resolve` + the rule-suppressor pass in `run.rs`).
    // Without replicating them here, routing an eligible single-file or
    // stdin scan over the daemon would silently un-suppress findings the
    // user explicitly allowlisted - results that change purely because a
    // daemon socket happens to be live. Anchor the allowlist files at the
    // same root the orchestrator uses: the scanned path's directory, or
    // "." for the stdin / bare-filename case.
    let allowlist = load_daemon_allowlist(args)?;

    // Mirror the in-process orchestrator's behaviour: when the
    // test-fixture filter drops a credential, bump the example-suppression
    // telemetry so the reporter's empty-findings summary distinguishes "no
    // matches at all" from "matched and suppressed as a known test
    // fixture". The daemon process runs its own scanner (with its own
    // telemetry counters that this CLI can't see), so the CLI must record
    // the suppression itself based on what came back over the wire.
    let mut matches: Vec<RawMatch> = matches
        .into_iter()
        .filter(|m| {
            if crate::orchestrator::suppresses_test_fixture(&fixtures, m) {
                return false;
            }
            // `.keyhogignore` legacy line-based allowlist: path globs,
            // credential-hash entries, and whole-detector ignores. Same
            // predicates the orchestrator runs in `filter_and_resolve`.
            if crate::orchestrator::suppresses_allowlist_match(&allowlist, m) {
                return false;
            }
            true
        })
        .collect();

    // Match resolution mirrors `ScanOrchestrator::filter_and_resolve`: named
    // service detectors beat generic/entropy matches on the same secret line
    // before cross-detector dedup picks a winner. Without this, daemon stdin can
    // report `entropy-api-key` for an AKIA value even though the scanner also
    // found the canonical `aws-access-key`.
    matches = keyhog_scanner::resolution::try_resolve_matches(matches)
        .map_err(anyhow::Error::msg)
        .context("failed to resolve matches; fix the detector definitions")?;

    // Inline `keyhog:ignore` / `gitleaks:allow` comment suppression. The
    // shared filter only acts on matches whose source is "filesystem"
    // (it re-opens `file_path` to read the directive line); daemon
    // `ScanPath` matches carry the daemon's own `source_type`
    // ("daemon/scan_path"), so normalise filesystem-backed matches to the
    // "filesystem" source before the call. A daemon single-file scan IS a
    // filesystem read, and `file_path` points at the real on-disk file,
    // so this is the same suppression the in-process path performs.
    // stdin/`ScanText` matches have no `file_path` and are left untouched
    // by the filter regardless of source.
    let filesystem_source = std::sync::Arc::<str>::from("filesystem");
    for m in &mut matches {
        if m.location.file_path.is_some() && m.location.source.as_ref() != "filesystem" {
            m.location.source = filesystem_source.clone();
        }
    }
    let matches = crate::inline_suppression::filter_inline_suppressions(matches);

    let scope = args.dedup.to_core();
    let deduped = crate::orchestrator::dedup_for_report(matches, &scope);
    let findings = crate::orchestrator::skipped_findings_from_deduped(deduped, args.show_secrets);

    // `.keyhogignore.toml` declarative rule suppressor (vyre rule engine).
    // The orchestrator applies this AFTER dedup on the final
    // `VerifiedFinding` set (see `orchestrator::run`), so we match that
    // ordering exactly. A missing/empty file is a no-op.
    let rule_suppressor = load_daemon_rule_suppressor(args)?;
    Ok(findings
        .into_iter()
        .filter(|f| !rule_suppressor.matches(f))
        .collect())
}

/// Resolve the directory used to discover `.keyhogignore` /
/// `.keyhogignore.toml` for a daemon-routed scan. Mirrors
/// `orchestrator::allowlist::allowlist_root`: a scanned directory is its
/// own root, a scanned file delegates to its parent, and the stdin /
/// bare-filename case falls back to ".".
#[cfg(unix)]
fn daemon_allowlist_root(args: &ScanArgs) -> PathBuf {
    let Some(path) = args
        .path
        .as_deref()
        .or_else(|| args.input.first().map(PathBuf::as_path))
    else {
        return PathBuf::from(".");
    };
    if path.is_dir() {
        return path.to_path_buf();
    }
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(".")) // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
}

/// Load the legacy line-based `.keyhogignore` allowlist for the daemon route.
/// A malformed file is a policy failure, not an empty allowlist.
#[cfg(unix)]
fn load_daemon_allowlist(args: &ScanArgs) -> Result<keyhog_core::Allowlist> {
    let ignore_path = daemon_allowlist_root(args).join(".keyhogignore");
    if ignore_path.exists() {
        keyhog_core::Allowlist::load_with_metadata_policy(
            &ignore_path,
            false,
            false,
            None,
        )
        .with_context(|| {
            format!(
                "daemon route: failed to load {}. Fix or remove the allowlist; refusing to scan with silently ignored policy.",
                ignore_path.display()
            )
        })
    } else {
        Ok(keyhog_core::Allowlist::default())
    }
}

/// Load the declarative `.keyhogignore.toml` rule suppressor for the daemon
/// route. A malformed file is a policy failure, not an empty suppressor.
#[cfg(unix)]
fn load_daemon_rule_suppressor(args: &ScanArgs) -> Result<RuleSuppressor> {
    let toml_path = daemon_allowlist_root(args).join(".keyhogignore.toml");
    if !toml_path.exists() {
        return Ok(RuleSuppressor::default());
    }
    let raw = std::fs::read_to_string(&toml_path).with_context(|| {
        format!(
            "daemon route: failed to read {}. Fix file permissions or remove the file; refusing \
             to scan with silently ignored suppression rules.",
            toml_path.display()
        )
    })?;
    match raw.parse::<RuleSuppressor>() {
        Ok(s) => Ok(s),
        Err(e) => anyhow::bail!(
            "daemon route: failed to load {}: {e}. Fix the TOML schema \
             (see docs/src/reference/keyhogignore-toml.md) or remove the file; refusing to scan \
             with silently ignored suppression rules.",
            toml_path.display()
        ),
    }
}
