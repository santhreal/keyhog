//! Logic for the `scan` subcommand.
//!
//! Default: build a [`ScanOrchestrator`] and run the full in-process
//! pipeline. For the simple stdin / single-file case there is also a
//! daemon fast path: when `--daemon=auto` sees a live socket, eligible
//! stdin / single-file scans go through the running `keyhog daemon`
//! and skip the ~3 s `CompiledScanner::compile` cold start. The daemon
//! path is deliberately narrow - it can honor stdin and a single regular
//! file through the source-owned filesystem expansion path; directory
//! walks, git-staged scans, baseline filtering, merkle skip cache, and
//! verification still go through the orchestrator. `--daemon=on` is a hard
//! contract: if the daemon cannot honor the requested scan exactly, the
//! command fails instead of silently running a different path.

use crate::args::{DaemonMode, ScanArgs};
#[cfg(unix)]
use crate::exit_codes::{EXIT_CREDENTIALS_FOUND, EXIT_SOURCE_FAILED};
// Daemon module is unix-only - Windows has no `tokio::net::UnixListener`
// or `std::os::unix::net::UnixStream`, so the whole `crate::daemon`
// subtree is `#[cfg(unix)]`. See `lib.rs` for the rationale. On
// Windows, the `--daemon` flag and daemon selection in
// `daemon_route` short-circuit to `Forbidden` (or emit a clear
// "daemon is unix-only" error if the user explicitly passed
// `--daemon`).
#[cfg(unix)]
use crate::daemon::client;
#[cfg(unix)]
use crate::daemon::protocol::{Request, Response, SourceCoverageGaps};
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
use keyhog_core::{RawMatch, RuleSuppressor, VerifiedFinding};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub(crate) async fn run(args: ScanArgs) -> Result<ExitCode> {
    crate::runtime_preflight::validate_scan_runtime_config()?;
    guard_multi_root_combinations(&args)?;

    // On Windows, the daemon route is never available (the `crate::daemon`
    // module is cfg(unix)). If the user explicitly passed `--daemon`,
    // refuse loudly so they don't silently get the in-process path; if
    // they didn't, fall straight through to the orchestrator.
    #[cfg(not(unix))]
    {
        if args.daemon_mode() == DaemonMode::On {
            bail!(
                "`--daemon=on` is a unix-only flag (the daemon serves scans \
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
    // `daemon_route` — letting a config min_confidence floor, a config
    // `[lockdown] require = true` fail-closed guard, or a config
    // `show_secrets` be silently bypassed whenever a daemon happened to be
    // live. Merge onto a throwaway clone so the real `args` the orchestrator
    // consumes is untouched (it re-merges identically), then route on the
    // EFFECTIVE values.
    #[cfg(unix)]
    let policy = EffectivePolicy::resolve(&args);
    #[cfg(unix)]
    match daemon_route(&args, &policy) {
        DaemonRoute::Required => run_via_daemon(&policy.effective_args).await,
        DaemonRoute::Opportunistic => match run_via_daemon(&policy.effective_args).await {
            Ok(exit) => Ok(exit),
            Err(e) => {
                if policy.effective_args.daemon_mode() == DaemonMode::Auto {
                    let palette = crate::style::for_stderr();
                    eprintln!(
                        "{}: daemon auto route unavailable ({e:#}); running in-process scanner",
                        crate::style::warn("keyhog", &palette)
                    );
                }
                // LAW10: opportunistic daemon failure is reported on stderr in
                // auto mode, then the same scan runs in-process.
                tracing::debug!(
                    error = %e,
                    "daemon auto route unavailable; running in-process scanner"
                );
                let orchestrator = ScanOrchestrator::new(args)?;
                orchestrator.run().await
            }
        },
        DaemonRoute::Rejected(reason) => bail!("{reason}"),
        DaemonRoute::Forbidden => {
            let orchestrator = ScanOrchestrator::new(args)?;
            orchestrator.run().await
        }
    }
}

#[cfg(unix)]
enum DaemonRoute {
    Required,
    Opportunistic,
    Forbidden,
    Rejected(String),
}

/// Fail closed when several positional roots are combined with a mode that has
/// no unambiguous meaning over more than one root.
///
/// keyhog now scans multiple roots per invocation (`keyhog scan a/ b/ c/`):
/// each becomes its own filesystem source and the engine merges the multi-
/// source `Vec` it already consumes. The only positional-root mode that breaks
/// is `--git-staged`, whose staged-file set is resolved from a SINGLE repository
/// working tree (`get_staged_files(first_root)`); with several roots there is no
/// one repo to read, and silently staged-filtering only the first root while
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
        // whose policy we are trying to honour — the exact bug this resolves.
        if probe.path.is_none() {
            probe.path = probe.input.clone();
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
        #[cfg(not(feature = "verify"))]
        let verify = false;
        let severity = probe.severity.is_some();
        EffectivePolicy {
            effective_args: probe,
            min_confidence,
            show_secrets,
            verify,
            severity,
            require_lockdown: outcome.require_lockdown,
            has_config_errors: !outcome.config_errors.is_empty(),
            custom_aws_canary_accounts: !outcome.aws_canary_accounts.is_empty(),
            has_allowlist_config: outcome.allowlist_file.is_some()
                || outcome.allowlist_require_reason
                || outcome.allowlist_require_approved_by
                || outcome.allowlist_max_expires_days.is_some(),
        }
    }
}

#[cfg(unix)]
fn daemon_route(args: &ScanArgs, policy: &EffectivePolicy) -> DaemonRoute {
    let mode = args.daemon_mode();
    if mode == DaemonMode::Off {
        return DaemonRoute::Forbidden;
    }
    let forced_on = mode == DaemonMode::On;

    // Daemon path doesn't run verification - the daemon process holds a
    // scanner but not the verifier engine. Trying to honour `--verify` or
    // config `verify = true` over a daemon-only result set would silently drop
    // every API-call-backed live-credential check; the orchestrator is the
    // only honest answer.
    #[cfg(feature = "verify")]
    if policy.verify {
        if let Some(route) = reject_forced_daemon(
            forced_on,
            "verification requires the in-process verifier; the daemon only returns scanner matches",
        ) {
            return route;
        }
        return DaemonRoute::Forbidden;
    }
    if args.baseline.is_some() {
        if let Some(route) = reject_forced_daemon(
            forced_on,
            "--baseline requires the in-process baseline filter; the daemon has no baseline state",
        ) {
            return route;
        }
        return DaemonRoute::Forbidden;
    }

    let single_file = match effective_single_file_path(args) {
        Ok(path) => path.is_some(),
        Err(error) => {
            if let Some(route) = reject_forced_daemon(
                forced_on,
                &format!(
                    "the daemon single-file route cannot inspect the requested path: {error:#}"
                ),
            ) {
                return route;
            }
            return DaemonRoute::Forbidden;
        }
    };
    let primary_sources = usize::from(args.stdin) + usize::from(single_file);
    if primary_sources != 1 || has_daemon_incompatible_extra_sources(args) {
        if let Some(route) = reject_forced_daemon(
            forced_on,
            "the daemon only supports exactly one source: --stdin or a single regular file; directories, git, remote, binary, dynamic, and multi-source scans require the in-process scanner",
        ) {
            return route;
        }
        return DaemonRoute::Forbidden;
    }

    // The daemon's client-side finalize mirrors allowlist/rule suppression,
    // inline suppression, match resolution, and dedup for daemon-eligible scans.
    // It still does NOT run live verification or enforce the policy/security
    // gates below (lockdown protections, secret-output policy, severity hiding,
    // client-safe hiding, or explicit confidence-floor policy). Routing a scan
    // that requests any of those over the daemon would silently change results
    // or bypass a hard security guard — and the opportunistic route flips on
    // merely because a daemon socket exists. Force the in-process path whenever
    // such policy is in play, so behavior never depends on whether a daemon
    // happens to be running.
    //
    // This SECURITY-policy check runs BEFORE the generic backend/GPU/batch
    // operational-controls check below: when a scan requests BOTH a fail-closed
    // security control (lockdown, secret-output) AND an operational control
    // (e.g. `--backend`), the refusal must name the security policy that cannot
    // be enforced, not merely the operational knob — the operator needs to know
    // their lockdown / secret-output intent is what the daemon can't honor.
    //
    // Critically, the floor / lockdown-require / show_secrets / severity checks
    // read the EFFECTIVE post-`.keyhog.toml`-merge policy, not just the raw CLI
    // flags: a `.keyhog.toml` `min_confidence`, `[lockdown] require = true`, or
    // `show_secrets` set via the config file (with no matching CLI flag) must
    // forbid the daemon route too — otherwise scan RESULTS and a fail-closed
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
        || args.hide_client_safe
    {
        if let Some(route) = reject_forced_daemon(
            forced_on,
            "this scan requests filtering, lockdown, secret-output, AWS canary config, allowlist governance, or config policy the daemon cannot enforce",
        ) {
            return route;
        }
        return DaemonRoute::Forbidden;
    }

    if let Some(reason) = daemon_incompatible_scan_options(&policy.effective_args) {
        if let Some(route) = reject_forced_daemon(forced_on, reason) {
            return route;
        }
        return DaemonRoute::Forbidden;
    }

    if forced_on {
        return DaemonRoute::Required;
    }

    // Opportunistic route flips on only when a live daemon is actually at the
    // socket we'd connect to — the `--daemon-socket` override when present, else
    // the default. Probing the default while a scan targeted an override socket
    // would mis-route (treat an unrelated daemon as ours, or miss the real one).
    if effective_daemon_socket(args).exists() {
        DaemonRoute::Opportunistic
    } else {
        DaemonRoute::Forbidden
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
        // LAW10: intentional_default — absent --daemon-socket => documented default
        // socket; Tier-A transport knob, recall-irrelevant.
        .unwrap_or_else(default_socket_path)
}

#[cfg(unix)]
fn reject_forced_daemon(forced_on: bool, reason: &str) -> Option<DaemonRoute> {
    forced_on.then(|| {
        DaemonRoute::Rejected(format!(
            "--daemon=on cannot be honored: {reason}. Drop `--daemon=on`, or pass \
             `--daemon=off` / `--no-daemon` to run the in-process scanner explicitly."
        ))
    })
}

#[cfg(unix)]
fn has_daemon_incompatible_extra_sources(args: &ScanArgs) -> bool {
    #[cfg(feature = "binary")]
    if args.binary {
        return true;
    }
    #[cfg(feature = "git")]
    if args.git_blobs.is_some()
        || args.git_diff.is_some()
        || args.git_history.is_some()
        || args.git_staged
    {
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
        || args.dogfood
    {
        return Some(
            "this scan sets scan-mode, engine, benchmark, or dogfood options that require the in-process scanner",
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
        || args.min_secret_len.is_some()
        || args.ml_weight.is_some()
        || args.max_file_size.is_some()
        || args.regex_dfa_limit.is_some()
        || args.cache_dir.is_some()
        || args.ml_threshold.is_some()
    {
        return Some(
            "this scan changes scanner or source-limit configuration that the precompiled daemon scanner cannot honor",
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
fn effective_single_file_path(args: &ScanArgs) -> Result<Option<&Path>> {
    // Several positional roots are never a daemon single-file candidate. Reading
    // only `path`/`input` here would see the FIRST root, route the scan over the
    // single-path daemon protocol, and silently drop every surplus root (Law 10).
    if !args.extra_paths.is_empty() {
        return Ok(None);
    }
    let Some(raw) = args.path.as_deref().or(args.input.as_deref()) else {
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
async fn run_via_daemon(args: &ScanArgs) -> Result<ExitCode> {
    let wall_start = chrono::Utc::now();
    let socket = effective_daemon_socket(args);
    let mut conn = client::connect(&socket).await.with_context(|| {
        format!(
            "daemon route: connect to {} (start one with `keyhog daemon start{}` or pass --no-daemon)",
            socket.display(),
            match &args.daemon_socket {
                Some(path) => format!(" --socket {}", path.display()),
                None => String::new(),
            },
        )
    })?;

    let (matches, source_coverage_gaps) = if args.stdin {
        let text = read_stdin_to_string(args)?;
        let resp = conn
            .round_trip(&Request::ScanText { path: None, text })
            .await?;
        unwrap_scan_results(resp)?
    } else if let Some(path) = effective_single_file_path(args)? {
        let working_dir = std::env::current_dir()
            .ok() // LAW10: malformed input => None (fail-closed at the boundary), recall-safe
            .map(|p| p.to_string_lossy().into_owned());
        let resp = conn
            .round_trip(&Request::ScanPath {
                path: path.to_string_lossy().into_owned(),
                working_dir,
            })
            .await?;
        unwrap_scan_results(resp)?
    } else {
        bail!(
            "daemon route requires either --stdin or a single file path. \
             For directory scans, pass `--no-daemon` to use the in-process scanner."
        );
    };

    let findings = finalize_for_report(matches, args)?;
    let report_finished_at = chrono::Utc::now();
    let report_metadata = crate::reporting::ReportMetadata::from_scan_run(
        args,
        wall_start,
        report_finished_at,
        (report_finished_at - wall_start).num_milliseconds().max(0) as u128,
        1,
        keyhog_core::embedded_detector_count(),
    );
    crate::reporting::report_findings_with_metadata(&findings, args, &report_metadata)?;

    if !source_coverage_gaps.is_empty() {
        let palette = crate::style::for_stderr();
        eprintln!(
            "{}: daemon input coverage was incomplete ({} source gap(s)); some requested bytes were not scanned.",
            crate::style::warn("warning", &palette),
            source_coverage_gaps.total()
        );
    }

    if findings.is_empty() && !source_coverage_gaps.is_empty() {
        let palette = crate::style::for_stderr();
        eprintln!(
            "{}: not reporting \"clean\" after incomplete daemon input coverage.",
            crate::style::fail("error", &palette)
        );
        Ok(ExitCode::from(EXIT_SOURCE_FAILED))
    } else if findings.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_CREDENTIALS_FOUND))
    }
}

#[cfg(unix)]
fn read_stdin_to_string(args: &ScanArgs) -> Result<String> {
    use std::io::Read;
    let stdin_cap_bytes = args.limits.to_source_limits().stdin_bytes;
    let mut buf = Vec::with_capacity(8 * 1024);
    std::io::stdin()
        .lock()
        .take(stdin_cap_bytes.saturating_add(1) as u64)
        .read_to_end(&mut buf)
        .context("daemon route: reading stdin")?;
    if buf.len() > stdin_cap_bytes {
        bail!(
            "daemon route: stdin exceeds {stdin_cap_bytes} byte limit. \
             Drop `--daemon` to use the streaming in-process path."
        );
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(unix)]
fn unwrap_scan_results(resp: Response) -> Result<(Vec<RawMatch>, SourceCoverageGaps)> {
    match resp {
        Response::ScanResults {
            matches,
            engine_example_suppressions,
            dogfood_events,
            source_coverage_gaps,
            ..
        } => {
            // Merge daemon-side telemetry into the CLI's process-local
            // counters. The reporter and `dump_dogfood_trace()` both
            // read these, so without the merge the count would stay
            // at 0 (the OnceLock cell here is distinct from the
            // daemon's). Wire v2 is what makes this field non-zero;
            // a v1 daemon returns the serde defaults and the merge
            // is a no-op.
            if engine_example_suppressions > 0 {
                keyhog_scanner::telemetry::add_example_suppressions(
                    engine_example_suppressions as usize,
                );
            }
            if !dogfood_events.is_empty() {
                keyhog_scanner::telemetry::append_events(dogfood_events);
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
        .context("failed to resolve matches; fix rules/detector-classification.toml")?;

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
    let Some(path) = args.path.as_deref().or(args.input.as_deref()) else {
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
             (see docs/keyhogignore-toml.md) or remove the file; refusing to scan \
             with silently ignored suppression rules.",
            toml_path.display()
        ),
    }
}
