//! Logic for the `scan` subcommand.
//!
//! Default: build a [`ScanOrchestrator`] and run the full in-process
//! pipeline. For the simple stdin / single-file case there is also a
//! daemon fast path: when `--daemon` is set (or auto-detected via a
//! live socket), the input goes through the running `keyhog daemon`
//! over a Unix socket and skips the ~3 s `CompiledScanner::compile`
//! cold start. The daemon path is deliberately narrow — directory
//! walks, git-staged scans, archive decoding, baseline filtering,
//! merkle skip cache, and verification all still go through the
//! orchestrator. Anything outside the stdin / single-file shape
//! falls through to in-process and the `--daemon` flag is treated as
//! advisory in those cases.

use crate::args::ScanArgs;
use crate::daemon::client;
use crate::daemon::protocol::{Request, Response};
use crate::daemon::server::default_socket_path;
use crate::orchestrator::ScanOrchestrator;
use anyhow::{bail, Context, Result};
use keyhog_core::{
    dedup_cross_detector, dedup_matches, RawMatch, VerificationResult, VerifiedFinding,
};
use std::path::Path;
use std::process::ExitCode;

const EXIT_CREDENTIALS_FOUND: u8 = 1;

pub async fn run(args: ScanArgs) -> Result<ExitCode> {
    match daemon_route(&args) {
        DaemonRoute::Required => run_via_daemon(&args).await,
        DaemonRoute::Opportunistic => match run_via_daemon(&args).await {
            Ok(exit) => Ok(exit),
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "daemon auto-route unavailable; falling back to in-process scanner"
                );
                let orchestrator = ScanOrchestrator::new(args)?;
                orchestrator.run().await
            }
        },
        DaemonRoute::Forbidden => {
            let orchestrator = ScanOrchestrator::new(args)?;
            orchestrator.run().await
        }
    }
}

enum DaemonRoute {
    Required,
    Opportunistic,
    Forbidden,
}

fn daemon_route(args: &ScanArgs) -> DaemonRoute {
    if args.no_daemon {
        return DaemonRoute::Forbidden;
    }

    // Daemon path doesn't run verification — the daemon process
    // holds a scanner but not the verifier engine. Trying to honour
    // `--verify` over a daemon-only result set would silently drop
    // every API-call-backed live-credential check; the orchestrator
    // is the only honest answer.
    #[cfg(feature = "verify")]
    if args.verify {
        if args.daemon {
            tracing::warn!(
                "--verify forces the in-process path (daemon has no verifier); --daemon ignored"
            );
        }
        return DaemonRoute::Forbidden;
    }
    if args.baseline.is_some() {
        if args.daemon {
            tracing::warn!(
                "--baseline forces the in-process path (daemon has no CLI-side state); --daemon ignored"
            );
        }
        return DaemonRoute::Forbidden;
    }

    let is_eligible_shape = args.stdin || effective_single_file_path(args).is_some();
    if !is_eligible_shape {
        if args.daemon {
            tracing::warn!(
                "--daemon only supports --stdin or a single regular file (no directories, archives, git, http sources); falling back to in-process"
            );
        }
        return DaemonRoute::Forbidden;
    }

    if args.daemon {
        return DaemonRoute::Required;
    }

    if default_socket_path().exists() {
        DaemonRoute::Opportunistic
    } else {
        DaemonRoute::Forbidden
    }
}

fn effective_single_file_path(args: &ScanArgs) -> Option<&Path> {
    let raw = args.path.as_deref().or(args.input.as_deref())?;
    let meta = std::fs::metadata(raw).ok()?;
    if !meta.is_file() {
        return None;
    }
    if raw
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("har"))
        .unwrap_or(false)
    {
        return None;
    }
    Some(raw)
}

async fn run_via_daemon(args: &ScanArgs) -> Result<ExitCode> {
    let socket = default_socket_path();
    let mut conn = client::connect(&socket).await.with_context(|| {
        format!(
            "daemon route: connect to {} (start one with `keyhog daemon start` or pass --no-daemon)",
            socket.display()
        )
    })?;

    let matches = if args.stdin {
        let text = read_stdin_to_string()?;
        let resp = conn
            .round_trip(&Request::ScanText { path: None, text })
            .await?;
        unwrap_scan_results(resp)?
    } else if let Some(path) = effective_single_file_path(args) {
        let working_dir = std::env::current_dir()
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        let resp = conn
            .round_trip(&Request::ScanPath {
                path: path.to_string_lossy().into_owned(),
                working_dir,
            })
            .await?;
        unwrap_scan_results(resp)?
    } else {
        bail!("daemon route invoked without --stdin and without a single-file path");
    };

    let findings = finalize_for_report(matches, args);
    crate::reporting::report_findings(&findings, args)?;

    if findings.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(EXIT_CREDENTIALS_FOUND))
    }
}

fn read_stdin_to_string() -> Result<String> {
    use std::io::Read;
    const STDIN_CAP_BYTES: usize = 10 * 1024 * 1024;
    let mut buf = Vec::with_capacity(8 * 1024);
    std::io::stdin()
        .lock()
        .take(STDIN_CAP_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .context("daemon route: reading stdin")?;
    if buf.len() > STDIN_CAP_BYTES {
        bail!(
            "daemon route: stdin exceeds {STDIN_CAP_BYTES} byte limit. \
             Drop `--daemon` to use the streaming in-process path."
        );
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn unwrap_scan_results(resp: Response) -> Result<Vec<RawMatch>> {
    match resp {
        Response::ScanResults {
            matches,
            engine_example_suppressions,
            dogfood_events,
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
            Ok(matches)
        }
        Response::Error { message } => bail!("daemon: {message}"),
        other => bail!("daemon route: expected ScanResults, got {other:?}"),
    }
}

fn finalize_for_report(matches: Vec<RawMatch>, args: &ScanArgs) -> Vec<VerifiedFinding> {
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

    // Mirror the in-process orchestrator's behaviour: when this filter
    // drops a credential, bump the example-suppression telemetry so the
    // reporter's empty-findings summary distinguishes "no matches at
    // all" from "matched and suppressed as a known test fixture". The
    // daemon process runs its own scanner (with its own telemetry
    // counters that this CLI can't see), so the CLI must record the
    // suppression itself based on what came back over the wire.
    let mut matches: Vec<RawMatch> = matches
        .into_iter()
        .filter(|m| {
            if fixtures.suppresses(&m.credential) {
                keyhog_scanner::telemetry::record_example_suppression(
                    m.detector_id.as_ref(),
                    m.location.file_path.as_deref(),
                    &m.credential,
                    "test_fixture_suppression",
                );
                return false;
            }
            true
        })
        .collect();
    matches.sort_by_key(|m| std::cmp::Reverse(m.severity));

    let scope = args.dedup.to_core();
    let deduped = dedup_matches(matches, &scope);
    let deduped = dedup_cross_detector(deduped);

    deduped
        .into_iter()
        .map(|m| VerifiedFinding {
            detector_id: m.detector_id,
            detector_name: m.detector_name,
            service: m.service,
            severity: m.severity,
            credential_redacted: if args.show_secrets {
                m.credential.to_string().into()
            } else {
                keyhog_core::redact(&m.credential)
            },
            credential_hash: m.credential_hash,
            location: m.primary_location,
            verification: VerificationResult::Skipped,
            metadata: std::collections::HashMap::new(),
            additional_locations: m.additional_locations,
            confidence: m.confidence,
        })
        .collect()
}
