//! The daemon warm-identity digest must not create Rayon's global pool.
//!
//! `rayon::current_num_threads()` reads like an accessor and is a constructor:
//! with no pool yet claimed it CREATES the global registry at Rayon's default
//! width, permanently. `resolved_default_autoroute_config` runs on every daemon
//! client connect that parses a `Hello` (via `warm_identity::client_identity`)
//! purely to compute an identity digest, so calling it there claimed the pool
//! as a side effect of a read.
//!
//! The damage was not to the daemon route, which kept working. It was to the
//! `--daemon=auto` in-process FALLBACK: `ScanOrchestrator::new` could no longer
//! build a KeyHog-owned pool, so a daemon holding a different detector corpus,
//! or one that died mid-scan, turned a scan into exit 2 with ZERO findings
//! immediately after the CLI printed "running in-process scanner". Measured on
//! commit 044cfdc425: corpus drift and mid-scan death both gave rc=2 with no
//! output where `--daemon=off` on the same file gave rc=1 and the credential.
//!
//! That regression is SILENT. Nothing fails to compile, no test goes red, the
//! warm route is unaffected, and the broken path only runs when a daemon is
//! both reachable and unusable. This gate is the thing that goes red instead.
//!
//! Scoped to the function body on purpose: `orchestrator/mod.rs` calls
//! `rayon::current_num_threads()` legitimately elsewhere (recording the worker
//! count in a report, and the test-harness pool policy), so a file-wide check
//! would be a needle wider than its target and would fail on correct code.

use std::fs;
use std::path::PathBuf;

fn repo_src(path: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path),
    )
    .unwrap_or_else(|_| panic!("{path} should be readable"))
}

/// Body of the first `fn <name>` in `src`, brace-matched from its opening `{`.
///
/// Returns `None` when the function is absent, which the caller MUST treat as a
/// failure rather than as "the forbidden call is not there". A rename that
/// silently made this gate pass over nothing is the exact vacuity this file
/// exists to prevent.
fn fn_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let start = src.find(&format!("fn {name}"))?;
    let open = start + src[start..].find('{')?;
    let mut depth = 0usize;
    for (offset, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open..=open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Strip `//` line comments so a needle cannot match the prose that EXPLAINS
/// the forbidden call.
///
/// The first version of this gate asserted over the raw body and failed
/// immediately, because the comment above the fixed line names
/// `rayon::current_num_threads()` in order to say do not call it. That is the
/// same needle-matched-a-non-target family this repository spent a day
/// cataloguing, reproduced inside the guard written to prevent a silent
/// regression. Assert over CODE, not over commentary about the code.
fn code_only(body: &str) -> String {
    body.lines()
        .map(|line| match line.find("//") {
            Some(at) => &line[..at],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn warm_identity_digest_does_not_create_the_rayon_global_pool() {
    let src = repo_src("crates/cli/src/orchestrator/mod.rs");
    let body = fn_body(&src, "resolved_default_autoroute_config").expect(
        "resolved_default_autoroute_config must exist in orchestrator/mod.rs; if it was \
         renamed, retarget this gate rather than deleting it, because the regression it \
         guards is silent",
    );

    let code = code_only(body);
    assert!(
        !code.contains("rayon::current_num_threads"),
        "resolved_default_autoroute_config must not call rayon::current_num_threads(): it \
         CREATES the global pool, and this function runs on every daemon client connect, \
         which makes the --daemon=auto in-process fallback impossible (exit 2 with zero \
         findings after announcing the fallback). Use \
         crate::orchestrator_config::keyhog_worker_threads(), which reports the same width \
         without constructing anything.\nbody was:\n{body}"
    );

    assert!(
        code.contains("keyhog_worker_threads()"),
        "resolved_default_autoroute_config must derive its thread width from \
         keyhog_worker_threads() so the digest is unchanged while the side effect is gone.\
         \nbody was:\n{body}"
    );

    // The helper must remain a non-constructing read of the KeyHog-owned width:
    // an already-configured pool, else the bounded persistent-daemon physical-core
    // width. Reintroducing rayon::current_num_threads() here recreates the pool
    // side effect this gate exists to prevent.
    let runtime = repo_src("crates/cli/src/orchestrator_config/runtime.rs");
    let helper = fn_body(&runtime, "keyhog_worker_threads")
        .expect("keyhog_worker_threads must exist in orchestrator_config/runtime.rs");
    let helper_code = code_only(helper);
    assert!(
        !helper_code.contains("rayon::current_num_threads"),
        "keyhog_worker_threads must not call rayon::current_num_threads(); that recreates \
         the global-pool side effect this gate exists to prevent.\nbody was:\n{helper}"
    );
    assert!(
        helper_code.contains("CONFIGURED_RAYON_THREADS")
            && helper_code.contains("persistent_daemon_worker_width"),
        "keyhog_worker_threads must report an already-configured KeyHog pool, else the \
         bounded persistent-daemon physical-core width.\nbody was:\n{helper}"
    );
}

#[test]
fn an_ineligible_daemon_scan_reports_why_only_when_the_daemon_was_requested() {
    let src = repo_src("crates/cli/src/subcommands/scan.rs");
    let body = fn_body(&src, "announce_in_process_route").expect(
        "announce_in_process_route must exist in subcommands/scan.rs; it is what stops an \
         ineligible scan from silently running in process while a daemon is live",
    );

    // Silent on the default path: `--daemon` defaults to auto and most scans
    // (any directory, any Git or remote source) can never use the warm route,
    // so announcing unconditionally would put a line of noise on nearly every
    // scan. Silent on `--daemon=off` too, which already asked for in-process.
    assert!(
        body.contains("args.daemon.is_none()") && body.contains("DaemonMode::Off"),
        "announce_in_process_route must stay silent when --daemon was not passed and when \
         it was passed as off, so the default scan path gains no new stderr output.\
         \nbody was:\n{body}"
    );

    // stderr only. stdout is the report, and a route diagnostic there would
    // corrupt `--format json` for every consumer.
    assert!(
        body.contains("eprintln!"),
        "the in-process route notice must go to stderr so --format json stdout stays \
         byte-identical.\nbody was:\n{body}"
    );

    // Every ineligibility site must carry its own reason rather than falling
    // back to one generic string, so an operator learns WHICH policy the daemon
    // could not honor.
    assert!(
        src.contains("Forbidden(Option<String>)"),
        "DaemonRoute::Forbidden must carry the reason the daemon could not serve the scan"
    );
}
