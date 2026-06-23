//! Lane-10 (dogfood/robustness) regression pins for the Law-10 silent-fallback
//! gaps closed in the watch / scan-system recall paths.
//!
//! Law 10: a code path that, when its mechanism is unavailable, quietly does
//! something else (skips work, drops bytes) WITHOUT surfacing it loudly is a
//! recall bug. `tracing::warn!` then `continue`/`skip` is SILENT (invisible
//! without RUST_LOG). These pins go red if the loud `eprintln!` surfacing is
//! removed or the silent `tracing::warn!` skip is reintroduced.
//!
//! The behavioral cases (inotify queue overflow; a `--no-default-features`
//! build with the `git` feature off) cannot be reliably forced from a default
//! release build, so these assert the surfacing at the source the operator
//! sees — the strongest available regression pin for those code paths.

use std::path::Path;

fn src(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

#[test]
fn watch_watcher_error_is_surfaced_loudly_not_traced() {
    let s = src("src/subcommands/watch.rs");
    // The watcher-error arm: an inotify queue overflow / dropped event is a
    // recall loss (a save the watcher never reported = a file never re-scanned).
    // It must reach the operator on stderr, not vanish into tracing.
    let arm = s
        .split("Err(e) => {")
        .nth(1)
        .expect("watch.rs must have an Err(e) arm in the event loop");
    // Grab just the watcher-error arm body (up to the next `};`).
    let arm = arm.split("};").next().unwrap_or(arm);
    assert!(
        arm.contains("eprintln!"),
        "a filesystem watcher error must be surfaced LOUDLY on stderr (eprintln!), \
         not swallowed by tracing — dropped events are unscanned files (Law 10)"
    );
    assert!(
        arm.contains("DROPPED") || arm.contains("NOT") || arm.contains("not re-scanned"),
        "the watcher-error message must name the recall loss (dropped/unscanned events)"
    );
    assert!(
        !arm.contains("tracing::warn!"),
        "the watcher-error arm must NOT use a silent tracing::warn! (Law 10)"
    );
}

#[test]
fn scan_system_git_feature_off_is_surfaced_loudly_and_counted() {
    let s = src("src/subcommands/scan_system.rs");
    // The `#[cfg(not(feature = "git"))]` arm of scan_git_history: a build
    // without the git feature CANNOT scan a discovered repo's history. The
    // banner announces "git history: yes" and "discovered N git repo(s)", so a
    // silent skip makes a partial audit look complete.
    let arm = s
        .split(r#"#[cfg(not(feature = "git"))]"#)
        .nth(1)
        .expect("scan_system.rs must have a not(git) cfg arm");
    assert!(
        arm.contains("eprintln!"),
        "the git-feature-off path must surface the unscanned history LOUDLY on \
         stderr, not via a silent tracing::warn! (Law 10)"
    );
    assert!(
        arm.contains("record_skipped_chunk"),
        "the git-feature-off path must COUNT the unscanned history as a skipped \
         chunk so the final summary's 'did NOT cover everything' warning fires"
    );
    assert!(
        !arm.contains("tracing::warn!"),
        "the git-feature-off path must NOT silently tracing::warn! and skip (Law 10)"
    );
}

#[test]
fn scan_system_summary_warns_when_chunks_were_skipped() {
    // The summary path must loudly warn when ANY chunk was skipped, so a partial
    // audit is never reported as a clean/complete one.
    let s = src("src/subcommands/scan_system.rs");
    assert!(
        s.contains("skipped_chunks() > 0"),
        "scan-system must branch on a non-zero skipped-chunk count in its summary"
    );
    assert!(
        s.contains("did") && s.contains("NOT cover everything"),
        "the skipped-chunk summary must state the audit did NOT cover everything"
    );
}

#[test]
fn verify_low_confidence_skips_are_surfaced_loudly() {
    let s = src("src/orchestrator/postprocess.rs");
    let block = s
        .split("skipping low-confidence findings from verification")
        .nth(1)
        .expect("verify path must classify low-confidence verification skips");
    let block = block
        .split("let verify = &self.effective_config.verify")
        .next()
        .unwrap_or(block);
    assert!(
        block.contains("eprintln!"),
        "`--verify` low-confidence skips must reach stderr, not only tracing"
    );
    assert!(
        block.contains("--verify skipped")
            && block.contains("verifier confidence floor")
            && block.contains("verification=skipped"),
        "the stderr warning must name the requested verify mode, the threshold \
         reason, and the machine-visible result"
    );
}

#[test]
fn daemon_accept_loop_does_not_silently_break_on_error() {
    let s = src("src/daemon/server.rs");
    // The accept-loop Err arm must surface loudly and classify transient vs
    // fatal, never the old silent `tracing::error!(...) ; break`.
    assert!(
        s.contains("is_transient_accept_error"),
        "the accept loop must classify transient vs fatal accept errors"
    );
    assert!(
        s.contains("eprintln!") && s.contains("accept"),
        "an accept() failure must be surfaced LOUDLY on stderr (Law 10), not only \
         via a silent tracing::error!"
    );
    // The fatal arm must trigger shutdown so the daemon doesn't become a deaf
    // zombie that `daemon status` still reports as healthy.
    assert!(
        s.contains("notify_waiters") && s.contains("shutting down"),
        "a fatal accept error must trigger graceful shutdown, not leave a deaf \
         daemon alive reporting 'ready'"
    );
}
