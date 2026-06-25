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

#[test]
fn numeric_threading_knobs_are_explicit_config() {
    let core_lib = repo_src("crates/core/src/lib.rs");
    assert!(
        !PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("crates/core/src/env_config.rs")
            .exists()
            && !core_lib.contains("env_config"),
        "numeric env knob helpers must not exist in production; use explicit TOML/CLI config"
    );

    let fused = repo_src("crates/cli/src/orchestrator/dispatch/fused.rs");
    let scan_args = repo_src("crates/cli/src/args/scan.rs");
    // The TOML merge for these knobs lives in the `config/scan.rs` section
    // submodule; the top-level `config.rs` is a delegating façade after the
    // per-section split.
    let config = repo_src("crates/cli/src/config/scan.rs");
    let orchestrator_config = repo_src("crates/cli/src/orchestrator_config.rs");
    let effective = repo_src("crates/cli/src/orchestrator_config/effective.rs");
    assert!(
        !fused.contains("KEYHOG_FUSED_BATCH")
            && !fused.contains("KEYHOG_FUSED_DEPTH")
            && fused.contains("self.effective_config.fused_batch")
            && fused.contains("self.effective_config")
            && fused.contains("fused_depth_default(rayon::current_num_threads())")
            && scan_args.contains("reader_threads")
            && scan_args.contains("fused_batch")
            && scan_args.contains("fused_depth")
            && config.contains("reader_threads")
            && config.contains("fused_batch")
            && config.contains("fused_depth")
            && orchestrator_config.contains("reader_threads: Option<usize>")
            && orchestrator_config.contains("fused_batch: usize")
            && orchestrator_config.contains("fused_depth: Option<usize>")
            && effective.contains("\"reader_threads\", resolved.reader_threads)")
            && effective.contains("\"fused_batch\", resolved.fused_batch)")
            && effective.contains("\"fused_depth\", resolved.fused_depth)"),
        "fused filesystem throughput knobs must be explicit CLI/TOML config and part of autoroute identity"
    );

    let daemon = repo_src("crates/cli/src/daemon/server.rs");
    // The daemon request-timeout CLI arg and its value parser reference live in
    // the `args/daemon.rs` subcommand submodule; the top-level `args.rs` only
    // re-exports the `DaemonArgs` type.
    let daemon_args = repo_src("crates/cli/src/args/daemon.rs");
    assert!(
        !daemon.contains("KEYHOG_DAEMON_REQUEST_TIMEOUT_SECS")
            && daemon.contains("request_read_timeout")
            && daemon_args.contains("request_timeout_secs")
            && daemon_args.contains("parse_daemon_request_timeout_secs"),
        "daemon request timeout must be explicit CLI configuration, not an env parser"
    );

    let reader = repo_src("crates/sources/src/filesystem/reader.rs");
    assert!(
        !reader.contains("KEYHOG_READER_THREADS")
            && !reader.contains("keyhog_core::env_config")
            && reader.contains("configured: Option<NonZeroUsize>")
            && reader.contains("reader_thread_count(rayon::current_num_threads(), reader_threads)"),
        "filesystem reader threads must be explicit source configuration, not ambient env"
    );
}
