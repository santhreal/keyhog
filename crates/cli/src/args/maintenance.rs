use clap::Parser;

#[derive(Parser)]
pub struct CompletionArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Parser)]
// `--json` renders either the self-test report or the autoroute-cache inspection,
// so it requires one of them; the two modes are mutually exclusive.
#[command(group(clap::ArgGroup::new("json_target").args(["self_test", "autoroute"])))]
pub struct BackendArgs {
    /// Probe the workload size in the diagnostic hardware heuristic matrix.
    /// This does not predict `scan --backend auto`, which uses persisted
    /// fastest-correct calibration evidence.
    #[arg(long)]
    pub probe_bytes: Option<u64>,

    /// Inspect the persisted autoroute calibration cache: which resolved scan
    /// configs and workload buckets have a fastest-correct backend decision,
    /// the cold-aware one-shot and warm-daemon routes, confidence basis, and
    /// whether the cache is stale for this build. Read-only; pairs with
    /// `--json`. Use this to diagnose a
    /// fail-closed "no decision for workload bucket ..." scan error.
    #[arg(long)]
    pub autoroute: bool,

    /// Compiled pattern count to use for the routing-simulation matrix.
    /// This is a what-if knob: it does not change the loaded corpus, only
    /// the pattern_count fed to the backend-routing thresholds so you can
    /// probe how a larger/smaller corpus would route. Omit it to use the live
    /// compiled embedded corpus.
    #[arg(long)]
    pub patterns: Option<usize>,

    /// Run the GPU self-tests (MoE compute kernel + VYRE direct-match
    /// diagnostic + production region-presence dispatch). Prints PASS/FAIL
    /// with adapter info and exits with code 4 on failure so CI can
    /// gate a release on real GPU functionality. Reports SKIP and exits zero
    /// without a non-software adapter unless --require-gpu is set.
    #[arg(long)]
    pub self_test: bool,

    /// Emit `backend --self-test` or `backend --autoroute` as stable JSON for
    /// CI health gates / scripted inspection.
    #[arg(long, requires = "json_target")]
    pub json: bool,

    /// Disable GPU probing for backend inspection/self-test.
    #[arg(long, conflicts_with = "require_gpu")]
    pub no_gpu: bool,

    /// Fail closed when backend self-test cannot use a real GPU.
    #[arg(long, conflicts_with = "no_gpu")]
    pub require_gpu: bool,
}

/// Arguments for `keyhog doctor`. The health check is fully automatic; no
/// flags are needed today. The struct exists so the command can grow options
/// (e.g. `--json`) without a breaking signature change.
#[derive(Parser)]
pub struct DoctorArgs {}

/// Arguments for `keyhog update` (self-update from GitHub releases).
#[derive(Parser)]
pub struct UpdateArgs {
    /// Only check whether a newer release is available; do not install.
    /// Exits 10 when an update is available, 0 when already current.
    #[arg(long)]
    pub check: bool,

    /// Install a specific release tag instead of the latest (e.g. `v0.5.34`).
    /// Use this to pin a version or downgrade.
    #[arg(long)]
    pub version: Option<String>,

    /// Hidden test seam for offline update lifecycle tests. Production users
    /// should resolve releases from the canonical GitHub API.
    #[arg(long, hide = true, value_name = "URL")]
    pub release_api_base: Option<String>,
}

/// Arguments for `keyhog repair` (reinstall a known-good binary from releases).
#[derive(Parser)]
pub struct RepairArgs {
    /// Reinstall even if the scan-engine self-test currently passes.
    #[arg(long)]
    pub force: bool,

    /// Reinstall a specific release tag instead of the latest (e.g. `v0.5.34`).
    /// Use this to pin a version or downgrade.
    #[arg(long)]
    pub version: Option<String>,

    /// Hidden test seam for offline repair lifecycle tests. Production users
    /// should resolve releases from the canonical GitHub API.
    #[arg(long, hide = true, value_name = "URL")]
    pub release_api_base: Option<String>,
}

/// Arguments for `keyhog uninstall`.
#[derive(Parser)]
pub struct UninstallArgs {
    /// Actually remove the binary. Without this, uninstall is a safe dry run
    /// that only reports what would be removed.
    #[arg(long)]
    pub yes: bool,
}
