use clap::Parser;

#[derive(Parser)]
pub struct CompletionArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Parser)]
pub struct BackendArgs {
    /// Probe the workload size that would route to a different backend.
    /// E.g. `--probe-bytes $((256 * 1024 * 1024))` to confirm GPU is picked
    /// at the 256 MiB threshold.
    #[arg(long)]
    pub probe_bytes: Option<u64>,

    /// Compiled pattern count to use for the routing-simulation matrix.
    /// This is a what-if knob: it does not change the loaded corpus, only
    /// the pattern_count fed to the backend-routing thresholds so you can
    /// probe how a larger/smaller corpus would route. Omit it to use the live
    /// compiled embedded corpus.
    #[arg(long)]
    pub patterns: Option<usize>,

    /// Run the GPU self-tests (MoE compute kernel + vyre literal-set
    /// diagnostic + production AC-kernel dispatch). Prints PASS/FAIL
    /// with adapter info and exits with code 4 on failure so CI can
    /// gate a release on real GPU functionality. No-op on systems
    /// without a non-software adapter.
    #[arg(long)]
    pub self_test: bool,

    /// Emit `backend --self-test` as stable JSON for CI health gates.
    #[arg(long, requires = "self_test")]
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

    /// Asset variant: `cuda` selects the CUDA-accelerated Linux build;
    /// `cpu` selects the portable WGPU+SIMD build. Omit to use the same host
    /// CUDA-toolkit heuristic as the installer.
    #[arg(long)]
    pub variant: Option<String>,

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

    /// Asset variant: `cuda` for the CUDA Linux build; `cpu` for the portable
    /// WGPU+SIMD build. Omit to use the same host CUDA-toolkit heuristic as the
    /// installer.
    #[arg(long)]
    pub variant: Option<String>,

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
