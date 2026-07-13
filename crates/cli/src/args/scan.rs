//! `keyhog scan` CLI arguments.
//!
//! Split out of `args.rs` because the scan subcommand has the largest flag
//! surface and needs its own validation boundary.

use clap::{parser::ValueSource, Parser, ValueEnum};
use keyhog_core::DedupScope;
use std::path::PathBuf;

use super::SourceLimitArgs;

#[derive(Clone, Debug, ValueEnum)]
pub enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    pub fn to_severity(&self) -> keyhog_core::Severity {
        match self {
            Self::Info => keyhog_core::Severity::Info,
            Self::Low => keyhog_core::Severity::Low,
            Self::Medium => keyhog_core::Severity::Medium,
            Self::High => keyhog_core::Severity::High,
            Self::Critical => keyhog_core::Severity::Critical,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
    Csv,
    GithubAnnotations,
    GitlabSast,
    Html,
    Junit,
}

#[derive(Clone, Debug, ValueEnum, PartialEq)]
pub enum CliDedupScope {
    Credential,
    File,
    None,
}

impl std::fmt::Display for CliDedupScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render the exact CLI spelling from the ONE owner — the `ValueEnum`
        // derive — so the `--dedup` default (`default_value_t`) can never drift
        // from the accepted `--dedup` values. Every variant is non-skipped, so
        // `to_possible_value` is always `Some`.
        f.write_str(
            clap::ValueEnum::to_possible_value(self)
                .expect("CliDedupScope variants are never skipped")
                .get_name(),
        )
    }
}

impl CliDedupScope {
    pub fn to_core(&self) -> DedupScope {
        match self {
            Self::Credential => DedupScope::Credential,
            Self::File => DedupScope::File,
            Self::None => DedupScope::None,
        }
    }
}

/// Tri-state daemon routing policy for `scan --daemon[=auto|on|off]` (CLI-02).
///
/// One flag owns the complete daemon policy:
///   * `--daemon` (bare)  → [`Self::On`]   (force the daemon route)
///   * `--daemon=auto`    → [`Self::Auto`] (the default when the flag is absent)
///   * `--daemon=off`     → [`Self::Off`]  (force in-process execution)
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
pub enum DaemonMode {
    /// Use a compatible daemon when its socket is reachable; otherwise scan in
    /// process. A failure after selecting the daemon is reported before the
    /// in-process retry. This is the behavior when the flag is absent. The
    /// explicit `--daemon=auto` spelling requires Unix; an absent flag remains
    /// portable and runs in process where no daemon transport ships.
    Auto,
    /// Force the scan through a running `keyhog daemon`; fail if none is up.
    On,
    /// Force in-process scanning even when a daemon is running.
    Off,
}

impl DaemonMode {
    /// Whether this policy may open the Unix daemon transport. An explicit
    /// `Auto` or `On` therefore requires Unix; `Off` is portable.
    pub const fn may_use_daemon_transport(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[derive(Parser, Clone)]
pub struct ScanArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    #[arg(skip)]
    pub(crate) detectors_cli_explicit: bool,

    /// Path(s) to scan. Pass several to scan multiple roots in one run
    /// (`keyhog scan a/ b/ c/`); nested or duplicate roots fold into their
    /// covering parent. Positional shorthand for `--path` (single root only).
    #[arg(value_name = "PATH", conflicts_with = "path")]
    pub input: Vec<PathBuf>,

    /// Scan a directory or file
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Scan binary files for hardcoded strings
    #[cfg(feature = "binary")]
    #[arg(long)]
    pub binary: bool,

    /// Scan stdin
    #[arg(long)]
    pub stdin: bool,

    /// Scan reachable git blobs from repository history (deduplicated by blob ID)
    #[cfg(feature = "git")]
    #[arg(long)]
    pub git_blobs: Option<PathBuf>,

    /// Scan only changed lines between two git refs (e.g., --git-diff main)
    #[cfg(feature = "git")]
    #[arg(long, value_name = "BASE_REF")]
    pub git_diff: Option<String>,

    /// Scan full git history commit-by-commit using added lines from patches
    #[cfg(feature = "git")]
    #[arg(long, value_name = "PATH")]
    pub git_history: Option<PathBuf>,

    /// Scan only staged files in the current git repository
    #[cfg(feature = "git")]
    #[arg(long)]
    pub git_staged: bool,

    /// Path to git repository for --git-diff (defaults to current directory)
    #[cfg(feature = "git")]
    #[arg(long, requires = "git_diff")]
    pub git_diff_path: Option<PathBuf>,

    /// Scan all repositories in a GitHub organization
    #[cfg(feature = "github")]
    #[arg(long, requires = "github_token", value_name = "ORG")]
    pub github_org: Option<String>,

    /// GitHub personal access token for --github-org
    #[cfg(feature = "github")]
    #[arg(long, requires = "github_org", value_name = "PAT")]
    pub github_token: Option<String>,

    /// Scan all projects in a GitLab group, including subgroups
    #[cfg(feature = "gitlab")]
    #[arg(long, requires = "gitlab_token", value_name = "GROUP")]
    pub gitlab_group: Option<String>,

    /// GitLab personal access token for --gitlab-group
    #[cfg(feature = "gitlab")]
    #[arg(long, requires = "gitlab_group", value_name = "PAT")]
    pub gitlab_token: Option<String>,

    /// GitLab API endpoint root, for example https://gitlab.example.com
    #[cfg(feature = "gitlab")]
    #[arg(long, requires = "gitlab_group", default_value = "https://gitlab.com")]
    pub gitlab_endpoint: String,

    /// Scan all repositories in a Bitbucket Cloud workspace
    #[cfg(feature = "bitbucket")]
    #[arg(
        long,
        requires_all = ["bitbucket_username", "bitbucket_token"],
        value_name = "WORKSPACE"
    )]
    pub bitbucket_workspace: Option<String>,

    /// Bitbucket username for --bitbucket-workspace
    #[cfg(feature = "bitbucket")]
    #[arg(long, requires = "bitbucket_workspace", value_name = "USERNAME")]
    pub bitbucket_username: Option<String>,

    /// Bitbucket app password for --bitbucket-workspace
    #[cfg(feature = "bitbucket")]
    #[arg(long, requires = "bitbucket_workspace", value_name = "APP_PASSWORD")]
    pub bitbucket_token: Option<String>,

    /// Bitbucket Cloud API endpoint root
    #[cfg(feature = "bitbucket")]
    #[arg(
        long,
        requires = "bitbucket_workspace",
        default_value = "https://api.bitbucket.org/2.0"
    )]
    pub bitbucket_endpoint: String,

    /// Scan a public or path-style S3 bucket via ListObjectsV2
    #[cfg(feature = "s3")]
    #[arg(long, value_name = "BUCKET")]
    pub s3_bucket: Option<String>,

    /// Optional S3 object prefix to limit the scan
    #[cfg(feature = "s3")]
    #[arg(long, requires = "s3_bucket", value_name = "PREFIX")]
    pub s3_prefix: Option<String>,

    /// Optional S3 endpoint for S3-compatible APIs
    #[cfg(feature = "s3")]
    #[arg(long, requires = "s3_bucket", value_name = "URL")]
    pub s3_endpoint: Option<String>,

    /// Forward ambient AWS credentials to a custom S3 endpoint you trust.
    /// Off by default; AWS-owned endpoints do not need this. This flag is
    /// intentionally explicit because it can send AWS identity material to a
    /// third-party host.
    #[cfg(feature = "s3")]
    #[arg(long, requires = "s3_endpoint")]
    pub allow_s3_credential_forward: bool,

    /// Scan a Google Cloud Storage bucket via the JSON API
    #[cfg(feature = "gcs")]
    #[arg(long, value_name = "BUCKET")]
    pub gcs_bucket: Option<String>,

    /// Optional GCS object prefix to limit the scan
    #[cfg(feature = "gcs")]
    #[arg(long, requires = "gcs_bucket", value_name = "PREFIX")]
    pub gcs_prefix: Option<String>,

    /// Optional GCS endpoint override for compatible APIs or tests
    #[cfg(feature = "gcs")]
    #[arg(long, requires = "gcs_bucket", value_name = "URL")]
    pub gcs_endpoint: Option<String>,

    /// Forward the ambient GCS bearer token to a custom GCS endpoint you trust.
    /// Off by default; googleapis.com endpoints do not need this. This flag is
    /// intentionally explicit because it can send a bearer token to a
    /// third-party host.
    #[cfg(feature = "gcs")]
    #[arg(long, requires = "gcs_endpoint")]
    pub allow_gcs_token_forward: bool,

    /// Scan an Azure Blob Storage container URL. Include a SAS query string for private containers.
    #[cfg(feature = "azure")]
    #[arg(long, value_name = "URL")]
    pub azure_container_url: Option<String>,

    /// Optional Azure Blob prefix to limit the scan
    #[cfg(feature = "azure")]
    #[arg(long, requires = "azure_container_url", value_name = "PREFIX")]
    pub azure_prefix: Option<String>,

    /// Scan a Docker image by unpacking `docker image save`
    #[cfg(feature = "docker")]
    #[arg(long, value_name = "IMAGE")]
    pub docker_image: Option<String>,

    /// Scan JavaScript, source maps, or WASM binaries at URLs for secrets
    #[cfg(feature = "web")]
    #[arg(long, value_name = "URL", num_args = 1..)]
    pub url: Option<Vec<String>>,

    /// Route outbound HTTP through a proxy (`http://burp:8080`,
    /// `socks5://127.0.0.1:9050`, etc.). This flag (or its TOML
    /// equivalent) is the ONLY way to set a proxy: no environment
    /// variable is consulted, and ambient `HTTPS_PROXY` / `HTTP_PROXY`
    /// / `ALL_PROXY` is ignored, so a stray env proxy can never silently
    /// reroute secret-bearing traffic. When unset, no proxy is used.
    /// Pass `off` to make that explicit for air-gapped scans.
    #[cfg(any(
        feature = "web",
        feature = "github",
        feature = "gitlab",
        feature = "bitbucket",
        feature = "s3",
        feature = "gcs",
        feature = "azure",
        feature = "verify"
    ))]
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Skip TLS certificate verification for every outbound HTTP
    /// request. Needed when scanning through Burp / mitmproxy /
    /// corporate-MITM CAs that present self-signed certificates.
    /// Off by default. This flag (or its TOML equivalent) is the ONLY
    /// way to disable verification: no environment variable can turn it
    /// off, so an ambient toggle can't silently expose secrets to a MITM.
    #[cfg(any(
        feature = "web",
        feature = "github",
        feature = "gitlab",
        feature = "bitbucket",
        feature = "s3",
        feature = "gcs",
        feature = "azure",
        feature = "verify"
    ))]
    #[arg(long)]
    pub insecure: bool,

    /// Allow cloud sources (`--s3-endpoint`, GCS / Azure container URLs) to reach
    /// an endpoint whose host — literal or DNS-resolved — is private, loopback,
    /// link-local, or cloud-metadata. OFF by default: the cloud SSRF screen
    /// refuses every such endpoint. Enable ONLY for a trusted private-network
    /// deployment (self-hosted MinIO / Ceph on an internal gateway). This flag
    /// (or its `[http].allow_private_endpoint` TOML equivalent) is the ONLY way
    /// to relax the screen — no environment variable can, so an ambient toggle
    /// can never silently turn keyhog into an SSRF proxy for internal services.
    #[cfg(any(
        feature = "web",
        feature = "github",
        feature = "gitlab",
        feature = "bitbucket",
        feature = "s3",
        feature = "gcs",
        feature = "azure",
        feature = "verify"
    ))]
    #[arg(long)]
    pub allow_private_cloud_endpoint: bool,

    /// Max git commits to traverse
    #[cfg(feature = "git")]
    #[arg(long)]
    pub max_commits: Option<usize>,

    /// Verify discovered credentials via API calls
    #[cfg(feature = "verify")]
    #[arg(long)]
    pub verify: bool,

    /// Enable out-of-band callback verification via an embedded interactsh
    /// client. For webhook- and callback-shaped credentials, OOB verification
    /// proves the credential is exfil-capable: we mint a per-finding
    /// subdomain on the configured collector, embed it in the verification
    /// probe, and confirm the service actually called back. Off by default.
    /// See docs/src/reference/oob-verification.md for the threat model and
    /// self-hosting guidance.
    #[cfg(feature = "verify")]
    #[arg(long, requires = "verify")]
    pub verify_oob: bool,

    /// Interactsh server for OOB verification. Defaults to projectdiscovery's
    /// public collector at `oast.fun`. Use a self-hosted server for sensitive
    /// scans; the collector sees correlation IDs and the IPs of services
    /// that call back, never the credential itself. Only meaningful with
    /// `--verify-oob`; clap rejects the flag without it instead of silently
    /// ignoring it (the prior behavior gave false confidence that an
    /// override had been applied).
    #[cfg(feature = "verify")]
    #[arg(
        long,
        default_value = "oast.fun",
        value_name = "HOST",
        requires = "verify_oob"
    )]
    pub oob_server: String,

    /// Per-finding OOB wait timeout in seconds. Detector specs may set their
    /// own `timeout_secs`; this value is the global default and the upper
    /// bound. Lower = faster scans, higher = catches services with delayed
    /// webhooks (e.g., queued mail delivery). Requires `--verify-oob`.
    #[cfg(feature = "verify")]
    #[arg(
        long,
        default_value = "30",
        value_name = "SECS",
        requires = "verify_oob"
    )]
    pub oob_timeout: u64,

    /// Show full credentials (default: redacted)
    #[arg(long)]
    pub show_secrets: bool,

    /// Incremental scan: skip files whose content hash matches the cached
    /// `~/.cache/keyhog/merkle.idx`. After the scan completes, the index is
    /// updated with the current file contents. On CI re-runs against a
    /// monorepo where 99% of files are unchanged, this gives 10-100x
    /// speedup. Pass `--incremental-cache <path>` to override the location.
    #[arg(long)]
    pub incremental: bool,

    /// Override the merkle-index cache file location.
    #[arg(long, value_name = "PATH", requires = "incremental")]
    pub incremental_cache: Option<PathBuf>,

    /// Override the Hyperscan compiled-database cache directory.
    ///
    /// This is explicit CLI/TOML configuration, not an environment variable:
    /// pass an absolute path under your home directory or the per-user keyhog
    /// temp cache root. Config: `[system].cache_dir` in `.keyhog.toml`; this
    /// flag overrides it.
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Override the persistent autoroute calibration cache file.
    ///
    /// Use an absolute path, or `off` to disable persistence. Config:
    /// `[system].autoroute_cache` in `.keyhog.toml`; this flag overrides it.
    #[arg(long, value_name = "PATH|off")]
    pub autoroute_cache: Option<String>,

    /// Explicit per-detector Bayesian calibration cache for confidence scoring.
    ///
    /// Normal scans are hermetic and ignore any default `keyhog calibrate`
    /// cache unless this flag or `[system].calibration_cache` supplies a path.
    /// The file must already exist and parse cleanly; damaged or missing
    /// explicit caches fail before scanning so score changes are reproducible.
    #[arg(long, value_name = "PATH")]
    pub calibration_cache: Option<PathBuf>,

    /// Run this scan as an explicit autoroute calibration probe: benchmark
    /// parity-checked backend candidates and persist the fastest-correct
    /// decision for each workload bucket. Normal scans never benchmark on cache
    /// miss; they require persisted installer calibration or an explicit
    /// `--backend`.
    #[arg(long)]
    pub autoroute_calibrate: bool,

    /// Output format
    #[arg(long, default_value = "text", value_enum)]
    pub format: OutputFormat,
    #[arg(skip)]
    pub(crate) format_cli_explicit: bool,

    /// Show progress bar
    #[arg(long)]
    pub progress: bool,

    /// Suppress the interactive stderr chrome (banner, live progress ticker,
    /// and the "Scan complete" summary). Coverage FAIL/WARN lines and fatal
    /// errors are still printed so a quiet scan can never read as clean when it
    /// was not. Findings still go to stdout / `--output`. Mutually exclusive
    /// with `--progress`.
    #[arg(long, conflicts_with = "progress")]
    pub quiet: bool,

    /// Disable ANSI color in the report and the stderr summary, regardless of
    /// whether the output is a TTY (the `NO_COLOR` convention is also honored).
    #[arg(long)]
    pub no_color: bool,

    /// Emit a redacted `[stream]` preview line on stderr for every REPORTED
    /// finding (`SEVERITY  SERVICE/DETECTOR  PATH:LINE  redacted`), so a quick
    /// human- or CI-scrapeable summary lands on stderr while the full formatted
    /// report (text/json/sarif/jsonl) goes to stdout or `--output`. The preview
    /// stream is consistent with that report and the exit code: every streamed
    /// line corresponds to a finding that survived suppression, the confidence
    /// floor / `--min-confidence`, and baseline filtering — it never previews a
    /// match the report drops.
    #[arg(long)]
    pub stream: bool,

    /// Emit the scanner-owned hierarchical profile report to stderr at scan end.
    #[arg(long)]
    pub profile: bool,

    /// Emit low-level scan/GPU phase timing traces to stderr.
    #[arg(long)]
    pub perf_trace: bool,

    /// Select persisted autoroute (`auto`) or explicitly force one diagnostic
    /// backend. Values: `auto`, `gpu`, `simd`, or `cpu`.
    #[arg(
        long,
        value_name = "BACKEND",
        value_parser = clap::builder::PossibleValuesParser::new(
            keyhog_scanner::hw_probe::BACKEND_OVERRIDE_VALUES
        )
    )]
    pub backend: Option<String>,

    /// Disable GPU probing and GPU backend acquisition for this scan.
    #[arg(long, conflicts_with = "require_gpu")]
    pub no_gpu: bool,

    /// Require a usable GPU stack before scanning; fail closed if GPU init or
    /// self-test is unavailable.
    #[arg(long, conflicts_with = "no_gpu")]
    pub require_gpu: bool,

    /// Allow autoroute calibration to include GPU candidates for eligible
    /// workload buckets. Normal scans still use persisted calibration only.
    #[arg(long, conflicts_with = "no_autoroute_gpu")]
    pub autoroute_gpu: bool,

    /// Keep GPU candidates out of autoroute calibration even when TOML enables
    /// them.
    #[arg(long, conflicts_with = "autoroute_gpu")]
    pub no_autoroute_gpu: bool,

    /// Force the coalesced batch scan pipeline instead of the fused filesystem
    /// pipeline. This is an explicit calibration/diagnostic control, not an
    /// ambient environment switch. Config: `[system].batch_pipeline`; this flag
    /// overrides it.
    #[arg(long, conflicts_with = "no_batch_pipeline")]
    pub batch_pipeline: bool,

    /// Keep the fused filesystem pipeline even when `[system].batch_pipeline`
    /// is true.
    #[arg(long, conflicts_with = "batch_pipeline")]
    pub no_batch_pipeline: bool,

    /// Daemon routing: `auto` (default — use a live daemon if one is up, else
    /// scan in-process), `on` (force the daemon route; fail if none is up), or
    /// `off` (force in-process). Bare `--daemon` means `on`. Use `on` in
    /// pre-commit hooks / IDE save handlers where the ~3 s in-process cold-start
    /// dominates the actual scan; the daemon holds a compiled scanner so each
    /// invocation is sub-ms IPC + scan. See `keyhog daemon start --help`.
    ///
    /// Socket: the daemon route connects to the default socket
    /// ($XDG_RUNTIME_DIR/keyhog.sock) unless `--daemon-socket <path>` points it
    /// at a daemon bound elsewhere (`daemon start --socket <path>`).
    /// Unix only: Windows rejects explicit `auto` and `on`; explicit `off` is
    /// accepted as a portable declaration of in-process execution.
    ///
    #[arg(
        long,
        value_enum,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "on",
        value_name = "auto|on|off"
    )]
    pub daemon: Option<DaemonMode>,

    /// Connect the daemon route to a daemon bound on a non-default socket.
    ///
    /// By default `scan --daemon` connects to `$XDG_RUNTIME_DIR/keyhog.sock`.
    /// Pass the same path a daemon was started on
    /// (`keyhog daemon start --socket <path>`) to reach a fixed-location daemon
    /// (e.g. a shared/system or systemd-managed instance). Combining it with
    /// `--daemon=off` is rejected as contradictory.
    #[arg(long, value_name = "PATH")]
    pub daemon_socket: Option<PathBuf>,

    /// Write findings to file
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Per-request HTTP verification timeout in seconds (default: 5). This does
    /// not impose a deadline on scanning; use `--per-chunk-timeout-ms` for the
    /// scanner's optional chunk deadline.
    #[cfg(feature = "verify")]
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Maximum in-flight verification requests per service (default: 5).
    #[cfg(feature = "verify")]
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_positive_usize)]
    pub verify_concurrency: Option<usize>,

    /// Steady-state cap for verification calls *per service*, in
    /// requests-per-second. Default 5.0. Drop this to be polite to
    /// upstream APIs when scanning a tree with hundreds of legitimate
    /// findings (test fixtures, examples); every finding produces a
    /// live verify call and most public APIs throttle aggressively.
    /// The limiter applies even with `--verify-batch` (which adds
    /// per-service serialisation on top).
    #[cfg(feature = "verify")]
    #[arg(
        long,
        value_name = "RPS",
        default_value = "5.0",
        value_parser = crate::value_parsers::parse_verify_rate
    )]
    pub verify_rate: f64,

    /// Conservative verify mode: serialises live verifications per
    /// service (max-concurrent-per-service = 1) on top of the
    /// `--verify-rate` cap. Use for repos with lots of legitimate
    /// findings (test fixtures, vendored examples) where bursting a
    /// provider's auth endpoint would get the scan IP rate-limited
    /// or blocked. Implies `--verify`.
    #[cfg(feature = "verify")]
    #[arg(long, requires = "verify")]
    pub verify_batch: bool,

    /// Permit detector `script:` verification for trusted detector corpora.
    /// Off by default because scripts execute verifier-supplied code with
    /// credential-adjacent context. Prints an explicit warning when active.
    #[cfg(feature = "verify")]
    #[arg(long, requires = "verify")]
    pub allow_script_verify: bool,

    /// Min severity to report: info, low, medium, high, critical
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Maximum file size to scan. Files larger than this are listed in
    /// the end-of-scan "files skipped: exceeded --max-file-size"
    /// summary. Default is 100 MiB, the `FilesystemSource` ceiling. Files
    /// above the 1 MiB window size are read in overlapping ~1 MiB windows
    /// (so memory stays bounded regardless of file size), up to this cap.
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub max_file_size: Option<usize>,

    /// Per-regex lazy-DFA cache CEILING, e.g. "256KB" or "1MB" (default 1 MiB).
    /// Bounds the worst-case per-thread DFA cache for pathological/state-heavy
    /// patterns; typical detectors stay well under it, so lowering this does
    /// NOT meaningfully cut peak memory (it's a safety ceiling, not a general
    /// memory lever). Lowering can force complex regexes to slower NFA
    /// simulation; raise it only for unusually large patterns. Config:
    /// `regex_dfa_limit` in `.keyhog.toml`; this flag overrides it.
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub regex_dfa_limit: Option<usize>,

    /// GPU batch-input buffer byte budget, e.g. "256MB" or "1GB". Overrides
    /// the VRAM-adaptive default (128 MiB–1 GiB by detected VRAM); the value is
    /// clamped into that range. Larger buffers scan more bytes per GPU dispatch
    /// on big inputs at higher VRAM cost. Config: `gpu_batch_input_limit` in
    /// `.keyhog.toml`; this flag overrides it.
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub gpu_batch_input_limit: Option<usize>,

    #[command(flatten)]
    pub limits: SourceLimitArgs,

    /// Custom input sources to enable (pluggable).
    #[arg(long, value_name = "NAME")]
    pub source: Option<Vec<String>>,

    /// Fast mode: pattern matching only. No decode, no entropy. Maximum speed.
    /// A preset is a BASE: it seeds defaults, then compatible explicit knobs
    /// override it (e.g. `--fast --decode-depth 2` re-enables shallow decode on
    /// top of the fast base). Entropy-only knobs conflict because fast mode
    /// disables entropy, so accepting them would create a no-op flag.
    #[arg(
        long,
        conflicts_with_all = [
            "deep",
            "precision",
            "no_decode",
            "no_entropy",
            "no_entropy_ml_scoring",
            "no_keyword_low_entropy",
            "entropy_threshold",
            "entropy_source_files",
            "min_secret_len"
        ]
    )]
    pub fast: bool,

    /// Deep mode: all features enabled. A preset is a BASE: it seeds defaults
    /// (decode-depth 10, entropy + ML on), then any explicit knob you pass
    /// overrides it — e.g. `--deep --decode-depth 3` runs deep with depth 3, and
    /// `--deep --min-confidence 0.9` raises the floor on the deep base.
    #[arg(long, conflicts_with_all = ["fast", "precision", "no_decode", "no_entropy"])]
    pub deep: bool,

    /// High-precision mode for mass scanning: minimise false positives at the
    /// cost of some recall. Drops entropy-only and ML-speculative findings,
    /// raises the confidence floor to 0.85 (so checksum-failing and weak-signal
    /// matches are suppressed), and uses shallow decode. Stays fully offline
    /// and fast. Use when triaging false positives across a huge corpus is
    /// expensive. `--min-confidence` still overrides the floor on top. Entropy-
    /// only knobs conflict because precision mode disables entropy, so accepting
    /// them would create a no-op flag.
    #[arg(
        long,
        conflicts_with_all = [
            "fast",
            "deep",
            "no_decode",
            "no_entropy",
            "no_entropy_ml_scoring",
            "no_keyword_low_entropy",
            "entropy_threshold",
            "entropy_source_files",
            "min_secret_len"
        ]
    )]
    pub precision: bool,

    /// Lockdown mode: maximum security at the cost of throughput. Enables
    /// every protection in `keyhog_core::apply_protections(true)`
    /// (mlock, refuse-on-coredump-leak, refuse-on-disk-cache), forces
    /// HTTPS-only verifier, refuses to write any cache to disk, and
    /// hard-aborts if any protection fails to take. Use this when keyhog
    /// is running inside EnvSeal or otherwise in a security-critical
    /// embedding.
    #[arg(long)]
    pub lockdown: bool,

    /// Skip decoding base64/hex encoded content
    #[arg(long)]
    pub no_decode: bool,

    /// Disable entropy-based detection
    #[arg(long)]
    pub no_entropy: bool,

    /// Score entropy-fallback candidates with the bare entropy heuristic instead
    /// of routing them through the MoE (the model is authoritative by default).
    /// The default ML path is a recall-safe precision win on the
    /// real-distribution-trained model; this opt-out restores the legacy
    /// heuristic emit. No effect when `--no-entropy` or `--no-ml` is set.
    #[arg(long)]
    pub no_entropy_ml_scoring: bool,

    /// Require high entropy even for credential-keyword-anchored values
    /// (`PASSWORD=`, `*_PASS=`, `secret:`, `api_key=` ...). By default the
    /// keyword key is treated as the evidence and the value is admitted on a far
    /// lower entropy floor (precision carried by the MoE), which is what surfaces
    /// real-world low-entropy config passwords. This opt-out restores the
    /// high-entropy-only generic gate (higher precision, much lower recall on
    /// real corpora). No effect unless the generic keyword bridge fires.
    #[arg(long)]
    pub no_keyword_low_entropy: bool,

    /// Minimum ML confidence score for generic entropy secrets (0.0 to 1.0).
    /// When present it tightens the bar a generic/entropy finding must clear
    /// by composing with the resolved confidence floor via `.max()` in
    /// `orchestrator_config::build_scanner_config`. Absence leaves the
    /// canonical floor untouched.
    #[arg(
        long,
        value_name = "THRESHOLD",
        value_parser = crate::value_parsers::parse_ml_threshold
    )]
    pub ml_threshold: Option<f64>,

    /// Minimum confidence score (0.0 - 1.0) to report findings (default: 0.40).
    #[arg(long, value_name = "FLOAT", value_parser = crate::value_parsers::parse_min_confidence)]
    pub min_confidence: Option<f64>,

    /// Number of parallel scanning threads (default: number of CPU cores)
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_positive_thread_count)]
    pub threads: Option<usize>,

    /// Dedicated filesystem reader threads. Default derives from the scan worker pool.
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_positive_usize)]
    pub reader_threads: Option<usize>,

    /// Fused filesystem pipeline chunk batch size.
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_positive_usize)]
    pub fused_batch: Option<usize>,

    /// Fused filesystem pipeline channel depth.
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_positive_usize)]
    pub fused_depth: Option<usize>,

    /// Hard deadline per chunk scan in milliseconds. Default unset = no
    /// operator deadline; decode still has its internal bomb guard.
    #[arg(long, value_name = "MS", value_parser = crate::value_parsers::parse_positive_millis)]
    pub per_chunk_timeout_ms: Option<u64>,

    /// Deduplication scope for findings.
    #[arg(long, default_value_t = CliDedupScope::Credential, value_enum)]
    pub dedup: CliDedupScope,
    #[arg(skip)]
    pub(crate) dedup_cli_explicit: bool,

    /// Load configuration from a specific file path.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Ignore any ambient `.keyhog.toml`: skip the walk-up discovery from the
    /// scan root and reject an explicit `--config`. The scan then runs on the
    /// compiled-in shipped defaults (the Tier-A `SHIPPED_*` floors/disables)
    /// and nothing else. This is the hermetic, reproducible config used by CI
    /// gates and the benchmark harness, so the measured behavior is the shipped
    /// default BY DESIGN and cannot silently drift when a stray `.keyhog.toml`
    /// appears on an ancestor path; the hermetic-config tests pin that contract.
    #[arg(long, conflicts_with = "config")]
    pub no_config: bool,

    /// Suppress findings that match an existing baseline file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["create_baseline", "update_baseline"])]
    pub baseline: Option<PathBuf>,

    /// Create a new baseline file from current findings and exit
    #[arg(long, value_name = "PATH", conflicts_with_all = ["baseline", "update_baseline"])]
    pub create_baseline: Option<PathBuf>,

    /// Update an existing baseline file with new findings
    #[arg(long, value_name = "PATH", conflicts_with_all = ["baseline", "create_baseline"])]
    pub update_baseline: Option<PathBuf>,

    /// Maximum depth for recursive decoding (1-10, default: 10).
    #[arg(long, value_name = "DEPTH", value_parser = crate::value_parsers::parse_decode_depth)]
    pub decode_depth: Option<usize>,

    /// Maximum file size for decode-through scanning (default: 512KB).
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub decode_size_limit: Option<usize>,

    /// Enable entropy scanning in source code files.
    #[arg(long)]
    pub entropy_source_files: bool,

    /// Disable default file exclusion patterns (lock files, minified files, build outputs, etc.)
    #[arg(long)]
    pub no_default_excludes: bool,

    /// Explicit paths or glob patterns to exclude from scanning.
    #[arg(long, value_name = "PATH", num_args = 1..)]
    pub exclude_paths: Option<Vec<String>>,

    /// Entropy threshold in bits per byte (default: 4.5).
    #[arg(
        long,
        value_name = "BITS",
        allow_hyphen_values = true,
        value_parser = crate::value_parsers::parse_entropy_threshold
    )]
    pub entropy_threshold: Option<f64>,

    /// BPE "rare-not-random" suppression bound in bytes-per-token (default: 2.2).
    /// A surviving entropy/generic candidate whose cl100k_base bytes-per-token is
    /// above this is treated as word-like (dotted API paths, prose) and dropped.
    /// Lower = more aggressive suppression (higher precision, lower recall);
    /// a large value effectively disables the gate.
    #[arg(
        long,
        value_name = "RATIO",
        allow_hyphen_values = true,
        value_parser = crate::value_parsers::parse_entropy_bpe_max_bytes_per_token
    )]
    pub entropy_bpe_max_bytes_per_token: Option<f64>,

    /// Minimum credential length for entropy-fallback candidates (default: 16).
    /// Named detectors keep their own shape-specific length gates.
    #[arg(long, value_name = "N", value_parser = crate::value_parsers::parse_min_secret_len)]
    pub min_secret_len: Option<usize>,

    /// Disable Unicode normalization (not recommended).
    #[arg(long)]
    pub no_unicode_norm: bool,

    /// Disable ML-based confidence scoring.
    #[arg(long)]
    pub no_ml: bool,

    /// Opt out of the bundled test-fixture suppression list. By default
    /// keyhog suppresses well-known public demo credentials (Stripe's
    /// docs example `sk_live_4eC39...`, GitHub's docs example
    /// `ghp_aBcD...`, the keyhog test fixtures, etc.) so the report
    /// stays focused on real leaks rather than tutorial copies. Pass
    /// this flag when you intentionally want those surfaced. Useful
    /// for differential benchmarking against gitleaks / trufflehog
    /// (which do NOT suppress these), or for auditing the suppression
    /// list itself.
    #[arg(long)]
    pub no_suppress_test_fixtures: bool,

    /// Run the built-in backend benchmark corpus and exit.
    #[arg(long)]
    pub benchmark: bool,

    /// Emit a structured `--dogfood` JSON trace to stderr after the
    /// scan: every credential that was matched but suppressed, with the
    /// reason — both example/test/placeholder markers
    /// (`kind: example_suppressed`) AND shape/heuristic gates such as
    /// UUID-v4, bare-hex digest, base64 blob, dashed serial, or repetitive
    /// run (`kind: shape_suppressed`, `reason` names the gate). Credentials
    /// are redacted (prefix only). Useful when keyhog reports zero findings
    /// and you want to know whether a match was made and silenced (and by
    /// which gate), or never reached the engine at all.
    #[arg(long)]
    pub dogfood: bool,

    /// ML weight for confidence scoring, 0.0-1.0 (default: 0.5).
    #[arg(long, value_name = "WEIGHT", value_parser = crate::value_parsers::parse_ml_weight)]
    pub ml_weight: Option<f64>,

    /// Drop every `client-safe` finding before reporting. Use this
    /// for bug-bounty / exfiltration-impact workflows where keys that
    /// are public by design (Sentry DSN, Stripe `pk_*`, Firebase web,
    /// Mapbox `pk.`, PostHog project, Google Maps browser, Mixpanel
    /// project, Algolia search, Datadog browser RUM) are noise: the
    /// vendor *expects* them to ship in client bundles and no
    /// attacker gains server-side access from finding one.
    ///
    /// Default off: client-safe findings still appear in scan output
    /// at the `CLIENT-SAFE` tier (below `LOW`) so a misconfigured
    /// "publishable" key wired into a server-only detector still
    /// surfaces. `--hide-client-safe` is the explicit opt-in to
    /// silence them.
    #[arg(long)]
    pub hide_client_safe: bool,

    /// Treat credentials inside source-code comments (// … / # … /
    /// /* … */ / <!-- … -->) as first-class findings instead of
    /// applying the default comment-context confidence penalty.
    ///
    /// By default keyhog downgrades the confidence of credentials it
    /// sees inside a comment because the most common case is an
    /// engineer pasting an EXAMPLE token into a doc comment. The
    /// drawback is that genuine secrets pasted into a TODO ("rotate
    /// this key, Bob") or a debug-trace comment never surface.
    /// Pass `--scan-comments` for repos where comments are part of
    /// the threat surface: shared snippets directories, leak
    /// post-mortems, training corpora, and CTF-style audits.
    #[arg(long)]
    pub scan_comments: bool,

    /// Known secret prefixes (internal use for config merge)
    #[arg(skip)]
    pub known_prefixes: Vec<String>,
    /// Secret keywords (internal use for config merge)
    #[arg(skip)]
    pub secret_keywords: Vec<String>,
    /// Test keywords (internal use for config merge)
    #[arg(skip)]
    pub test_keywords: Vec<String>,
    /// Placeholder keywords (internal use for config merge)
    #[arg(skip)]
    pub placeholder_keywords: Vec<String>,
}

impl ScanArgs {
    pub(crate) fn mark_cli_value_sources(&mut self, matches: &clap::ArgMatches) {
        self.detectors_cli_explicit =
            matches.value_source("detectors") == Some(ValueSource::CommandLine);
        self.format_cli_explicit = matches.value_source("format") == Some(ValueSource::CommandLine);
        self.dedup_cli_explicit = matches.value_source("dedup") == Some(ValueSource::CommandLine);
    }
}

impl ScanArgs {
    /// Resolve the effective daemon routing policy (CLI-02).
    #[must_use]
    pub fn daemon_mode(&self) -> DaemonMode {
        self.daemon.unwrap_or(DaemonMode::Auto) // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
    }

    /// The ordered set of filesystem roots this invocation scans, the single
    /// source of truth for "which paths" across source construction, daemon
    /// routing, and the scan-target header.
    ///
    /// Positional roots live in one vector, so Clap's generated usage, parsing,
    /// daemon eligibility, and source construction share the same model. The
    /// positional vector wins over the orchestrator's internal first-root copy
    /// into `path`; Clap guarantees a user cannot combine positional roots with
    /// the explicit single-root `--path` flag.
    #[must_use]
    pub fn scan_roots(&self) -> Vec<PathBuf> {
        if !self.input.is_empty() {
            return self.input.clone();
        }
        self.path.clone().into_iter().collect()
    }
}
