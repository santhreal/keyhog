//! Command-line argument parsing for KeyHog.

use clap::{Parser, ValueEnum};
use keyhog_core::DedupScope;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "keyhog",
    about = "KeyHog: The developer-first secret scanner.\nFind leaked credentials in your code before hackers do. Fast, accurate, and verifying.",
    after_help = "EXIT CODES:\n  0   Success (no secrets found)\n  1   Secrets found (unverified or verification skipped)\n  2   Runtime error (e.g., config error, unreadable path)\n  10  Live credentials found (requires --verify)",
    disable_version_flag = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Print version, build information, and statistics
    #[arg(short = 'V', long)]
    pub version: bool,
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// 🔍 Scan files, directories, or repositories for secrets
    #[command(verbatim_doc_comment)]
    Scan(Box<ScanArgs>),

    /// 🪝 Manage git pre-commit hooks
    #[command(verbatim_doc_comment)]
    Hook {
        #[command(subcommand)]
        command: crate::subcommands::hook::HookCommand,
    },

    /// 📋 List all loaded secret detectors
    #[command(verbatim_doc_comment)]
    Detectors(DetectorArgs),

    /// 📖 Explain a detector — spec, regex, severity, rotation guide
    #[command(verbatim_doc_comment)]
    Explain(ExplainArgs),

    /// 🔀 Diff two baseline JSON files — show NEW / RESOLVED / UNCHANGED
    #[command(verbatim_doc_comment)]
    Diff(DiffArgs),

    /// 📊 Show or update per-detector Bayesian calibration counters
    #[command(verbatim_doc_comment)]
    Calibrate(CalibrateArgs),

    /// 👁  Watch a directory and scan files as they change (daemon mode)
    #[command(verbatim_doc_comment)]
    Watch(WatchArgs),

    /// 🔧 Print shell completion script (bash, zsh, fish, powershell, elvish)
    #[command(verbatim_doc_comment)]
    Completion(CompletionArgs),

    /// ⚙️  Inspect detected hardware + the auto-selected scan backend
    #[command(verbatim_doc_comment)]
    Backend(BackendArgs),

    /// 🛰  Recursive system-wide scan: every mounted drive, every git history
    #[command(verbatim_doc_comment)]
    ScanSystem(ScanSystemArgs),
}

#[derive(Parser)]
pub struct ScanSystemArgs {
    /// Hard ceiling on total bytes scanned. Walker tracks running total
    /// and stops when the next file would push past this. Examples:
    ///   --space 50G   --space 1T   --space 500M
    /// Default 50 GiB — enough to cover most home directories without
    /// drowning the scan on a NAS-mount.
    #[arg(long, default_value = "50G", value_parser = parse_byte_size)]
    pub space: u64,

    /// Include network-mounted filesystems (NFS, SMB, sshfs). Off by
    /// default — these are typically slow and contain other people's
    /// secrets the user hasn't authorized scanning.
    #[arg(long, default_value_t = false)]
    pub include_network: bool,

    /// Skip auto-discovery of `.git` directories. By default scan-system
    /// finds every git repo on every walked drive and runs --git-history
    /// on each, including bare repos and submodules. Disable to save time
    /// when you only care about working-tree state.
    #[arg(long, default_value_t = false)]
    pub no_git_history: bool,

    /// Honor `.gitignore` like `keyhog scan` does. Default OFF — system
    /// scans are paranoid because an attacker stashing a leaked key
    /// would `.gitignore` it. Set this to behave like a normal scan.
    #[arg(long, default_value_t = false)]
    pub respect_gitignore: bool,

    /// Output JSON path. Defaults to stderr (text format) if unset.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Detector directory (same as `keyhog scan --detectors`).
    #[arg(long, default_value = "detectors")]
    pub detectors: PathBuf,

    /// Apply hardening protections (mlocked + coredump-blocked) and
    /// refuse the operations that weaken detection or expand attack
    /// surface. See `keyhog scan --lockdown` for the full list.
    #[arg(long, default_value_t = false)]
    pub lockdown: bool,
}

/// Parse human-readable byte sizes: `50G`, `1T`, `500M`, `1024K`, `1234`.
fn parse_byte_size(s: &str) -> Result<u64, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty size".into());
    }
    let (num_part, suffix) = trimmed.split_at(
        trimmed
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(trimmed.len()),
    );
    let n: f64 = num_part.parse().map_err(|e| format!("bad number: {e}"))?;
    let multiplier: u64 = match suffix.trim().to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" | "TIB" => 1024_u64.pow(4),
        other => return Err(format!("unknown size suffix: {other}")),
    };
    Ok((n * multiplier as f64) as u64)
}

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

    /// Pattern count to use for routing simulation. Defaults to 1509
    /// (current corpus). Use this to test threshold behavior.
    #[arg(long, default_value_t = 1509)]
    pub patterns: usize,
}

#[derive(Parser)]
pub struct WatchArgs {
    /// Directory to watch recursively. Defaults to the current directory.
    #[arg(default_value = ".")]
    pub path: PathBuf,
    /// Detector TOML directory. Falls back to embedded corpus if missing.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Quiet mode — only print findings (suppress "watching X" status).
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Parser)]
pub struct CalibrateArgs {
    /// Mark these detector IDs as confirmed true positives (α += 1 each).
    /// Use `--tp` repeatedly: `--tp aws-access-key --tp github-pat`.
    #[arg(long, value_name = "DETECTOR_ID")]
    pub tp: Vec<String>,
    /// Mark these detector IDs as confirmed false positives (β += 1 each).
    #[arg(long, value_name = "DETECTOR_ID")]
    pub fp: Vec<String>,
    /// Print every recorded counter and exit (no updates).
    #[arg(long)]
    pub show: bool,
    /// Override the calibration cache path. Defaults to
    /// $XDG_CACHE_HOME/keyhog/calibration.json.
    #[arg(long, value_name = "PATH")]
    pub cache: Option<PathBuf>,
}

#[derive(Parser)]
pub struct DiffArgs {
    /// Baseline file A (the "before" / older state).
    pub before: PathBuf,
    /// Baseline file B (the "after" / newer state).
    pub after: PathBuf,
    /// Suppress the `UNCHANGED` section (default: shown).
    #[arg(long)]
    pub hide_unchanged: bool,
    /// Emit results as JSON instead of human-readable text. Useful for CI
    /// that wants to gate merges on regressions programmatically.
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser)]
pub struct ExplainArgs {
    /// Detector ID to explain (e.g. `aws-access-key`, `github-pat`).
    /// Use `keyhog detectors` to list available IDs.
    pub detector_id: String,

    /// Detector TOML directory; falls back to the embedded corpus when
    /// missing. Same semantics as `keyhog detectors --detectors`.
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
}

#[derive(Parser)]
pub struct ScanArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,

    /// Positional shorthand for `--path`
    #[arg(value_name = "PATH", conflicts_with = "path")]
    pub input: Option<PathBuf>,

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

    /// Scan a Docker image by unpacking `docker image save`
    #[cfg(feature = "docker")]
    #[arg(long, value_name = "IMAGE")]
    pub docker_image: Option<String>,

    /// Scan JavaScript, source maps, or WASM binaries at URLs for secrets
    #[cfg(feature = "web")]
    #[arg(long, value_name = "URL", num_args = 1..)]
    pub url: Option<Vec<String>>,

    /// Max git commits to traverse
    #[cfg(feature = "git")]
    #[arg(long, default_value = "1000")]
    pub max_commits: usize,

    /// Verify discovered credentials via API calls
    #[cfg(feature = "verify")]
    #[arg(long)]
    pub verify: bool,

    /// Enable out-of-band callback verification via an embedded interactsh
    /// client. For webhook- and callback-shaped credentials, OOB verification
    /// proves the credential is exfil-capable: we mint a per-finding
    /// subdomain on the configured collector, embed it in the verification
    /// probe, and confirm the service actually called back. Off by default.
    /// See docs/OOB.md for the threat model and self-hosting guidance.
    #[cfg(feature = "verify")]
    #[arg(long, requires = "verify")]
    pub verify_oob: bool,

    /// Interactsh server for OOB verification. Defaults to projectdiscovery's
    /// public collector at `oast.fun`. Use a self-hosted server for sensitive
    /// scans — the collector sees correlation IDs and the IPs of services
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

    /// Output format
    #[arg(long, default_value = "text", value_enum)]
    pub format: OutputFormat,

    /// Show progress bar
    #[arg(long)]
    pub progress: bool,

    /// Stream findings to stderr as they're discovered, instead of
    /// waiting for the full scan + verify pipeline to finish before
    /// printing anything. Each line is a single redacted preview
    /// (`SEVERITY  SERVICE/DETECTOR  PATH:LINE`). The final
    /// formatted report (text/json/sarif/jsonl) still lands on stdout
    /// or `--output` after dedup + verification complete — the stream
    /// is purely a UX hint that the scanner is making progress on
    /// long-running runs (large monorepos, scan-system, GitHub orgs).
    #[arg(long)]
    pub stream: bool,

    /// Write findings to file
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verification timeout in seconds
    #[arg(long, default_value = "5")]
    pub timeout: u64,

    /// Max concurrent verification requests per service
    #[arg(long, default_value = "5")]
    pub rate: usize,

    /// Steady-state cap for verification calls *per service*, in
    /// requests-per-second. Default 5.0. Drop this to be polite to
    /// upstream APIs when scanning a tree with hundreds of legitimate
    /// findings (test fixtures, examples) — every finding produces a
    /// live verify call and most public APIs throttle aggressively.
    /// The limiter applies even with `--verify-batch` (which adds
    /// per-service serialisation on top).
    #[cfg(feature = "verify")]
    #[arg(long, value_name = "RPS", default_value = "5.0")]
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

    /// Min severity to report: info, low, medium, high, critical
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Maximum file size to scan (default: 10MB).
    #[arg(long, value_name = "SIZE", value_parser = crate::value_parsers::parse_byte_size)]
    pub max_file_size: Option<usize>,

    /// Custom input sources to enable (pluggable).
    #[arg(long, value_name = "NAME")]
    pub source: Option<Vec<String>>,

    /// Fast mode: pattern matching only. No decode, no entropy. Maximum speed.
    #[arg(long, conflicts_with_all = ["deep", "no_decode", "no_entropy"])]
    pub fast: bool,

    /// Deep mode: all features enabled.
    #[arg(long, conflicts_with_all = ["fast", "no_decode", "no_entropy"])]
    pub deep: bool,

    /// Lockdown mode: maximum security at the cost of throughput. Enables
    /// every protection in `keyhog_core::hardening::apply_lockdown_protections`
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

    /// Minimum ML confidence score for generic entropy secrets (0.0 to 1.0)
    #[arg(long, default_value = "0.5", value_name = "THRESHOLD")]
    pub ml_threshold: f64,

    /// Minimum confidence score (0.0 - 1.0) to report findings
    #[arg(long, value_name = "FLOAT", value_parser = crate::value_parsers::parse_min_confidence)]
    pub min_confidence: Option<f64>,

    /// Number of parallel scanning threads (default: number of CPU cores)
    #[arg(long, value_name = "N")]
    pub threads: Option<usize>,

    /// Deduplication scope for findings.
    #[arg(long, default_value = "credential", value_enum)]
    pub dedup: CliDedupScope,

    /// Load configuration from a specific file path.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Suppress findings that match an existing baseline file
    #[arg(long, value_name = "PATH", conflicts_with_all = ["create_baseline", "update_baseline"])]
    pub baseline: Option<PathBuf>,

    /// Create a new baseline file from current findings and exit
    #[arg(long, value_name = "PATH", conflicts_with_all = ["baseline", "update_baseline"])]
    pub create_baseline: Option<PathBuf>,

    /// Update an existing baseline file with new findings
    #[arg(long, value_name = "PATH", conflicts_with_all = ["baseline", "create_baseline"])]
    pub update_baseline: Option<PathBuf>,

    /// Maximum depth for recursive decoding (1-10, default: 4).
    #[arg(long, value_name = "DEPTH", value_parser = crate::value_parsers::parse_decode_depth)]
    pub decode_depth: Option<usize>,

    /// Maximum file size for decode-through scanning (default: 64KB).
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
    #[arg(long, value_name = "BITS")]
    pub entropy_threshold: Option<f64>,

    /// Disable Unicode normalization (not recommended).
    #[arg(long)]
    pub no_unicode_norm: bool,

    /// Disable ML-based confidence scoring.
    #[arg(long)]
    pub no_ml: bool,

    /// Run the built-in backend benchmark corpus and exit.
    #[arg(long)]
    pub benchmark: bool,

    /// ML weight for confidence scoring, 0.0-1.0 (default: 0.6).
    #[arg(long, value_name = "WEIGHT")]
    pub ml_weight: Option<f64>,

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

#[derive(Parser)]
pub struct DetectorArgs {
    /// Detector TOML directory
    #[arg(short, long, default_value = "detectors")]
    pub detectors: PathBuf,
    /// Filter detectors by substring match (case-insensitive) against id,
    /// name, service, and keywords. Useful for finding detectors in the
    /// 888-strong corpus (e.g. `keyhog detectors --search aws`).
    #[arg(short, long)]
    pub search: Option<String>,
    /// Print full detector spec (regex, prefixes, keywords) instead of
    /// the grouped service summary. Pairs naturally with `--search`.
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
    /// Audit detectors against the quality gate (`keyhog_core::validate_detector`).
    /// Prints every issue grouped by detector and exits non-zero (3) if any
    /// `Error`-severity issue was found. Warnings are reported but do not
    /// fail the run. Pairs with `--detectors <DIR>` for CI gating.
    #[arg(long, conflicts_with = "fix")]
    pub audit: bool,
    /// Apply safe automated fixes to the detector TOMLs in `--detectors`.
    /// Currently rewrites single-brace template references (`{name}`) to
    /// the double-brace form (`{{name}}`) within `[detector.verify*]`
    /// blocks — the one fix the interpolator's contract makes safe to
    /// perform mechanically. Other validator findings are left alone
    /// (they need human judgement). Use `--dry-run` to preview rewrites
    /// without touching the filesystem.
    #[arg(long, conflicts_with = "audit")]
    pub fix: bool,
    /// Show the rewrites `--fix` *would* make without writing them. No-op
    /// unless `--fix` is also set.
    #[arg(long, requires = "fix")]
    pub dry_run: bool,
}

#[derive(Clone, ValueEnum)]
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

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Jsonl,
    Sarif,
}

#[derive(Clone, ValueEnum, PartialEq)]
pub enum CliDedupScope {
    Credential,
    File,
    None,
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
