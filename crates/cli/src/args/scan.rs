//! `keyhog scan` CLI arguments.
//!
//! Split out of `args.rs` so the parent module stays under the 500-line
//! modularity cap (the scan subcommand has the largest flag surface of
//! any subcommand by a wide margin).

use clap::Parser;
use std::path::PathBuf;

use super::{CliDedupScope, OutputFormat, SeverityFilter};

#[derive(Parser, Clone)]
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

    /// Route outbound HTTP through a proxy (`http://burp:8080`,
    /// `socks5://127.0.0.1:9050`, etc.). When unset, falls back to
    /// `KEYHOG_PROXY` env var, then reqwest's built-in handling of
    /// `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY`. Pass
    /// `off` to disable proxying entirely (including env inheritance)
    /// for air-gapped scans.
    #[cfg(any(feature = "web", feature = "github", feature = "s3"))]
    #[arg(long, value_name = "URL")]
    pub proxy: Option<String>,

    /// Skip TLS certificate verification for every outbound HTTP
    /// request. Needed when scanning through Burp / mitmproxy /
    /// corporate-MITM CAs that present self-signed certificates.
    /// Off by default; equivalent env var: `KEYHOG_INSECURE_TLS=1`.
    #[cfg(any(feature = "web", feature = "github", feature = "s3"))]
    #[arg(long)]
    pub insecure: bool,

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

    /// Output format
    #[arg(long, default_value = "text", value_enum)]
    pub format: OutputFormat,

    /// Show progress bar
    #[arg(long)]
    pub progress: bool,

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

    /// Force a specific scan backend instead of letting the auto-router
    /// choose. Same effect as `KEYHOG_BACKEND=<value>` but visible in
    /// the CLI and harder to forget. Values: `gpu`, `mega-scan`, `simd`,
    /// `cpu`. The CLI flag takes precedence over the env var when both
    /// are set.
    #[arg(
        long,
        value_name = "BACKEND",
        value_parser = clap::builder::PossibleValuesParser::new([
            "gpu",
            "mega-scan",
            "megascan",
            "simd",
            "cpu",
            "auto",
        ])
    )]
    pub backend: Option<String>,

    /// Force the scan through a running `keyhog daemon`. Fails if no
    /// daemon is up. Use this in pre-commit hooks / IDE save handlers
    /// where the ~3 s in-process cold-start dominates the actual scan;
    /// the daemon holds a compiled scanner so each invocation is sub-ms
    /// IPC + scan. See `keyhog daemon start --help`.
    #[arg(long, conflicts_with = "no_daemon")]
    pub daemon: bool,

    /// Force in-process scanning even when a daemon is running. Useful
    /// for debugging, hardware probing, contract tests, or any case
    /// where you need the orchestrator's full pipeline (baseline /
    /// merkle skip cache / verification) which the daemon's stdin-
    /// only fast path does not replicate.
    #[arg(long, conflicts_with = "daemon")]
    pub no_daemon: bool,

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

    /// Min severity to report: info, low, medium, high, critical
    #[arg(short, long, value_enum)]
    pub severity: Option<SeverityFilter>,

    /// Maximum file size to scan. Files larger than this are listed in
    /// the end-of-scan "files skipped: exceeded --max-file-size"
    /// summary. Default is 100 MiB, chosen to match the
    /// `FilesystemSource` ceiling (files above 64 MiB already use
    /// windowed scanning). kimi-dogfood-3 #135: prior help text said
    /// "10MB" but no default was wired; the 100 MiB FilesystemSource
    /// default was the de facto cap.
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

    /// Custom input sources to enable (pluggable).
    #[arg(long, value_name = "NAME")]
    pub source: Option<Vec<String>>,

    /// Fast mode: pattern matching only. No decode, no entropy. Maximum speed.
    #[arg(long, conflicts_with_all = ["deep", "precision", "no_decode", "no_entropy"])]
    pub fast: bool,

    /// Deep mode: all features enabled.
    #[arg(long, conflicts_with_all = ["fast", "precision", "no_decode", "no_entropy"])]
    pub deep: bool,

    /// High-precision mode for mass scanning: minimise false positives at the
    /// cost of some recall. Drops entropy-only and ML-speculative findings,
    /// raises the confidence floor to 0.85 (so checksum-failing and weak-signal
    /// matches are suppressed), and uses shallow decode. Stays fully offline
    /// and fast. Use when triaging false positives across a huge corpus is
    /// expensive. `--min-confidence` still overrides the floor on top.
    #[arg(long, conflicts_with_all = ["fast", "deep", "no_decode", "no_entropy"])]
    pub precision: bool,

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

    /// Minimum ML confidence score for generic entropy secrets (0.0 to 1.0).
    /// When raised above the resolved confidence floor it tightens the bar a
    /// generic/entropy finding must clear (composed via `.max()` in
    /// `orchestrator_config::build_scanner_config`); a value at or below the
    /// floor is a no-op. The `default_value` literal here is the canonical
    /// `orchestrator_config::ML_THRESHOLD_DEFAULT` (kept in sync); an unset
    /// flag leaves the canonical floor untouched.
    #[arg(
        long,
        default_value = "0.5",
        value_name = "THRESHOLD",
        value_parser = crate::value_parsers::parse_ml_threshold
    )]
    pub ml_threshold: f64,

    /// Minimum confidence score (0.0 - 1.0) to report findings (default: 0.40).
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
    #[arg(long, value_name = "BITS")]
    pub entropy_threshold: Option<f64>,

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
    /// scan: every example/test/placeholder credential that was
    /// suppressed, with the reason. Credentials are redacted (prefix
    /// only). Useful when keyhog reports zero findings and you want
    /// to know whether a match was made and silenced, or never
    /// reached the engine at all.
    #[arg(long)]
    pub dogfood: bool,

    /// ML weight for confidence scoring, 0.0-1.0 (default: 0.5).
    #[arg(long, value_name = "WEIGHT")]
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
