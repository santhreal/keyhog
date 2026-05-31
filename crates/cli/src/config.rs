//! Configuration file handling for the KeyHog CLI.

use crate::args::ScanArgs;
use crate::value_parsers::{parse_dedup_scope, parse_output_format, parse_severity_filter};
use std::path::PathBuf;

/// On-disk `.keyhog.toml` configuration file that mirrors CLI arguments.
/// CLI flags always override values from the config file.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct ConfigFile {
    /// Path to detector TOMLs directory.
    pub detectors: Option<String>,
    /// Minimum severity to report: info, low, medium, high, critical.
    pub severity: Option<String>,
    /// Output format: text, json, jsonl, sarif.
    pub format: Option<String>,
    /// Enable fast mode (pattern matching only).
    pub fast: Option<bool>,
    /// Enable deep mode (all features).
    pub deep: Option<bool>,
    /// Skip decode-through scanning.
    pub no_decode: Option<bool>,
    /// Skip entropy-based detection.
    pub no_entropy: Option<bool>,
    /// Minimum confidence score (0.0 - 1.0).
    pub min_confidence: Option<f64>,
    /// Number of parallel scanning threads.
    pub threads: Option<usize>,
    /// Deduplication scope: credential, file, none.
    pub dedup: Option<String>,
    /// Whether to verify discovered credentials.
    pub verify: Option<bool>,
    /// Verification timeout in seconds.
    pub timeout: Option<u64>,
    /// Max concurrent verification requests per service.
    pub rate: Option<usize>,
    /// Maximum git commits to traverse.
    pub max_commits: Option<usize>,
    /// Show full credentials (not redacted).
    pub show_secrets: Option<bool>,
    /// Maximum depth for recursive decoding (1-10, default: 10 — the canonical
    /// `ScanConfig::default().max_decode_depth`).
    pub decode_depth: Option<usize>,
    /// Maximum file size for decode-through scanning (default: 512KB — the
    /// canonical `ScanConfig::default().max_decode_bytes`).
    pub decode_size_limit: Option<String>,
    /// Enable entropy scanning in source code files.
    pub entropy_source_files: Option<bool>,
    /// Entropy threshold in bits per byte (default: 4.5).
    pub entropy_threshold: Option<f64>,
    /// Disable Unicode normalization.
    pub no_unicode_norm: Option<bool>,
    /// Disable ML-based confidence scoring.
    pub no_ml: Option<bool>,
    /// Explicit paths or glob patterns to exclude from scanning.
    pub exclude_paths: Option<Vec<String>>,
    /// Maximum file size to scan (can be string like '1MB' or bytes).
    pub max_file_size: Option<String>,
    /// Per-regex lazy-DFA cache CEILING, e.g. "256KB" / "1MB" (default 1 MiB).
    /// Worst-case bound for pathological patterns, not a general memory lever
    /// (typical detectors stay under it). The `--regex-dfa-limit` CLI flag
    /// overrides this.
    pub regex_dfa_limit: Option<String>,
    /// ML weight for confidence scoring, 0.0-1.0 (default: 0.5 — the canonical
    /// `ScanConfig::default().ml_weight`).
    pub ml_weight: Option<f64>,
    /// Known secret prefixes used to boost confidence.
    pub known_prefixes: Option<Vec<String>>,
    /// Keywords indicating a secret context (e.g. "api_key", "token").
    pub secret_keywords: Option<Vec<String>>,
    /// Keywords indicating a test/mock context (e.g. "test", "fake").
    pub test_keywords: Option<Vec<String>>,
    /// Keywords indicating a placeholder value (e.g. "change_me", "todo").
    pub placeholder_keywords: Option<Vec<String>>,

    // ─── Documented nested sections ─────────────────────────────────
    // The README documents `[scan]`, `[detector.X]`, and `[lockdown]`
    // nested tables; all three are now WIRED in `apply_config_file`
    // (`[scan]` -> the flat scalar args, `[detector.X] enabled` -> the
    // disabled-detector set, `[detector.X] min_confidence` -> the
    // per-detector confidence floor applied in scan post-processing,
    // `[lockdown] require` -> ConfigOutcome). They were previously
    // parsed-and-silently-ignored - a user copying the README believed
    // e.g. lockdown enforcement was active when it never reached the
    // runtime.
    //
    // The `[detector.X]` floors/disables additionally ship in the binary via
    // the compiled Tier-A defaults (`SHIPPED_DETECTOR_FLOORS` /
    // `SHIPPED_DISABLED_DETECTORS`), so they apply on the bench/default path
    // too - not only when a user authors a `.keyhog.toml`. A file
    // `[detector.X]` entry overrides the compiled floor for that id. This is
    // the fix for the "tuned != benched != shipped" leak: the only Tier-A knob
    // that can suppress a specific noisy detector now reaches the very runs
    // that set the headline metric.
    //
    // `[allowlist]` is still parse-only: its governance flags
    // (require_reason / require_approved_by / max_expires_days) need the
    // allowlist evaluator to enforce them, which is not yet built, so the
    // README no longer presents it as active. Suppression itself works via
    // `.keyhogignore`. New nested fields must ship with BOTH a parser entry
    // here AND the wire-up in apply_config_file - never parse-only.
    /// `[scan]` - runtime scan policy. Mirrors top-level scalar fields.
    pub scan: Option<ScanSection>,
    /// `[allowlist]` - `.keyhogignore` discovery + governance metadata.
    pub allowlist: Option<AllowlistSection>,
    /// `[detector.<id>]` - per-detector overrides keyed by detector_id.
    pub detector: Option<std::collections::HashMap<String, DetectorSection>>,
    /// `[lockdown]` - refuse to start unless explicit `--lockdown` flag.
    pub lockdown: Option<LockdownSection>,
}

/// `[scan]` nested table. Fields here map 1:1 to the flat top-level
/// scalars and override them when both are present. Issue #5: README
/// documented `[scan]` as the canonical surface; we now accept both
/// shapes and warn-on-mismatch.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct ScanSection {
    pub severity: Option<String>,
    pub min_confidence: Option<f64>,
    pub format: Option<String>,
    pub exclude: Option<Vec<String>>,
    pub threads: Option<usize>,
    pub dedup: Option<String>,
}

/// `[allowlist]` nested table. Issue #5: README documents `file`,
/// `require_reason`, `require_approved_by`, `max_expires_days`. The
/// allowlist enforcement layer reads `.keyhogignore` directly so the
/// `file` override is the wiring point; the governance flags are
/// surfaced to the allowlist evaluator post-parse.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct AllowlistSection {
    pub file: Option<String>,
    pub require_reason: Option<bool>,
    pub require_approved_by: Option<bool>,
    pub max_expires_days: Option<u64>,
}

/// `[detector.<id>]` per-detector override. `enabled = false` drops the
/// detector from the corpus (wired via `ConfigOutcome::disabled_detectors`).
/// `min_confidence = <f>` sets a per-detector confidence floor applied in
/// scan post-processing (wired via `ConfigOutcome::detector_min_confidence`),
/// taking precedence over the global `--min-confidence`. Both are
/// README-documented and now reach the runtime.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct DetectorSection {
    pub enabled: Option<bool>,
    pub min_confidence: Option<f64>,
}

/// `[lockdown]` enforcement. `require = true` refuses to run unless
/// the operator passes `--lockdown` on the CLI. Issue #5: README example
/// implied this was active; pre-fix the table was discarded silently.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default)]
pub struct LockdownSection {
    pub require: Option<bool>,
}

/// Compiled-in Tier-A per-detector confidence floors that ship inside the
/// binary, independent of any on-disk `.keyhog.toml`. This is the fix for the
/// "tuned != benched != shipped" leak: `[detector.<id>] min_confidence`
/// overrides used to exist ONLY in a user-authored `.keyhog.toml`, so the
/// bench and every default scan (which find no such file and short-circuit to
/// `ConfigOutcome::default()`) never exercised them. Floors listed here are
/// seeded into every `ConfigOutcome` regardless of whether a config file is
/// present, so the benched/default path runs the same per-detector tuning the
/// shipped binary carries. A user `.keyhog.toml` `[detector.<id>]
/// min_confidence` overrides the compiled value for that id (operator intent
/// wins per-detector); ids only listed here still apply on the no-file path.
///
/// Entries are `(detector_id, floor)`. Edit this table to raise the floor on a
/// specific noisy detector (e.g. loosened twilio / connection-string ones)
/// without requiring the operator to author a TOML; the change ships in the
/// binary and the bench picks it up automatically. Tier B (the detector
/// corpus) stays in `rules/`; this is the Tier-A scalar knob.
pub const SHIPPED_DETECTOR_FLOORS: &[(&str, f64)] = &[];

/// Compiled-in Tier-A detector disables that ship inside the binary, same
/// rationale as [`SHIPPED_DETECTOR_FLOORS`]: a detector listed here is dropped
/// from the loaded corpus on every path, including the no-config bench/default
/// path. A user `.keyhog.toml` `[detector.<id>] enabled = true` cannot
/// re-enable a compiled disable today (the merge is additive); keep this table
/// for detectors that must never fire by default.
pub const SHIPPED_DISABLED_DETECTORS: &[&str] = &[];

/// Build the baseline [`ConfigOutcome`] from the compiled-in Tier-A defaults.
/// Every return path of [`apply_config_file`] starts from this (not the empty
/// `ConfigOutcome::default()`), so the per-detector floors / disables that ship
/// in the binary reach the benched and default scans even when no
/// `.keyhog.toml` exists on disk.
fn shipped_config_outcome() -> ConfigOutcome {
    ConfigOutcome {
        disabled_detectors: SHIPPED_DISABLED_DETECTORS
            .iter()
            .map(|id| (*id).to_string())
            .collect(),
        require_lockdown: false,
        detector_min_confidence: SHIPPED_DETECTOR_FLOORS
            .iter()
            .map(|(id, floor)| ((*id).to_string(), *floor))
            .collect(),
    }
}

/// Search for `.keyhog.toml` starting from the scan root, walking up to the
/// filesystem root. Returns `None` when no config file is found.
pub fn find_config_file(start: Option<&std::path::Path>) -> Option<PathBuf> {
    let mut dir = start
        .and_then(|p| {
            if p.is_dir() {
                Some(p.to_path_buf())
            } else {
                p.parent().map(std::path::Path::to_path_buf)
            }
        })
        .or_else(|| std::env::current_dir().ok())?;

    loop {
        let candidate = dir.join(".keyhog.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Outcome of merging `.keyhog.toml` into `ScanArgs`, beyond the in-place
/// `args` mutations: the things the caller must still act on.
///
/// Prefer [`crate::orchestrator_config::resolve_scan_config`] over calling
/// [`apply_config_file`] directly: it runs this same merge and then folds the
/// result into a single [`crate::orchestrator_config::ResolvedScanConfig`] - the
/// engine `ScannerConfig` PLUS the post-scan floors - so the live worker reads
/// one resolved struct instead of re-deriving the confidence floor from raw
/// `args` (the "tuned != benched != shipped" leak). `detector_min_confidence`
/// here is the source the resolved struct carries through to post-processing.
#[derive(Debug, Default)]
pub struct ConfigOutcome {
    /// Detector ids disabled via `[detector.<id>] enabled = false`; the caller
    /// drops these from the loaded corpus.
    pub disabled_detectors: Vec<String>,
    /// `[lockdown] require = true`: this repo's config DEMANDS lockdown mode.
    /// The caller must refuse to run unless `--lockdown` was passed. Documented
    /// in the README ("refuse to run without --lockdown") but, before this
    /// wiring, parsed and silently ignored - a security control that looked
    /// active but never enforced.
    pub require_lockdown: bool,
    /// Per-detector `[detector.<id>] min_confidence = <f>` overrides keyed by
    /// detector id. Applied in scan post-processing: a finding from detector
    /// `id` is dropped when its confidence is below this threshold, taking
    /// precedence over the global `--min-confidence`. Was parsed into
    /// `DetectorSection.min_confidence` and silently ignored before this
    /// wiring (the README documents it as active).
    pub detector_min_confidence: std::collections::HashMap<String, f64>,
}

/// Load and merge a `.keyhog.toml` config file into the parsed `ScanArgs`.
/// CLI flags always take precedence over the config file.
///
/// Returns a [`ConfigOutcome`] the caller must act on: detector ids disabled
/// via `[detector.<id>] enabled = false` (dropped from the corpus) and whether
/// `[lockdown] require = true` demands `--lockdown`. Both are README-documented
/// but were parsed-and-silently-ignored before this wiring.
#[allow(clippy::collapsible_if, clippy::cmp_owned)]
pub fn apply_config_file(args: &mut ScanArgs) -> ConfigOutcome {
    let config_path = args
        .config
        .clone()
        .or_else(|| find_config_file(args.path.as_deref()));

    let config_path = match config_path {
        Some(path) => path,
        // No `.keyhog.toml` on the walk-up path (the bench/default case): still
        // ship the compiled Tier-A floors/disables so tuned == benched ==
        // shipped, instead of the empty `ConfigOutcome::default()`.
        None => return shipped_config_outcome(),
    };

    let raw = match std::fs::read_to_string(&config_path) {
        Ok(content) => content,
        Err(error) => {
            tracing::warn!(
                path = %config_path.display(),
                "failed to read .keyhog.toml: {error}"
            );
            return shipped_config_outcome();
        }
    };

    let config: ConfigFile = match toml::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!(
                "⚠️  WARNING: Failed to parse .keyhog.toml at {}: {}",
                config_path.display(),
                error
            );
            tracing::warn!(
                path = %config_path.display(),
                "failed to parse .keyhog.toml: {error}"
            );
            return shipped_config_outcome();
        }
    };

    tracing::debug!(path = %config_path.display(), "loaded .keyhog.toml");

    // Apply config values only when no explicit CLI flag was given.
    if let Some(ref detectors_str) = config.detectors {
        if args.detectors == PathBuf::from("detectors") {
            args.detectors = PathBuf::from(detectors_str);
        }
    }

    if let Some(ref format_str) = config.format {
        // Only override if the user didn't set --format (defaults to Text).
        if matches!(args.format, crate::args::OutputFormat::Text) {
            if let Some(fmt) = parse_output_format(format_str) {
                args.format = fmt;
            }
        }
    }

    if let Some(ref severity_str) = config.severity {
        if args.severity.is_none() {
            args.severity = parse_severity_filter(severity_str);
        }
    }

    if let Some(fast) = config.fast {
        if !args.fast && !args.deep {
            args.fast = fast;
        }
    }

    if let Some(deep) = config.deep {
        if !args.fast && !args.deep {
            args.deep = deep;
        }
    }

    if let Some(no_decode) = config.no_decode {
        if !args.no_decode {
            args.no_decode = no_decode;
        }
    }

    if let Some(_no_entropy) = config.no_entropy {
        if !args.no_entropy {
            args.no_entropy = _no_entropy;
        }
    }

    if let Some(min_conf) = config.min_confidence {
        if args.min_confidence.is_none() {
            args.min_confidence = Some(min_conf);
        }
    }

    if let Some(threads) = config.threads {
        if args.threads.is_none() {
            args.threads = Some(threads);
        }
    }

    if let Some(ref dedup_str) = config.dedup {
        // credential is the clap default
        if matches!(args.dedup, crate::args::CliDedupScope::Credential) {
            if let Some(scope) = parse_dedup_scope(dedup_str) {
                args.dedup = scope;
            }
        }
    }

    if let Some(_verify) = config.verify {
        #[cfg(feature = "verify")]
        if !args.verify {
            args.verify = _verify;
        }
    }

    if let Some(timeout) = config.timeout {
        if args.timeout == 5 {
            args.timeout = timeout;
        }
    }

    if let Some(rate) = config.rate {
        if args.rate == 5 {
            args.rate = rate;
        }
    }

    if let Some(_max_commits) = config.max_commits {
        #[cfg(feature = "git")]
        if args.max_commits == 1000 {
            args.max_commits = _max_commits;
        }
    }

    if let Some(show_secrets) = config.show_secrets {
        if !args.show_secrets {
            args.show_secrets = show_secrets;
        }
    }

    if let Some(depth) = config.decode_depth {
        if args.decode_depth.is_none() {
            args.decode_depth = Some(depth);
        }
    }

    if let Some(ref limit_str) = config.decode_size_limit {
        if args.decode_size_limit.is_none() {
            if let Ok(size) = crate::value_parsers::parse_byte_size(limit_str) {
                args.decode_size_limit = Some(size);
            }
        }
    }

    if let Some(_entropy_source) = config.entropy_source_files {
        if !args.entropy_source_files {
            args.entropy_source_files = _entropy_source;
        }
    }

    if let Some(_entropy_threshold) = config.entropy_threshold {
        if args.entropy_threshold.is_none() {
            args.entropy_threshold = Some(_entropy_threshold);
        }
    }

    if let Some(no_unicode_norm) = config.no_unicode_norm {
        if !args.no_unicode_norm {
            args.no_unicode_norm = no_unicode_norm;
        }
    }

    if let Some(no_ml) = config.no_ml {
        if !args.no_ml {
            args.no_ml = no_ml;
        }
    }

    if let Some(ml_weight) = config.ml_weight {
        if args.ml_weight.is_none() {
            args.ml_weight = Some(ml_weight);
        }
    }

    if let Some(ref limit_str) = config.max_file_size {
        if args.max_file_size.is_none() {
            if let Ok(size) = crate::value_parsers::parse_byte_size(limit_str) {
                args.max_file_size = Some(size);
            }
        }
    }

    if let Some(ref limit_str) = config.regex_dfa_limit {
        if args.regex_dfa_limit.is_none() {
            if let Ok(size) = crate::value_parsers::parse_byte_size(limit_str) {
                args.regex_dfa_limit = Some(size);
            }
        }
    }

    if let Some(paths) = config.exclude_paths {
        if args.exclude_paths.is_none() {
            args.exclude_paths = Some(paths);
        }
    }

    if let Some(prefixes) = config.known_prefixes {
        args.known_prefixes = prefixes;
    }
    if let Some(keywords) = config.secret_keywords {
        args.secret_keywords = keywords;
    }
    if let Some(keywords) = config.test_keywords {
        args.test_keywords = keywords;
    }
    if let Some(keywords) = config.placeholder_keywords {
        args.placeholder_keywords = keywords;
    }

    // `[scan]` nested table - the surface the README documents as canonical.
    // Mirrors the flat top-level scalars and fills only fields still at their
    // default (so the flat form wins if both are present, and a `[scan]`-only
    // config now actually takes effect instead of being silently dropped).
    if let Some(scan) = config.scan {
        if args.severity.is_none() {
            if let Some(ref s) = scan.severity {
                args.severity = parse_severity_filter(s);
            }
        }
        if args.min_confidence.is_none() {
            args.min_confidence = scan.min_confidence;
        }
        if matches!(args.format, crate::args::OutputFormat::Text) {
            if let Some(ref f) = scan.format {
                if let Some(fmt) = parse_output_format(f) {
                    args.format = fmt;
                }
            }
        }
        if args.exclude_paths.is_none() {
            args.exclude_paths = scan.exclude;
        }
        if args.threads.is_none() {
            args.threads = scan.threads;
        }
        if matches!(args.dedup, crate::args::CliDedupScope::Credential) {
            if let Some(ref d) = scan.dedup {
                if let Some(scope) = parse_dedup_scope(d) {
                    args.dedup = scope;
                }
            }
        }
    }

    // `[lockdown] require = true` -> the caller refuses to run unless
    // `--lockdown` was passed (README: "refuse to run without --lockdown").
    let require_lockdown = config
        .lockdown
        .as_ref()
        .and_then(|l| l.require)
        .unwrap_or(false);

    // `[detector.<id>]` table: `enabled = false` drops the detector from the
    // loaded corpus after `load_detectors`; `min_confidence = <f>` becomes a
    // per-detector confidence floor applied in scan post-processing. Both keys
    // were README-documented; the confidence floor used to be parsed and
    // silently ignored (the disabled toggle was wired earlier). Drain the map
    // once into both outputs.
    //
    // Start from the compiled Tier-A defaults (`shipped_config_outcome`) so the
    // shipped floors/disables apply even when the `.keyhog.toml` does not
    // mention that detector, then layer the file on top: a file
    // `min_confidence` overrides the compiled floor for that id, and file
    // disables union with the compiled disables.
    let baseline = shipped_config_outcome();
    let mut disabled_detectors = baseline.disabled_detectors;
    let mut detector_min_confidence = baseline.detector_min_confidence;
    if let Some(map) = config.detector {
        for (id, section) in map {
            if section.enabled == Some(false) && !disabled_detectors.contains(&id) {
                disabled_detectors.push(id.clone());
            }
            if let Some(conf) = section.min_confidence {
                detector_min_confidence.insert(id, conf);
            }
        }
    }

    ConfigOutcome {
        disabled_detectors,
        require_lockdown,
        detector_min_confidence,
    }
}
