//! LANE: `keyhog config` init/print surface, driven over the SHIPPED binary
//! (`CARGO_BIN_EXE_keyhog`), never the library, so every assertion pins the
//! exact operator-visible contract a packager / CI author hits.
//!
//! REALITY OF THE SURFACE (read the code, do not guess): keyhog's config
//! surface is `keyhog config --effective`, which PRINTS the fully-resolved scan
//! configuration (`crate::orchestrator_config::render_effective_config`) to
//! stdout and exits WITHOUT scanning. There is NO `--print-config` alias and NO
//! subcommand that WRITES a config file to disk. `ConfigArgs` only has the
//! `required = true` `--effective` bool plus a flattened `ScanArgs` (see
//! `crates/cli/src/args/config.rs` and `crates/cli/src/subcommands/config.rs`).
//! These tests therefore pin the PRINT contract, its exact default key/value
//! lines, and the user-error exit codes for the two ways to misdrive it.
//!
//! EMITTED FORMAT (NOT round-trippable TOML): a `[effective-config]` header
//! line followed by deterministic `key = value` lines. Values include bare
//! words (`auto`), sentinels (`<platform default>`), and annotated defaults
//! (`104857600 (default)`), so the block is greppable/diffable but is NOT a
//! valid TOML document (no test here claims it parses as TOML).
//!
//! HOST-INDEPENDENCE: `config --effective` resolves config only; it never
//! probes an accelerator. With no `--require-gpu`, the default GPU policy is
//! `auto` and `backend = auto`, so every asserted line is identical on a GPU
//! box and a GPU-less CI runner. Nothing asserts a SIMD/GPU/Hyperscan backend
//! is present, and the hermetic (`--no-config`) runs assert compiled defaults.
//!
//! Exit codes (per `crate::exit_codes`): 0 = success, 2 = user error (clap
//! parse failure / missing required flag / unknown flag or subcommand).

use std::process::Command;

fn binary() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run the shipped binary and return (exit code, stdout, stderr).
fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(binary())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("spawn `keyhog {}`: {e}", args.join(" ")));
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The compiled-in default max-file-size (`keyhog_core::DEFAULT_MAX_FILE_SIZE_BYTES`
/// = 100 MiB). `--effective` reports an unset cap as `<bytes> (default)`: never
/// "off" (so operators cannot mistake the fall-back cap for "no cap").
const DEFAULT_MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 104_857_600

/// The compiled-in default per-regex DFA size limit
/// (`keyhog_scanner::regex_dfa_limit_default()` = `1 << 20` = 1 MiB).
const DEFAULT_REGEX_DFA_LIMIT: usize = 1 << 20; // 1_048_576

// ---------------------------------------------------------------------------
// 1. Print contract: header + exit 0, no scan performed
// ---------------------------------------------------------------------------

#[test]
fn config_effective_exits_zero_and_leads_with_header() {
    let (code, stdout, stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(
        code,
        Some(0),
        "`keyhog config --effective` renders and exits 0 (never scans); stderr={stderr}"
    );
    // The block LEADS with its exact header line (first bytes, not merely present).
    assert!(
        stdout.starts_with("[effective-config]\n"),
        "effective dump must lead with the `[effective-config]` header line; got:\n{stdout}"
    );
    // First key line immediately follows the header.
    assert!(
        stdout.starts_with("[effective-config]\nbackend = "),
        "the first key line after the header must be `backend = ...`; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 2. Exact default values (hermetic `--no-config`, host-independent)
// ---------------------------------------------------------------------------

#[test]
fn config_effective_default_backend_is_auto() {
    let (code, stdout, _stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(code, Some(0), "config --effective must exit 0");
    // `backend_override_label(None)` == "auto": no operator override, no probe.
    assert!(
        stdout.contains("\nbackend = auto\n")
            || stdout.starts_with("[effective-config]\nbackend = auto\n"),
        "hermetic default backend must render `backend = auto`; got:\n{stdout}"
    );
}

#[test]
fn config_effective_default_gpu_policy_is_auto_not_required() {
    // HOST-INDEPENDENCE: with no `--require-gpu`/`--no-gpu`, the resolved GPU
    // runtime policy is `Auto` (Display == "auto"). This line is identical on a
    // GPU host and a GPU-less runner; it must NEVER silently become "required".
    let (code, stdout, _stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(code, Some(0), "config --effective must exit 0");
    assert!(
        stdout.contains("\ngpu = auto\n"),
        "default GPU runtime policy must render `gpu = auto`; got:\n{stdout}"
    );
    assert!(
        !stdout.contains("\ngpu = required\n"),
        "no accelerator was requested, so `gpu` must not be `required`; got:\n{stdout}"
    );
}

#[test]
fn config_effective_default_max_file_size_reports_annotated_compiled_default() {
    let (code, stdout, _stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(code, Some(0), "config --effective must exit 0");
    let expected = format!("\nmax_file_size = {DEFAULT_MAX_FILE_SIZE} (default)\n");
    assert!(
        stdout.contains(&expected),
        "unset max_file_size must report the compiled 100 MiB cap as `{DEFAULT_MAX_FILE_SIZE} (default)`, never `off`; got:\n{stdout}"
    );
    // Adversarial: the annotated-default form must not degrade to a bare "off".
    assert!(
        !stdout.contains("\nmax_file_size = off\n"),
        "an unset file-size cap is never `off` (a cap is in force); got:\n{stdout}"
    );
}

#[test]
fn config_effective_default_regex_dfa_limit_reports_annotated_compiled_default() {
    let (code, stdout, _stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(code, Some(0), "config --effective must exit 0");
    let expected = format!("\nregex_dfa_limit = {DEFAULT_REGEX_DFA_LIMIT} (default)\n");
    assert!(
        stdout.contains(&expected),
        "unset regex_dfa_limit must report the compiled 1 MiB cap as `{DEFAULT_REGEX_DFA_LIMIT} (default)`; got:\n{stdout}"
    );
}

#[test]
fn config_effective_default_threads_render_auto() {
    // `resolved.threads == None` renders "auto" (map_or_else), NOT "0" / a probed
    // core count (so the dump stays host-independent).
    let (code, stdout, _stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(code, Some(0), "config --effective must exit 0");
    assert!(
        stdout.contains("\nthreads = auto\n"),
        "unset --threads must render `threads = auto`; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 3. Key completeness: the documented default keys are all present
// ---------------------------------------------------------------------------

#[test]
fn config_effective_emits_all_core_default_keys() {
    let (code, stdout, stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    // Every key here is emitted UNCONDITIONALLY by render_effective_config (none
    // are feature-gated: `max_commits` is git-gated and deliberately omitted).
    // Each must appear as a newline-prefixed `key = ` line.
    let required_keys = [
        "backend",
        "batch_pipeline",
        "threads",
        "reader_threads",
        "fused_batch",
        "gpu",
        "autoroute_gpu",
        "profile",
        "perf_trace",
        "min_confidence",
        "ml_enabled",
        "ml_weight",
        "entropy_enabled",
        "entropy_threshold",
        "max_decode_depth",
        "max_decode_bytes",
        "validate_decode",
        "regex_dfa_limit",
        "gpu_batch_input_limit",
        "max_file_size",
        "no_default_excludes",
        "exclude_paths",
        "incremental",
        "scan_comments",
        "unicode_normalization",
        "disabled_detectors",
        "allowlist_file",
        "known_prefixes",
        "secret_keywords",
        "test_keywords",
        "placeholder_keywords",
        "min_secret_len",
    ];
    for key in required_keys {
        let needle = format!("\n{key} = ");
        assert!(
            stdout.contains(&needle),
            "effective-config dump is missing the `{key} = ` line; got:\n{stdout}"
        );
    }
}

#[test]
fn config_effective_default_exclude_and_disabled_counts_are_zero() {
    // Hermetic defaults ship with no excludes and no disabled detectors, so the
    // count-valued lines must be exactly 0 (proves the counters, not just keys).
    let (code, stdout, _stderr) = run(&["config", "--effective", "--no-config", "--daemon=off"]);
    assert_eq!(code, Some(0), "config --effective must exit 0");
    assert!(
        stdout.contains("\nexclude_paths = 0\n"),
        "hermetic default must report `exclude_paths = 0`; got:\n{stdout}"
    );
    assert!(
        stdout.contains("\ndisabled_detectors = 0\n"),
        "hermetic default must report `disabled_detectors = 0`; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 4. Override truth: config-affecting flags reach the printed resolution
// ---------------------------------------------------------------------------

#[test]
fn config_effective_min_confidence_override_reaches_output() {
    // No `--precision` / `--ml-threshold`, so the resolved floor equals the raw
    // override EXACTLY (scanner.rs: `config.min_confidence = conf`).
    let (code, stdout, stderr) = run(&[
        "config",
        "--effective",
        "--no-config",
        "--daemon=off",
        "--min-confidence",
        "0.95",
    ]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    assert!(
        stdout.contains("\nmin_confidence = 0.95\n"),
        "the --min-confidence 0.95 override must reach the resolved config verbatim; got:\n{stdout}"
    );
}

#[test]
fn config_effective_decode_depth_override_reaches_output() {
    let (code, stdout, stderr) = run(&[
        "config",
        "--effective",
        "--no-config",
        "--daemon=off",
        "--decode-depth",
        "7",
    ]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    // `--decode-depth 7` maps straight to `max_decode_depth = 7`.
    assert!(
        stdout.contains("\nmax_decode_depth = 7\n"),
        "the --decode-depth 7 override must reach max_decode_depth; got:\n{stdout}"
    );
}

#[test]
fn config_effective_threads_override_reaches_output() {
    let (code, stdout, stderr) = run(&[
        "config",
        "--effective",
        "--no-config",
        "--daemon=off",
        "--threads",
        "3",
    ]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    assert!(
        stdout.contains("\nthreads = 3\n"),
        "the --threads 3 override must reach the resolved threads; got:\n{stdout}"
    );
}

#[test]
fn config_effective_min_secret_len_override_reaches_output() {
    let (code, stdout, stderr) = run(&[
        "config",
        "--effective",
        "--no-config",
        "--daemon=off",
        "--min-secret-len",
        "24",
    ]);
    assert_eq!(
        code,
        Some(0),
        "config --effective must exit 0; stderr={stderr}"
    );
    assert!(
        stdout.contains("\nmin_secret_len = 24\n"),
        "the --min-secret-len 24 override must reach the resolved dump; got:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// 5. Determinism: two identical invocations produce byte-identical dumps
// ---------------------------------------------------------------------------

#[test]
fn config_effective_is_deterministic_across_two_runs() {
    let args = &["config", "--effective", "--no-config", "--daemon=off"];
    let (code_a, stdout_a, _e_a) = run(args);
    let (code_b, stdout_b, _e_b) = run(args);
    assert_eq!(code_a, Some(0), "first config --effective run must exit 0");
    assert_eq!(code_b, Some(0), "second config --effective run must exit 0");
    assert_eq!(
        stdout_a, stdout_b,
        "config --effective must be deterministic: identical args must yield byte-identical dumps"
    );
    assert!(
        stdout_a.starts_with("[effective-config]\n"),
        "the deterministic dump must still carry its header; got:\n{stdout_a}"
    );
}

// ---------------------------------------------------------------------------
// 6. User-error exits (the two ways to misdrive the surface)
// ---------------------------------------------------------------------------

#[test]
fn config_without_effective_exits_two_naming_the_flag() {
    // `--effective` is `required = true`: clap rejects the invocation at parse
    // time with the user-error code 2 and names the missing flag.
    let (code, _stdout, stderr) = run(&["config"]);
    assert_eq!(
        code,
        Some(2),
        "`keyhog config` without --effective is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("--effective"),
        "the parse error must name the missing --effective flag; got:\n{stderr}"
    );
}

#[test]
fn config_effective_with_unknown_flag_exits_two() {
    // An unrecognized flag under the `config` subcommand is a clap parse error
    // → exit 2. `--effective` is present, so this isolates the unknown-flag path.
    let (code, _stdout, stderr) = run(&["config", "--effective", "--definitely-not-a-real-flag"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown flag under `config` must exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("--definitely-not-a-real-flag")
            || stderr.contains("unexpected argument"),
        "the parse error must name the unknown flag / report an unexpected argument; got:\n{stderr}"
    );
}

#[test]
fn unknown_top_level_subcommand_exits_two() {
    // The closest analog to an "unknown config subcommand": an unrecognized
    // top-level subcommand is a clap parse error → exit 2. keyhog has no
    // sub-subcommands under `config`, so this pins the unknown-subcommand path.
    let (code, _stdout, stderr) = run(&["definitely-not-a-subcommand"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown subcommand must exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("definitely-not-a-subcommand")
            || stderr.contains("unrecognized subcommand")
            || stderr.contains("unexpected argument"),
        "the parse error must name the unknown subcommand; got:\n{stderr}"
    );
}
