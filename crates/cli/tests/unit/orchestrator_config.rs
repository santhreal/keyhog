use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

fn global_config_state_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("global config state lock")
}

fn args_for_config(contents: &str) -> ScanArgs {
    args_for_config_with_extra(contents, &[])
}

fn args_for_config_with_extra(contents: &str, extra_args: &[&str]) -> ScanArgs {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join(".keyhog.toml"), contents).expect("write config");
    let path = dir.path().to_string_lossy().to_string();
    let mut argv = vec!["scan".to_string(), "--path".to_string(), path];
    argv.extend(extra_args.iter().copied().map(String::from));
    let mut args = ScanArgs::try_parse_from(argv).unwrap();
    API.apply_config_file_quiet(&mut args);
    args
}

fn detector_toml(id: &str, prefix: &str) -> String {
    format!(
        r#"
        [detector]
        id = "{id}"
        name = "{id}"
        service = "demo"
        severity = "high"
        keywords = ["{prefix}"]

        [[detector.patterns]]
        regex = "{prefix}[A-Z0-9]{{8}}"
        "#
    )
}

#[test]
fn no_verify_build_policy_and_config_keys_are_not_dead_surfaces() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let policy =
        std::fs::read_to_string(root.join("src/orchestrator_config/policy.rs")).expect("policy.rs");
    let scan_args = std::fs::read_to_string(root.join("src/args/scan.rs")).expect("scan args");
    let config_scan =
        std::fs::read_to_string(root.join("src/config/scan.rs")).expect("config scan");
    let config = std::fs::read_to_string(root.join("src/config.rs")).expect("config.rs");
    let sections =
        std::fs::read_to_string(root.join("src/config/sections.rs")).expect("sections.rs");

    assert!(
        policy.contains("#[cfg(not(feature = \"verify\"))]")
            && policy.contains("pub(super) fn from_scan_args(_args: &ScanArgs) -> Self")
            && policy.contains("Self::disabled()")
            && policy.contains("fn scan_verify_enabled(_args: &ScanArgs) -> bool")
            && policy.contains("false"),
        "no-verify builds must resolve verifier policy explicitly disabled"
    );
    assert!(
        scan_args.contains("#[cfg(feature = \"verify\")]\n    #[arg(long)]\n    pub timeout")
            && scan_args.contains("#[cfg(feature = \"verify\")]\n    #[arg(long)]\n    pub rate"),
        "verifier-only CLI flags must not be accepted in no-verify builds"
    );
    for required in [
        "- verify: this key requires the `verify` feature",
        "- timeout: this key requires the `verify` feature",
        "- rate: this key requires the `verify` feature",
        "- max_commits: this key requires the `git` feature",
    ] {
        assert!(
            config_scan.contains(required),
            "verifier-only TOML key must fail loud in no-verify builds; missing {required:?}"
        );
    }
    assert!(
        config.contains("feature = \"verify\"") && sections.contains("feature = \"verify\""),
        "[http] proxy/TLS config gates must include verifier HTTP usage"
    );
}

#[test]
fn sanitise_thread_count_rejects_zero() {
    assert_eq!(API.sanitise_thread_count(0, 8, "test"), 8);
    assert_eq!(API.sanitise_thread_count(0, 0, "test"), 1);
}

#[test]
fn sanitise_thread_count_caps_pathological_values() {
    assert_eq!(
        API.sanitise_thread_count(999_999, 8, "test"),
        API.max_threads_cap()
    );
    assert_eq!(
        API.sanitise_thread_count(API.max_threads_cap() + 1, 8, "test"),
        API.max_threads_cap()
    );
}

#[test]
fn sanitise_thread_count_passes_through_sane_values() {
    assert_eq!(API.sanitise_thread_count(1, 8, "test"), 1);
    assert_eq!(API.sanitise_thread_count(8, 8, "test"), 8);
    assert_eq!(API.sanitise_thread_count(64, 8, "test"), 64);
    assert_eq!(
        API.sanitise_thread_count(API.max_threads_cap(), 8, "test"),
        API.max_threads_cap()
    );
}

#[test]
fn config_top_level_min_secret_len_reaches_scan_args() {
    let args = args_for_config("min_secret_len = 29\n");
    assert_eq!(args.min_secret_len, Some(29));
}

#[test]
fn config_scan_min_secret_len_reaches_scan_args() {
    let args = args_for_config("[scan]\nmin_secret_len = 33\n");
    assert_eq!(args.min_secret_len, Some(33));
}

#[test]
fn config_top_level_min_secret_len_wins_over_scan_table() {
    let args = args_for_config("min_secret_len = 29\n[scan]\nmin_secret_len = 33\n");
    assert_eq!(args.min_secret_len, Some(29));
}

#[test]
fn config_top_level_ml_threshold_and_verify_knobs_reach_scan_args() {
    let args = args_for_config(
        "ml_threshold = 0.5\n\
         timeout = 9\n\
         rate = 7\n\
         max_commits = 123\n",
    );
    assert_eq!(args.ml_threshold, Some(0.5));
    assert_eq!(args.timeout, Some(9));
    assert_eq!(args.rate, Some(7));
    #[cfg(feature = "git")]
    assert_eq!(args.max_commits, Some(123));
}

#[test]
fn config_scan_ml_threshold_reaches_scan_args() {
    let args = args_for_config("[scan]\nml_threshold = 0.6\n");
    assert_eq!(args.ml_threshold, Some(0.6));
}

#[test]
fn explicit_cli_default_values_win_over_config_sentinels() {
    let mut extra_args = vec!["--ml-threshold", "0.5", "--timeout", "5", "--rate", "5"];
    #[cfg(feature = "git")]
    extra_args.extend(["--max-commits", "1000"]);

    let args = args_for_config_with_extra(
        "ml_threshold = 0.9\n\
         timeout = 30\n\
         rate = 11\n\
         max_commits = 222\n",
        &extra_args,
    );

    assert_eq!(
        args.ml_threshold,
        Some(0.5),
        "explicit --ml-threshold 0.5 must not be overwritten by TOML"
    );
    assert_eq!(
        args.timeout,
        Some(5),
        "explicit --timeout 5 must not be overwritten by TOML"
    );
    assert_eq!(
        args.rate,
        Some(5),
        "explicit --rate 5 must not be overwritten by TOML"
    );
    #[cfg(feature = "git")]
    assert_eq!(
        args.max_commits,
        Some(1000),
        "explicit --max-commits 1000 must not be overwritten by TOML"
    );
}

#[test]
fn config_top_level_generic_keyword_low_entropy_false_reaches_scan_args() {
    let args = args_for_config("generic_keyword_low_entropy = false\n");
    assert!(
        args.no_keyword_low_entropy,
        "documented TOML generic_keyword_low_entropy=false must reach the same scanner path as --no-keyword-low-entropy"
    );
}

#[test]
fn config_limit_stdin_bytes_reaches_source_limits() {
    let args = args_for_config("[limits]\nstdin_bytes = \"1MB\"\n");
    assert_eq!(args.limits.to_source_limits().stdin_bytes, 1024 * 1024);
}

#[test]
fn cli_limit_stdin_bytes_wins_over_config_limit() {
    let args = args_for_config_with_extra(
        "[limits]\nstdin_bytes = \"1MB\"\n",
        &["--limit-stdin-bytes", "3MB"],
    );
    assert_eq!(args.limits.to_source_limits().stdin_bytes, 3 * 1024 * 1024);
}

#[test]
fn system_trusted_bin_dirs_reach_safe_bin_resolver() {
    let _guard = global_config_state_lock();
    let dir = TempDir::new().expect("tempdir");
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("mkdir bin");
    let bin_name = "keyhog-config-wired-bin";
    let bin = bin_dir.join(bin_name);
    std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").expect("write fake binary");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        format!(
            "[system]\ntrusted_bin_dirs = [{}]\n",
            toml::Value::String(bin_dir.to_string_lossy().to_string())
        ),
    )
    .expect("write config");

    let path = dir.path().to_string_lossy().to_string();
    let mut args = ScanArgs::try_parse_from(["scan", "--path", &path]).expect("parse scan args");
    API.resolve_scan_config(&mut args)
        .expect("resolve scan config");
    let resolved = keyhog_core::resolve_safe_bin(bin_name);
    keyhog_core::set_extra_trusted_dirs(Vec::new());

    assert_eq!(
        resolved.as_deref(),
        Some(bin.as_path()),
        "[system].trusted_bin_dirs must reach the safe binary resolver used by git/docker sources"
    );
}

#[test]
fn system_cache_dir_reaches_scan_args() {
    let dir = TempDir::new().expect("tempdir");
    let cache_dir = dir.path().join("hs-cache");
    let args = args_for_config(&format!(
        "[system]\ncache_dir = {}\n",
        toml::Value::String(cache_dir.to_string_lossy().to_string())
    ));

    assert_eq!(
        args.cache_dir.as_deref(),
        Some(cache_dir.as_path()),
        "[system].cache_dir must reach the scan args consumed before scanner compilation"
    );
}

#[test]
fn cli_cache_dir_wins_over_system_cache_dir() {
    let dir = TempDir::new().expect("tempdir");
    let config_cache = dir.path().join("config-cache");
    let cli_cache = dir.path().join("cli-cache");
    let cli_cache_arg = cli_cache.to_string_lossy().to_string();
    let args = args_for_config_with_extra(
        &format!(
            "[system]\ncache_dir = {}\n",
            toml::Value::String(config_cache.to_string_lossy().to_string())
        ),
        &["--cache-dir", &cli_cache_arg],
    );

    assert_eq!(
        args.cache_dir.as_deref(),
        Some(cli_cache.as_path()),
        "--cache-dir must override [system].cache_dir"
    );
}

#[test]
fn system_calibration_cache_reaches_scan_args() {
    let dir = TempDir::new().expect("tempdir");
    let cache_path = dir.path().join("calibration.json");
    let args = args_for_config(&format!(
        "[system]\ncalibration_cache = {}\n",
        toml::Value::String(cache_path.to_string_lossy().to_string())
    ));

    assert_eq!(
        args.calibration_cache.as_deref(),
        Some(cache_path.as_path()),
        "[system].calibration_cache must reach the scan args consumed before scanner compilation"
    );
}

#[test]
fn cli_calibration_cache_wins_over_system_calibration_cache() {
    let dir = TempDir::new().expect("tempdir");
    let config_cache = dir.path().join("config-calibration.json");
    let cli_cache = dir.path().join("cli-calibration.json");
    let cli_cache_arg = cli_cache.to_string_lossy().to_string();
    let args = args_for_config_with_extra(
        &format!(
            "[system]\ncalibration_cache = {}\n",
            toml::Value::String(config_cache.to_string_lossy().to_string())
        ),
        &["--calibration-cache", &cli_cache_arg],
    );

    assert_eq!(
        args.calibration_cache.as_deref(),
        Some(cli_cache.as_path()),
        "--calibration-cache must override [system].calibration_cache"
    );
}

#[cfg(any(
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "s3",
    feature = "gcs",
    feature = "azure"
))]
#[test]
fn http_proxy_and_insecure_tls_reach_scan_args() {
    let args = args_for_config(
        "[http]\n\
         proxy = \"http://127.0.0.1:8080\"\n\
         insecure_tls = true\n",
    );

    assert_eq!(
        args.proxy.as_deref(),
        Some("http://127.0.0.1:8080"),
        "[http].proxy must reach the outbound HTTP policy fields consumed by sources and verifier"
    );
    assert!(
        args.insecure,
        "[http].insecure_tls must reach the outbound HTTP policy fields consumed by sources and verifier"
    );
}

#[cfg(any(
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "s3",
    feature = "gcs",
    feature = "azure"
))]
#[test]
fn cli_http_flags_win_over_http_toml() {
    let args = args_for_config_with_extra(
        "[http]\n\
         proxy = \"http://127.0.0.1:8080\"\n\
         insecure_tls = false\n",
        &["--proxy", "off", "--insecure"],
    );

    assert_eq!(
        args.proxy.as_deref(),
        Some("off"),
        "--proxy must override [http].proxy"
    );
    assert!(args.insecure, "--insecure must remain enabled over TOML");
}

#[test]
fn relative_system_trusted_bin_dir_is_config_error() {
    let _guard = global_config_state_lock();
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[system]\ntrusted_bin_dirs = [\"relative-bin\"]\n",
    )
    .expect("write config");

    let path = dir.path().to_string_lossy().to_string();
    let mut args = ScanArgs::try_parse_from(["scan", "--path", &path]).expect("parse scan args");
    let error = API
        .resolve_scan_config(&mut args)
        .expect_err("relative trusted bin dir must fail");

    assert!(
        error
            .to_string()
            .contains("[system].trusted_bin_dirs: trusted binary directory relative-bin must be absolute"),
        "relative trusted binary directories must fail closed with an actionable config error: {error}"
    );
}

#[test]
fn relative_system_cache_dir_is_config_error() {
    let _guard = global_config_state_lock();
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[system]\ncache_dir = \"relative-cache\"\n",
    )
    .expect("write config");

    let path = dir.path().to_string_lossy().to_string();
    let mut args = ScanArgs::try_parse_from(["scan", "--path", &path]).expect("parse scan args");
    let error = API
        .resolve_scan_config(&mut args)
        .expect_err("relative cache dir must fail");

    assert!(
        error.to_string().contains(
            "[system].cache_dir: Hyperscan cache directory relative-cache must be absolute"
        ),
        "relative cache dirs must fail closed with an actionable config error: {error}"
    );
}

#[test]
fn relative_system_calibration_cache_is_config_error() {
    let _guard = global_config_state_lock();
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[system]\ncalibration_cache = \"relative-calibration.json\"\n",
    )
    .expect("write config");

    let path = dir.path().to_string_lossy().to_string();
    let mut args = ScanArgs::try_parse_from(["scan", "--path", &path]).expect("parse scan args");
    let error = API
        .resolve_scan_config(&mut args)
        .expect_err("relative calibration cache must fail");

    assert!(
        error.to_string().contains(
            "[system].calibration_cache: calibration cache path relative-calibration.json must be absolute"
        ),
        "relative calibration cache paths must fail closed with an actionable config error: {error}"
    );
}

#[test]
fn aws_canary_accounts_reach_resolved_scan_config() {
    let _guard = global_config_state_lock();
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[aws]\ncanary_accounts = [\"000000000001\"]\n",
    )
    .expect("write config");

    let path = dir.path().to_string_lossy().to_string();
    let mut args = ScanArgs::try_parse_from(["scan", "--path", &path]).expect("parse scan args");
    let accounts = API
        .resolve_scan_config_aws_canary_accounts(&mut args)
        .expect("resolve scan config");

    assert_eq!(
        accounts,
        vec!["000000000001".to_string()],
        "[aws].canary_accounts must be carried by the resolved scan config"
    );
    keyhog_core::set_extra_canary_accounts(Default::default());
}

#[test]
fn invalid_aws_canary_accounts_are_config_errors() {
    let _guard = global_config_state_lock();
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join(".keyhog.toml"),
        "[aws]\ncanary_accounts = [\"1234\"]\nknockoff_accounts = [\"\"]\n",
    )
    .expect("write config");

    let path = dir.path().to_string_lossy().to_string();
    let mut args = ScanArgs::try_parse_from(["scan", "--path", &path]).expect("parse scan args");
    let error = API
        .resolve_scan_config(&mut args)
        .expect_err("invalid AWS accounts must fail");
    let message = error.to_string();

    assert!(
        message.contains("[aws].canary_accounts")
            && message.contains("12-digit AWS account id")
            && message.contains("[aws].knockoff_accounts")
            && message.contains("must not be empty"),
        "invalid AWS account IDs must fail closed with actionable config errors: {message}"
    );
    keyhog_core::set_extra_canary_accounts(Default::default());
}

#[cfg(all(feature = "web", feature = "git"))]
#[test]
fn config_feature_limits_reach_source_limits() {
    let args = args_for_config(
        "[limits]\n\
         web_response_bytes = \"2MB\"\n\
         git_chunks = 17\n",
    );
    let limits = args.limits.to_source_limits();

    assert_eq!(limits.web_response_bytes, 2 * 1024 * 1024);
    assert_eq!(limits.git_chunk_count, 17);
}

#[cfg(all(
    any(feature = "s3", feature = "gcs", feature = "azure"),
    any(feature = "github", feature = "gitlab", feature = "bitbucket")
))]
#[test]
fn config_count_limits_reach_source_limits() {
    let args = args_for_config(
        "[limits]\n\
         cloud_max_objects = 23\n\
         hosted_git_pages = 31\n",
    );
    let limits = args.limits.to_source_limits();

    assert_eq!(limits.cloud_max_objects, 23);
    assert_eq!(limits.hosted_git_pages, 31);
}

#[test]
fn detector_parse_cache_has_single_cli_owner() {
    let cli_src = include_str!("../../src/orchestrator_config/detectors.rs");
    let parent_src = include_str!("../../src/orchestrator_config.rs");
    let core_src = include_str!("../../../core/src/spec/load.rs");
    assert!(
        cli_src.contains("struct DetectorCacheFile") && cli_src.contains("source_fingerprint"),
        "CLI detector loading owns the XDG parse-cache schema and source fingerprint"
    );
    assert!(
        parent_src.contains("mod detectors;")
            && parent_src.contains("pub(crate) use detectors::{"),
        "orchestrator_config parent must expose the detector owner without keeping the cache implementation"
    );
    assert!(
        !parent_src.contains("struct DetectorCacheFile")
            && !parent_src.contains("save_detector_cache")
            && !parent_src.contains("load_detector_cache"),
        "orchestrator_config parent must not keep a second detector parse-cache schema/parser"
    );
    assert!(
        !cli_src.contains("keyhog_core::load_detectors_with_cache("),
        "detector owner must not call a second core detector-cache owner"
    );
    assert!(
        !core_src.contains("DetectorCacheFile")
            && !core_src.contains("save_detector_cache")
            && !core_src.contains("load_detector_cache"),
        "keyhog-core must not keep a second detector parse-cache schema/parser"
    );
}

#[test]
fn detector_parse_cache_invalidates_deleted_source_toml() {
    let dir = TempDir::new().expect("tempdir");
    let source_dir = dir.path().join("detectors");
    std::fs::create_dir_all(&source_dir).expect("mkdir detectors");
    std::fs::write(
        source_dir.join("alpha.toml"),
        detector_toml("alpha-token", "alpha_"),
    )
    .expect("write alpha");
    std::fs::write(
        source_dir.join("bravo.toml"),
        detector_toml("bravo-token", "bravo_"),
    )
    .expect("write bravo");
    let cache_path = dir.path().join("detectors-cache.json");

    let first = API
        .load_detectors_from_dir_with_cache(&source_dir, &cache_path)
        .expect("first load");
    assert_eq!(first.len(), 2);
    assert!(cache_path.exists(), "first cached load should write cache");

    std::fs::remove_file(source_dir.join("bravo.toml")).expect("delete bravo");
    let second = API
        .load_detectors_from_dir_with_cache(&source_dir, &cache_path)
        .expect("second load");
    assert_eq!(
        second.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(),
        vec!["alpha-token"],
        "deleted detector TOML must invalidate the cache instead of keeping stale detectors live"
    );
}

#[test]
fn detector_parse_cache_rejects_poisoned_cached_detector() {
    let dir = TempDir::new().expect("tempdir");
    let source_dir = dir.path().join("detectors");
    std::fs::create_dir_all(&source_dir).expect("mkdir detectors");
    std::fs::write(
        source_dir.join("alpha.toml"),
        detector_toml("alpha-token", "alpha_"),
    )
    .expect("write alpha");
    let cache_path = dir.path().join("detectors-cache.json");

    let first = API
        .load_detectors_from_dir_with_cache(&source_dir, &cache_path)
        .expect("first load");
    assert_eq!(first.len(), 1);

    let mut poisoned: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).expect("read cache"))
            .expect("cache JSON");
    poisoned["detectors"][0]["patterns"][0]["regex"] = serde_json::json!("(");
    std::fs::write(
        &cache_path,
        serde_json::to_vec_pretty(&poisoned).expect("serialize poisoned cache"),
    )
    .expect("write poisoned cache");

    let second = API
        .load_detectors_from_dir_with_cache(&source_dir, &cache_path)
        .expect("second load");
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].id, "alpha-token");
    assert_eq!(
        second[0].patterns[0].regex, "alpha_[A-Z0-9]{8}",
        "invalid cached detector must be rejected and replaced by source TOML"
    );
}

#[test]
fn detector_parse_cache_refuses_oversized_cache_file() {
    let dir = TempDir::new().expect("tempdir");
    let source_dir = dir.path().join("detectors");
    std::fs::create_dir_all(&source_dir).expect("mkdir detectors");
    std::fs::write(
        source_dir.join("alpha.toml"),
        detector_toml("alpha-token", "alpha_"),
    )
    .expect("write alpha");
    let cache_path = dir.path().join("detectors-cache.json");
    let cache = std::fs::File::create(&cache_path).expect("create oversized cache");
    cache
        .set_len(70 * 1024 * 1024)
        .expect("make oversized sparse cache");

    let loaded = API
        .load_detectors_from_dir_with_cache(&source_dir, &cache_path)
        .expect("oversized cache should be discarded and rebuilt from source TOML");

    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].id, "alpha-token");
    assert!(
        std::fs::metadata(&cache_path)
            .expect("rebuilt cache metadata")
            .len()
            < 1024 * 1024,
        "oversized parse cache must be replaced by a normal cache artifact"
    );
}

#[test]
fn detector_parse_cache_reads_are_bounded() {
    let cli_src = include_str!("../../src/orchestrator_config/detectors.rs");
    assert!(
        cli_src.contains("const DETECTOR_CACHE_FILE_BYTES")
            && cli_src.contains("fn read_detector_cache_file(")
            && cli_src.contains(".take(DETECTOR_CACHE_FILE_BYTES.saturating_add(1))"),
        "detector parse cache reads must go through the capped cache reader"
    );
    assert!(
        !cli_src.contains("std::fs::read(cache_path)")
            && !cli_src.contains("std::fs::read(&cache_path)"),
        "detector parse cache must not use unbounded std::fs::read"
    );
    assert!(
        cli_src.contains("keyhog_core::read_detector_toml_file(&path)"),
        "detector source fingerprinting must share the bounded core detector TOML reader"
    );
}
