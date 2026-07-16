use super::schema::{AllowlistSection, AwsSection, HttpSection, SystemSection, TuningSection};
use crate::args::ScanArgs;
use std::path::{Path, PathBuf};

fn collect_trusted_bin_dirs(
    config_errors: &mut Vec<String>,
    trusted_bin_dirs: &mut Vec<PathBuf>,
    field: &str,
    dirs: Option<&[PathBuf]>,
) {
    if let Some(dirs) = dirs {
        for dir in dirs {
            if dir.is_absolute() {
                trusted_bin_dirs.push(dir.clone());
            } else {
                config_errors.push(format!(
                    "- {field}: trusted binary directory {} must be absolute",
                    dir.display()
                ));
            }
        }
    }
}

pub(super) fn config_relative_path(config_path: &Path, configured: &str) -> PathBuf {
    let path = PathBuf::from(configured);
    if path.is_absolute() {
        return path;
    }
    match config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) => parent.join(path),
        None => path,
    }
}

fn parse_gpu_runtime_policy(raw: &str) -> Option<keyhog_scanner::gpu::GpuRuntimePolicy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(keyhog_scanner::gpu::GpuRuntimePolicy::Auto),
        "off" | "disabled" | "disable" | "false" => {
            Some(keyhog_scanner::gpu::GpuRuntimePolicy::Disabled)
        }
        "required" | "require" | "on" | "true" => {
            Some(keyhog_scanner::gpu::GpuRuntimePolicy::Required)
        }
        _ => None,
    }
}

pub(super) fn apply_system_section(
    args: &mut ScanArgs,
    config_errors: &mut Vec<String>,
    trusted_bin_dirs: &mut Vec<PathBuf>,
    system: Option<&SystemSection>,
) {
    collect_trusted_bin_dirs(
        config_errors,
        trusted_bin_dirs,
        "[system].trusted_bin_dirs",
        system.and_then(|section| section.trusted_bin_dirs.as_deref()),
    );
    if let Some(cache_dir) = system.and_then(|section| section.cache_dir.as_ref()) {
        if cache_dir.is_absolute() {
            if args.cache_dir.is_none() {
                args.cache_dir = Some(cache_dir.clone());
            }
        } else {
            config_errors.push(format!(
                "- [system].cache_dir: Hyperscan cache directory {} must be absolute",
                cache_dir.display()
            ));
        }
    }
    if let Some(autoroute_cache) = system.and_then(|section| section.autoroute_cache.as_ref()) {
        if args.autoroute_cache.is_none() {
            args.autoroute_cache = Some(autoroute_cache.clone());
        }
    }
    if let Some(calibration_cache) = system.and_then(|section| section.calibration_cache.as_ref()) {
        if calibration_cache.is_absolute() {
            if args.calibration_cache.is_none() {
                args.calibration_cache = Some(calibration_cache.clone());
            }
        } else {
            config_errors.push(format!(
                "- [system].calibration_cache: calibration cache path {} must be absolute",
                calibration_cache.display()
            ));
        }
    }
    if let Some(batch_pipeline) = system.and_then(|section| section.batch_pipeline) {
        if !args.batch_pipeline && !args.no_batch_pipeline {
            args.batch_pipeline = batch_pipeline;
        }
    }
    if let Some(gpu_policy) = system.and_then(|section| section.gpu.as_deref()) {
        match parse_gpu_runtime_policy(gpu_policy) {
            Some(policy) if args.backend.is_none() => match policy {
                keyhog_scanner::gpu::GpuRuntimePolicy::Disabled => {
                    if !args.no_gpu && !args.require_gpu {
                        args.no_gpu = true;
                    }
                }
                keyhog_scanner::gpu::GpuRuntimePolicy::Required => {
                    if !args.no_gpu && !args.require_gpu {
                        args.require_gpu = true;
                    }
                }
                keyhog_scanner::gpu::GpuRuntimePolicy::Auto => {}
            },
            Some(_) => {}
            None => config_errors.push(super::invalid_config_value(
                "[system].gpu",
                gpu_policy,
                "expected auto, off, or required",
            )),
        }
    }
    if let Some(autoroute_gpu) = system.and_then(|section| section.autoroute_gpu) {
        if !args.autoroute_gpu && !args.no_autoroute_gpu {
            args.autoroute_gpu = autoroute_gpu;
        }
    }
}

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
pub(super) fn apply_http_section(args: &mut ScanArgs, http: Option<&HttpSection>) {
    if let Some(http) = http {
        if args.proxy.is_none() {
            args.proxy = http.proxy.clone();
        }
        if let Some(insecure_tls) = http.insecure_tls {
            if !args.insecure {
                args.insecure = insecure_tls;
            }
        }
        if let Some(allow_private_endpoint) = http.allow_private_endpoint {
            if !args.allow_private_cloud_endpoint {
                args.allow_private_cloud_endpoint = allow_private_endpoint;
            }
        }
    }
}

#[cfg(not(any(
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket",
    feature = "s3",
    feature = "gcs",
    feature = "azure",
    feature = "verify"
)))]
pub(super) fn apply_http_section(
    _args: &mut ScanArgs,
    config_errors: &mut Vec<String>,
    http: Option<&HttpSection>,
) {
    if let Some(http) = http {
        if http.proxy.is_some() {
            config_errors
                .push("- [http].proxy: this key requires an HTTP-capable keyhog build".to_string());
        }
        if http.insecure_tls.is_some() {
            config_errors.push(
                "- [http].insecure_tls: this key requires an HTTP-capable keyhog build".to_string(),
            );
        }
        if http.allow_private_endpoint.is_some() {
            config_errors.push(
                "- [http].allow_private_endpoint: this key requires an HTTP-capable keyhog build"
                    .to_string(),
            );
        }
    }
}

pub(super) fn apply_aws_section(
    config_errors: &mut Vec<String>,
    aws_canary_accounts: &mut Vec<String>,
    aws: Option<&AwsSection>,
) {
    if let Some(aws) = aws {
        if let Some(accounts) = aws.canary_accounts.as_ref() {
            match keyhog_core::parse_canary_account_ids(accounts.iter().map(String::as_str)) {
                Ok(parsed) => aws_canary_accounts.extend(parsed),
                Err(error) => config_errors.push(format!("- [aws].canary_accounts: {error}")),
            }
        }
        if let Some(accounts) = aws.knockoff_accounts.as_ref() {
            match keyhog_core::parse_canary_account_ids(accounts.iter().map(String::as_str)) {
                Ok(parsed) => aws_canary_accounts.extend(parsed),
                Err(error) => config_errors.push(format!("- [aws].knockoff_accounts: {error}")),
            }
        }
    }
}

pub(super) fn apply_allowlist_section(
    config_errors: &mut Vec<String>,
    config_path: &Path,
    allowlist_file: &mut Option<PathBuf>,
    allowlist_require_reason: &mut bool,
    allowlist_require_approved_by: &mut bool,
    allowlist_max_expires_days: &mut Option<u64>,
    allowlist: Option<&AllowlistSection>,
) {
    if let Some(allowlist) = allowlist {
        if let Some(require_reason) = allowlist.require_reason {
            *allowlist_require_reason = require_reason;
        }
        if let Some(require_approved_by) = allowlist.require_approved_by {
            *allowlist_require_approved_by = require_approved_by;
        }
        *allowlist_max_expires_days = allowlist.max_expires_days;
        if let Some(file) = allowlist.file.as_deref() {
            let file = file.trim();
            if file.is_empty() {
                config_errors.push("- [allowlist].file: path must not be empty".to_string());
            } else {
                *allowlist_file = Some(config_relative_path(config_path, file));
            }
        }
    }
}

pub(super) fn apply_tuning_section(
    config_errors: &mut Vec<String>,
    scanner_tuning: &mut keyhog_scanner::ScannerTuningConfig,
    tuning: Option<&TuningSection>,
) {
    if let Some(tuning) = tuning {
        scanner_tuning.phase2_hs = tuning.fallback_hs;
        scanner_tuning.hs_prefilter_max_len = tuning.hs_prefilter_max_len;
        if let Some(shard_target) = tuning.hs_shard_target {
            if shard_target == 0 {
                config_errors
                    .push("- [tuning].hs_shard_target: expected an integer >= 1".to_string());
            } else {
                scanner_tuning.hs_shard_target = Some(shard_target);
            }
        }
        scanner_tuning.phase2_anchor = tuning.fallback_anchor;
        scanner_tuning.homoglyph_gate = tuning.homoglyph_gate;
        scanner_tuning.homoglyph_ascii_skip = tuning.homoglyph_ascii_skip;
        scanner_tuning.fallback_reverse = tuning.fallback_reverse;
        scanner_tuning.prefilter_truncate = tuning.prefilter_truncate;
        scanner_tuning.fallback_prefix_gate = tuning.fallback_prefix_gate;
        scanner_tuning.decode_focus = tuning.decode_focus;
        scanner_tuning.confirmed_suffix_gate = tuning.confirmed_suffix_gate;
        scanner_tuning.no_candidate_gate = tuning.no_candidate_gate;
        scanner_tuning.fallback_localizer = tuning.fallback_localizer;
        scanner_tuning.gpu_recall_floor = tuning.gpu_recall_floor;
        if let Some(timeout_ms) = tuning.gpu_moe_timeout_ms {
            if timeout_ms == 0 {
                config_errors
                    .push("- [tuning].gpu_moe_timeout_ms: expected an integer >= 1".to_string());
            } else {
                scanner_tuning.gpu_moe_timeout_ms = Some(timeout_ms);
            }
        }
    }
}
