use super::support::ENV_LOCK;
use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator::gpu_init_policy_for_args_for_test;
use keyhog_scanner::GpuInitPolicy;
use std::ffi::OsString;

fn scan_args(args: &[&str]) -> ScanArgs {
    ScanArgs::try_parse_from(args).expect("parse scan args")
}

fn with_clean_gpu_env(test: impl FnOnce()) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let keys = [
        "KEYHOG_BACKEND",
        "KEYHOG_NO_GPU",
        "KEYHOG_REQUIRE_GPU",
        "KEYHOG_LEGACY_PIPELINE",
    ];
    let previous: Vec<(&str, Option<OsString>)> = keys
        .into_iter()
        .map(|key| (key, std::env::var_os(key)))
        .collect();
    unsafe {
        for (key, _) in &previous {
            std::env::remove_var(key);
        }
    }

    test();

    unsafe {
        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[test]
fn explicit_simd_backend_skips_gpu_compile() {
    with_clean_gpu_env(|| {
        let args = scan_args(&["scan", "--backend", "simd", "--path", "."]);
        assert_eq!(
            gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn explicit_gpu_backend_forces_gpu_compile() {
    with_clean_gpu_env(|| {
        let args = scan_args(&["scan", "--backend", "megascan", "--path", "."]);
        assert_eq!(
            gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceEnabled
        );
    });
}

#[test]
fn filesystem_auto_scan_skips_gpu_compile() {
    with_clean_gpu_env(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--path", "."]);
        assert_eq!(
            gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn stdin_auto_scan_keeps_environment_gpu_policy() {
    with_clean_gpu_env(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--stdin"]);
        assert_eq!(
            gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromEnvironment
        );
    });
}

#[test]
fn env_forced_gpu_overrides_filesystem_auto_skip() {
    with_clean_gpu_env(|| {
        unsafe { std::env::set_var("KEYHOG_BACKEND", "gpu") };
        let args = scan_args(&["scan", "--path", "."]);
        assert_eq!(
            gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceEnabled
        );
    });
}

#[test]
fn explicit_no_gpu_zero_keeps_environment_gpu_policy_for_auto() {
    with_clean_gpu_env(|| {
        unsafe { std::env::set_var("KEYHOG_NO_GPU", "0") };
        let args = scan_args(&["scan", "--backend", "auto", "--path", "."]);
        assert_eq!(
            gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromEnvironment
        );
    });
}
