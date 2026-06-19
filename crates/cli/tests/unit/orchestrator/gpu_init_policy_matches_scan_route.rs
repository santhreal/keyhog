use super::support::ENV_LOCK;
use clap::{CommandFactory, Parser};
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};
use keyhog_scanner::hw_probe::parse_backend_str;
use keyhog_scanner::GpuInitPolicy;

fn scan_args(args: &[&str]) -> ScanArgs {
    ScanArgs::try_parse_from(args).expect("parse scan args")
}

fn with_route_policy_lock(test: impl FnOnce()) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|err| err.into_inner());
    test();
}

#[test]
fn explicit_simd_backend_skips_gpu_compile() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "simd", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn explicit_gpu_backend_forces_gpu_compile() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "megascan", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceEnabled
        );
    });
}

#[test]
fn filesystem_auto_scan_skips_gpu_compile() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn batch_pipeline_filesystem_auto_keeps_runtime_gpu_policy() {
    with_route_policy_lock(|| {
        let args = scan_args(&[
            "scan",
            "--backend",
            "auto",
            "--batch-pipeline",
            "--path",
            ".",
        ]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromRuntimePolicy
        );
    });
}

#[test]
fn stdin_auto_scan_keeps_runtime_gpu_policy() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--stdin"]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromRuntimePolicy
        );
    });
}

#[test]
fn backend_flag_gpu_overrides_filesystem_auto_skip() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "gpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceEnabled
        );
    });
}

#[test]
fn no_gpu_flag_forces_disabled_policy_for_auto() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--no-gpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::ForceDisabled
        );
    });
}

#[test]
fn require_gpu_flag_keeps_auto_filesystem_gpu_policy_open() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--backend", "auto", "--require-gpu", "--path", "."]);
        assert_eq!(
            API.gpu_init_policy_for_args_for_test(&args),
            GpuInitPolicy::FromRuntimePolicy
        );
    });
}

#[test]
fn autoroute_config_digest_includes_gpu_autoroute_opt_in() {
    with_route_policy_lock(|| {
        let args = scan_args(&["scan", "--path", "."]);
        let scanner = API.build_scanner_config(&args);

        let without_gpu_probe = API.autoroute_config_digest_for_scanner(scanner.clone());
        let with_gpu_probe =
            API.autoroute_config_digest_for_scanner_with_autoroute_gpu(scanner, true);

        assert_ne!(
            without_gpu_probe, with_gpu_probe,
            "autoroute cache identity must distinguish calibration with and without GPU candidates"
        );
    });
}

#[test]
fn autoroute_config_digest_includes_source_limits() {
    with_route_policy_lock(|| {
        let mut default_limit = scan_args(&["scan", "--no-config", "--stdin"]);
        let default_digest = API
            .autoroute_config_digest_for_args(&mut default_limit)
            .expect("default resolved config digest");

        let mut smaller_stdin = scan_args(&[
            "scan",
            "--no-config",
            "--stdin",
            "--limit-stdin-bytes",
            "1MiB",
        ]);
        let smaller_digest = API
            .autoroute_config_digest_for_args(&mut smaller_stdin)
            .expect("limited resolved config digest");

        assert_ne!(
            default_digest, smaller_digest,
            "autoroute cache identity must include resolved source limits because they change workload bytes and route cost"
        );
    });
}

/// Coherence gate: every value the `--backend` flag ADVERTISES (clap
/// `PossibleValuesParser`) must be RECOGNIZED by the canonical
/// `parse_backend_str`, which both the gpu-init policy and the actual scan
/// routing delegate to. The two lists had drifted: clap accepted `megascan`
/// (no hyphen) but the parser dropped it to `None`, so `--backend megascan`
/// silently fell through to auto-routing — the gpu-init policy and the routing
/// disagreed about the same flag. This pins them together so a future
/// advertised value that nobody teaches the parser fails CI instead of
/// silently no-op'ing.
#[test]
fn every_advertised_backend_value_is_recognized_by_the_canonical_parser() {
    let cmd = ScanArgs::command();
    let backend = cmd
        .get_arguments()
        .find(|a| a.get_id() == "backend")
        .expect("the scan command must expose a --backend argument");
    let advertised: Vec<String> = backend
        .get_possible_values()
        .iter()
        .map(|v| v.get_name().to_string())
        .collect();
    assert!(
        advertised.len() >= 4,
        "the --backend flag must advertise its fixed value set; got {advertised:?}"
    );
    for value in &advertised {
        if value == "auto" {
            // `auto` is the explicit "defer to the router" choice, not a fixed
            // backend the parser names.
            assert_eq!(
                parse_backend_str(value),
                None,
                "`auto` must not resolve to a fixed backend"
            );
        } else {
            assert!(
                parse_backend_str(value).is_some(),
                "advertised --backend value `{value}` is not recognized by the \
                 canonical parse_backend_str: clap accepts it but routing would \
                 silently ignore it (alias-list drift)"
            );
        }
    }
}
