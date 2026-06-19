//! Migrated from src/gpu.rs

use keyhog_scanner::gpu::{
    env_no_gpu, env_require_gpu, gpu_runtime_policy, set_gpu_runtime_policy, GpuRuntimePolicy,
};

// SAFETY rationale: these tests mutate process-global env state and the scanner
// GPU runtime policy, so they cannot run in parallel with anything else that
// reads the policy. Rust's test harness runs `#[test]`s in the same module on
// separate threads by default; we serialize by putting all env/policy-touching
// tests behind a single Mutex guard.
static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_clean_env<F: FnOnce()>(test: F) {
    let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let saved_policy = gpu_runtime_policy();
    let saved = [
        ("CI", std::env::var("CI").ok()),
        ("GITHUB_ACTIONS", std::env::var("GITHUB_ACTIONS").ok()),
        ("GITLAB_CI", std::env::var("GITLAB_CI").ok()),
        ("JENKINS_URL", std::env::var("JENKINS_URL").ok()),
    ];
    set_gpu_runtime_policy(GpuRuntimePolicy::Auto);
    // Clear everything to start.
    for (k, _) in &saved {
        // SAFETY: env mutation is unsafe in Rust 2024+ for soundness
        // reasons (race with reads in other threads). The ENV_GUARD
        // mutex above serializes our env-touching tests, and Rust's
        // own env::var implementation locks internally, so a non-
        // guarded reader still gets a consistent atomic snapshot.
        unsafe { std::env::remove_var(k) };
    }
    test();
    // Restore.
    for (k, v) in saved {
        unsafe {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
    set_gpu_runtime_policy(saved_policy);
}

#[test]
fn empty_env_no_ci_no_gpu_skip() {
    with_clean_env(|| {
        assert!(
            !env_no_gpu(),
            "env_no_gpu with no env vars set should be false"
        );
    });
}

#[test]
fn ci_true_does_not_change_gpu_policy() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "true") };
        assert!(
            !env_no_gpu(),
            "CI=true must not change GPU policy without explicit --no-gpu"
        );
    });
}

#[test]
fn disabled_policy_skips_gpu_even_with_ci_set() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "true") };
        set_gpu_runtime_policy(GpuRuntimePolicy::Disabled);
        assert!(
            env_no_gpu(),
            "GpuRuntimePolicy::Disabled must disable GPU regardless of CI"
        );
    });
}

#[test]
fn required_policy_does_not_skip_gpu() {
    with_clean_env(|| {
        set_gpu_runtime_policy(GpuRuntimePolicy::Required);
        assert!(!env_no_gpu(), "required policy must keep GPU probing open");
        assert!(env_require_gpu(), "required policy must arm require-gpu");
    });
}

#[test]
fn github_actions_marker_does_not_change_gpu_policy() {
    with_clean_env(|| {
        unsafe { std::env::set_var("GITHUB_ACTIONS", "true") };
        assert!(
            !env_no_gpu(),
            "GITHUB_ACTIONS should not change GPU policy without --no-gpu"
        );
    });
}

#[test]
fn ci_false_does_not_trigger_skip() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "false") };
        assert!(!env_no_gpu(), "CI=false should not imply env_no_gpu");
    });
}
