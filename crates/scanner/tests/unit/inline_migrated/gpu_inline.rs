//! Migrated from src/gpu.rs

use keyhog_scanner::gpu::{gpu_disabled_by_policy, gpu_runtime_policy, GpuRuntimePolicy};

// SAFETY rationale: these tests mutate process-global environment state, so
// they cannot run in parallel with one another. They deliberately never mutate
// the process-global GPU policy: unrelated scan tests read it concurrently.
static POLICY_ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_clean_env<F: FnOnce()>(test: F) {
    let _guard = POLICY_ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let initial_policy = gpu_runtime_policy();
    let saved = [
        ("CI", std::env::var("CI").ok()),
        ("GITHUB_ACTIONS", std::env::var("GITHUB_ACTIONS").ok()),
        ("GITLAB_CI", std::env::var("GITLAB_CI").ok()),
        ("JENKINS_URL", std::env::var("JENKINS_URL").ok()),
    ];
    assert_eq!(initial_policy, GpuRuntimePolicy::Auto);
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
}

#[test]
fn empty_env_no_ci_no_gpu_skip() {
    with_clean_env(|| {
        assert!(
            !gpu_disabled_by_policy(),
            "clean process env must not disable GPU without explicit policy"
        );
    });
}

#[test]
fn ci_true_does_not_change_gpu_policy() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "true") };
        assert!(
            !gpu_disabled_by_policy(),
            "CI=true must not change GPU policy without explicit --no-gpu"
        );
    });
}

#[test]
fn disabled_policy_skips_gpu_even_with_ci_set() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "true") };
        assert!(
            GpuRuntimePolicy::Disabled.is_disabled(),
            "GpuRuntimePolicy::Disabled must disable GPU regardless of CI"
        );
    });
}

#[test]
fn required_policy_does_not_skip_gpu() {
    with_clean_env(|| {
        assert!(
            !GpuRuntimePolicy::Required.is_disabled(),
            "required policy must keep GPU probing open"
        );
        assert!(
            GpuRuntimePolicy::Required.is_required(),
            "required policy must arm require-gpu"
        );
    });
}

#[test]
fn github_actions_marker_does_not_change_gpu_policy() {
    with_clean_env(|| {
        unsafe { std::env::set_var("GITHUB_ACTIONS", "true") };
        assert!(
            !gpu_disabled_by_policy(),
            "GITHUB_ACTIONS should not change GPU policy without --no-gpu"
        );
    });
}

#[test]
fn ci_false_does_not_trigger_skip() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "false") };
        assert!(
            !gpu_disabled_by_policy(),
            "CI=false should not disable GPU policy"
        );
    });
}
