//! Migrated from src/gpu.rs

use keyhog_scanner::testing::{env_no_gpu, is_ci_environment};

// SAFETY rationale: these tests mutate process-global env state,
// so they cannot run in parallel with anything else that reads
// CI / KEYHOG_NO_GPU. Rust's test harness runs `#[test]`s in the
// same module on separate threads by default; we serialize by
// putting all env-touching tests behind a single Mutex guard.
// Without this, a parallel test that reads CI mid-set sees the
// wrong value and flakes. The Mutex is per-module so other
// modules' tests aren't blocked.
static ENV_GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_clean_env<F: FnOnce()>(test: F) {
    let _guard = ENV_GUARD.lock().unwrap_or_else(|e| e.into_inner());
    let saved = [
        ("CI", std::env::var("CI").ok()),
        ("GITHUB_ACTIONS", std::env::var("GITHUB_ACTIONS").ok()),
        ("GITLAB_CI", std::env::var("GITLAB_CI").ok()),
        ("JENKINS_URL", std::env::var("JENKINS_URL").ok()),
        ("KEYHOG_NO_GPU", std::env::var("KEYHOG_NO_GPU").ok()),
    ];
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
            !is_ci_environment(),
            "is_ci_environment with no env vars set should be false"
        );
        assert!(
            !env_no_gpu(),
            "env_no_gpu with no env vars set should be false"
        );
    });
}

#[test]
fn ci_true_triggers_gpu_skip() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "true") };
        assert!(is_ci_environment(), "CI=true should be detected as CI");
        assert!(
            env_no_gpu(),
            "CI=true should imply env_no_gpu=true without explicit KEYHOG_NO_GPU"
        );
    });
}

#[test]
fn keyhog_no_gpu_zero_overrides_ci() {
    with_clean_env(|| {
        unsafe {
            std::env::set_var("CI", "true");
            std::env::set_var("KEYHOG_NO_GPU", "0");
        }
        assert!(
            is_ci_environment(),
            "CI=true still detected as CI even with NO_GPU=0"
        );
        assert!(
            !env_no_gpu(),
            "KEYHOG_NO_GPU=0 must override CI auto-skip (self-hosted GPU runner case)"
        );
    });
}

#[test]
fn keyhog_no_gpu_one_in_non_ci_skips() {
    with_clean_env(|| {
        unsafe { std::env::set_var("KEYHOG_NO_GPU", "1") };
        assert!(
            !is_ci_environment(),
            "KEYHOG_NO_GPU=1 alone should not flag CI"
        );
        assert!(
            env_no_gpu(),
            "explicit KEYHOG_NO_GPU=1 should still disable GPU"
        );
    });
}

#[test]
fn github_actions_marker_alone_is_ci() {
    with_clean_env(|| {
        unsafe { std::env::set_var("GITHUB_ACTIONS", "true") };
        assert!(
            is_ci_environment(),
            "GITHUB_ACTIONS set without CI= must still detect CI"
        );
        assert!(env_no_gpu(), "GITHUB_ACTIONS should imply auto-skip");
    });
}

#[test]
fn ci_false_does_not_trigger_skip() {
    with_clean_env(|| {
        unsafe { std::env::set_var("CI", "false") };
        assert!(
            !is_ci_environment(),
            "CI=false should not be detected as CI"
        );
        assert!(!env_no_gpu(), "CI=false should not imply env_no_gpu");
    });
}
