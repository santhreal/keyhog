//! GPU environment detection + require-GPU preflight policy.
//!
//! Split out of `gpu.rs` (Law 5 / 500-LOC modularity cap): these are the
//! environment-variable readers (`KEYHOG_NO_GPU`, `KEYHOG_REQUIRE_GPU`, CI
//! auto-detect) plus the `require-GPU` preflight that fails closed when a
//! GPU is demanded but absent. Re-exported from `gpu` via `pub use env::*`
//! so the public surface (`crate::gpu::env_no_gpu`, `::gpu_probe`,
//! `::require_gpu_preflight`, …) is unchanged.

#[cfg(feature = "gpu")]
use super::backend;

/// Probe GPU availability and adapter metadata without panicking.
///
/// Honours `KEYHOG_NO_GPU=1` (and the usual on/off/true/false/0
/// negatives) by reporting "no GPU available" without ever calling
/// `backend::get_gpu()`. The MoE compute-shader init happens lazily
/// inside `get_gpu()`, so this short-circuit is the difference
/// between "Metal adapter request blocks for minutes on certain Mac
/// configurations" (the v0.5.27 reproduction on Apple M4 Pro that
/// the env var was added to escape) and "scanner starts in ~10ms
/// like every other CPU-only tool".
#[must_use]
pub fn gpu_probe() -> (bool, Option<String>, Option<u64>) {
    if env_no_gpu() {
        return (false, None, None);
    }
    #[cfg(feature = "gpu")]
    if let Some(gpu) = backend::get_gpu() {
        return (true, Some(gpu.gpu_name().to_string()), gpu.vram_mb());
    }
    (false, None, None)
}

/// True when `KEYHOG_REQUIRE_GPU=1` is set: the operator demands a usable
/// GPU and a silent CPU fallback is forbidden. Read uncached so embedders /
/// tests that toggle the var between scans see the change (it is process-
/// global at runtime, so this is only a few extra syscalls on the cold path).
#[must_use]
pub fn env_require_gpu() -> bool {
    std::env::var("KEYHOG_REQUIRE_GPU").as_deref() == Ok("1")
}

/// Require-GPU preflight, independent of backend routing.
///
/// When `KEYHOG_REQUIRE_GPU=1` is NOT set this is a no-op and returns
/// `Ok(())`. When it IS set, the contract (docs/src/reference/env.md,
/// install.md, the `require-gpu-fails-closed` docker scenario) is to
/// "refuse to run when no usable GPU adapter is detected". This check
/// fires on the *no-GPU* path the flag exists for - it does not depend on
/// `select_backend` having chosen GPU first (finding C0): the hard-fail
/// that used to live only inside the GPU-selected dispatch paths was
/// unreachable when there was no GPU, so a CPU scan completed and exited 0.
///
/// Returns `Err(diagnostic)` when a GPU is required but the host has no
/// non-software adapter, or the GPU self-test (adapter init + one real MoE
/// compute dispatch) fails. The caller (CLI run loop) maps that to the
/// documented exit code 2. Returning an `Err` here - rather than calling
/// `std::process::exit` from the library - keeps embedders alive (finding
/// M12).
pub fn require_gpu_preflight() -> Result<(), String> {
    if !env_require_gpu() {
        return Ok(());
    }

    let caps = crate::hw_probe::probe_hardware();
    if !caps.gpu_available || caps.gpu_is_software {
        let detail = match (&caps.gpu_name, caps.gpu_is_software) {
            (Some(name), true) => {
                format!("only a software GPU adapter is present ({name})")
            }
            (Some(name), false) => format!("adapter present but unusable ({name})"),
            (None, _) => "no GPU adapter detected".to_string(),
        };
        return Err(format!(
            "KEYHOG_REQUIRE_GPU=1 but {detail}; refusing to run on CPU. \
             Install or enable a non-software GPU adapter + driver, or unset \
             KEYHOG_REQUIRE_GPU to allow the CPU/SIMD path."
        ));
    }

    // A non-software adapter is reported. Prove it can actually run a
    // production-sized MoE dispatch before declaring the requirement met -
    // a present-but-broken GPU (driver mismatch, dispatch reject) is exactly
    // the regression the flag is meant to catch on self-hosted runners.
    if let Err(reason) = super::gpu_self_test() {
        return Err(format!(
            "KEYHOG_REQUIRE_GPU=1 but the GPU self-test failed ({reason}); \
             refusing to run on CPU. Fix the GPU stack or unset \
             KEYHOG_REQUIRE_GPU."
        ));
    }

    Ok(())
}

pub fn env_no_gpu() -> bool {
    if let Ok(v) = std::env::var("KEYHOG_NO_GPU") {
        // Explicit user choice wins both directions. "0"/"false"/"off"
        // is the override that says "yes I want the GPU even though
        // CI is detected" (self-hosted GPU runners exist).
        return !matches!(v.as_str(), "" | "0" | "false" | "FALSE" | "off" | "OFF");
    }
    // `KEYHOG_REQUIRE_GPU=1` implies "do not skip the GPU": the operator
    // wants a regression on a self-hosted GPU runner to fail loudly, not be
    // masked by the CI auto-skip below. GitHub Actions always sets
    // CI=true/GITHUB_ACTIONS=true even on self-hosted runners that have real
    // GPUs, so without this override the auto-skip would route to SimdCpu
    // before any GPU probe and the require gate would never fire (finding
    // C1). This mirrors the explicit `KEYHOG_NO_GPU=0` override above; an
    // explicit `KEYHOG_NO_GPU=1` still wins as the more specific signal (and
    // the require-GPU preflight then hard-fails because the GPU is absent).
    if env_require_gpu() {
        return false;
    }
    // No explicit setting. Auto-skip GPU init on CI runners: they
    // have no discrete GPU, the wgpu adapter probe enumerates the
    // llvmpipe/swiftshader software fallback, gpu.rs:83 rightly
    // rejects it as a software adapter, and the operator gets a
    // confusing "GPU MoE init failed" warning that costs ~250ms of
    // cold-start time for nothing. Detecting CI here turns that
    // failure into a silent no-op (the user is on CPU + SIMD which
    // is the right path on a CI runner anyway). Set
    // KEYHOG_NO_GPU=0 to opt back in on self-hosted GPU runners.
    is_ci_environment()
}

/// True when we are running inside a CI system. Used by the GPU
/// init paths to auto-skip the wgpu adapter probe (which always
/// fails on hosted CI runners and costs ~250ms of pointless cold-
/// start time + emits a confusing warning).
///
/// Checks `CI=true` (the de-facto standard, set by GitHub Actions,
/// GitLab CI, CircleCI, Travis, Buildkite, Drone, AppVeyor,
/// Codeship, Wercker, and most others) plus a handful of platform-
/// specific markers that some runners set without also setting the
/// generic `CI` (Jenkins, TeamCity, Azure Pipelines, Bitbucket
/// Pipelines).
pub fn is_ci_environment() -> bool {
    // The generic CI marker. Some runners set CI=true, some set
    // CI=1, GitHub Actions sets both. Treat any non-empty non-false
    // value as truthy.
    if let Ok(v) = std::env::var("CI") {
        if !matches!(v.as_str(), "" | "0" | "false" | "FALSE" | "off" | "OFF") {
            return true;
        }
    }
    // Platform-specific markers. Some legacy CI systems set their
    // own variable but not the generic CI=. Hit the common ones.
    const CI_MARKERS: &[&str] = &[
        "GITHUB_ACTIONS",         // GitHub Actions
        "GITLAB_CI",              // GitLab CI
        "JENKINS_URL",            // Jenkins
        "TF_BUILD",               // Azure Pipelines
        "TEAMCITY_VERSION",       // TeamCity
        "BITBUCKET_BUILD_NUMBER", // Bitbucket Pipelines
        "BUILDKITE",              // Buildkite
        "CIRCLECI",               // CircleCI
        "DRONE",                  // Drone CI
        "TRAVIS",                 // Travis CI
        "APPVEYOR",               // AppVeyor
        "CODEBUILD_BUILD_ID",     // AWS CodeBuild
        "WERCKER",                // Wercker
        "SEMAPHORE",              // Semaphore CI
    ];
    CI_MARKERS.iter().any(|k| std::env::var(k).is_ok())
}
