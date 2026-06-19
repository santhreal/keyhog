//! Regression: the old `KEYHOG_SERVICE_ENV_VARS` runtime-extension hook for the
//! Tier-B auto-fix service map is ignored.
//!
//! This lives in its OWN test binary (one file == one process) so that this is
//! the only test that touches the `auto_fix` service map. The map is a
//! process-wide `LazyLock` initialized once at first use; isolating the test
//! proves the env var cannot influence first initialization.
//!
//! Goes red if ambient process environment can still augment the compiled-in
//! Tier-B data.

#[test]
fn legacy_runtime_extension_env_is_ignored() {
    // A unique temp dir so a parallel run of another test binary can't collide.
    let dir = std::env::temp_dir().join(format!(
        "keyhog-svcenv-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let ext = dir.join("service-env-ext.toml");
    std::fs::write(
        &ext,
        "[[service]]\nmatch = \"acmecorp\"\nenv = \"ACMECORP_DEPLOY_TOKEN\"\n",
    )
    .expect("write extension file");

    // SAFETY: single-threaded at this point — this is the only test in this
    // binary and it sets the env var before any code path can read the map.
    std::env::set_var("KEYHOG_SERVICE_ENV_VARS", &ext);

    // Baseline still resolves from compiled Tier-B data.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "stripe"
        ),
        "STRIPE_SECRET_KEY"
    );
    // The old runtime extension hook is ignored; unknown services use the
    // documented screaming-snake derivation.
    assert_eq!(
        keyhog_core::testing::CoreTestApi::auto_fix_env_var_name_for_service(
            &keyhog_core::testing::TestApi,
            "acmecorp-prod"
        ),
        "ACMECORP_PROD_KEY",
        "legacy KEYHOG_SERVICE_ENV_VARS must not alter SARIF fix suggestions"
    );

    std::env::remove_var("KEYHOG_SERVICE_ENV_VARS");
    let _ = std::fs::remove_dir_all(&dir);
}
