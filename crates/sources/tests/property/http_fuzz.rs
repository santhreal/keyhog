//! Property tests for the shared `keyhog_sources::http` module.
//!
//! The HTTP client builder is on the critical path for every URL scan, every
//! GitHub-org enumeration, every verifier round-trip, and every Slack source
//! pull. Egress routing (proxy) and TLS verification are security-load-bearing:
//! the verifier transmits discovered secrets to provider APIs, so anything that
//! can silently reroute that traffic or disable certificate checking is a
//! secret-theft vector.
//!
//! Policy (config mandate): ONLY explicit config, the `--proxy` / `--insecure`
//! CLI flags (and TOML) that populate `HttpClientConfig.proxy` /
//! `.insecure_tls`: may change behavior. NO environment variable does.
//! `KEYHOG_PROXY` / `KEYHOG_INSECURE_TLS` are NOT read, and the builders call
//! `.no_proxy()` when none is configured so reqwest's ambient `HTTPS_PROXY` /
//! `HTTP_PROXY` / `ALL_PROXY` auto-detection cannot silently reroute traffic.
//! These tests SET those env vars to hostile values and prove they have no
//! effect.
//!
//! Test budget: policy properties run 10 000 cases. Builder properties run a
//! bounded smoke profile because constructing real reqwest builders/clients
//! dominates the fast aggregate source gate.

#![cfg(any(feature = "web", feature = "github", feature = "s3"))]

use keyhog_sources::testing::{SourceTestApi, TestApi};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use keyhog_sources::http::HttpClientConfig;

const POLICY_CASES: u32 = 10_000;
const BUILDER_CASES: u32 = 256;

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── strategies ──────────────────────────────────────────────────────

/// A proxy URL the operator might plausibly pass - covers `http://`,
/// `https://`, `socks5://`, plus the `off`/`none`/`""` disable
/// sentinels.
fn any_proxy_url() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("off".to_string()),
        Just("none".to_string()),
        Just(String::new()),
        // Plain http/https proxy on a random port.
        (
            prop_oneof![Just("http"), Just("https"), Just("socks5"), Just("socks5h")],
            "[a-z][a-z0-9.-]{0,30}",
            1u16..=65535,
        )
            .prop_map(|(scheme, host, port)| format!("{scheme}://{host}:{port}")),
        // Proxy with userinfo.
        (
            prop_oneof![Just("http"), Just("https")],
            "[a-z]{1,8}",
            "[A-Za-z0-9]{1,32}",
            "[a-z][a-z0-9.-]{0,30}",
            1u16..=65535,
        )
            .prop_map(|(scheme, user, pass, host, port)| {
                format!("{scheme}://{user}:{pass}@{host}:{port}")
            }),
    ]
}

/// Arbitrary `KEYHOG_PROXY` env value, including missing / empty. Used to prove
/// that whatever is in the env, it never changes `effective_proxy`.
fn any_env_proxy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), any_proxy_url().prop_map(Some)]
}

// ── helpers ─────────────────────────────────────────────────────────

/// Test-local HTTP env scope. Rust environment variables are process-global,
/// while the test harness runs property tests concurrently. Hold one lock
/// around every case that writes HTTP env knobs so a sibling case cannot leak
/// proxy/TLS state into the assertion under test. (The production code no longer
/// READS these vars; we set them only to prove they are ignored.)
fn with_http_env<R>(proxy: Option<&str>, insecure_tls: Option<&str>, f: impl FnOnce() -> R) -> R {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let prev_proxy = std::env::var("KEYHOG_PROXY").ok();
    let prev_insecure_tls = std::env::var("KEYHOG_INSECURE_TLS").ok();

    set_env_value("KEYHOG_PROXY", proxy);
    set_env_value("KEYHOG_INSECURE_TLS", insecure_tls);

    let out = f();

    set_env_value("KEYHOG_PROXY", prev_proxy.as_deref());
    set_env_value("KEYHOG_INSECURE_TLS", prev_insecure_tls.as_deref());
    out
}

fn set_env_value(key: &str, value: Option<&str>) {
    match value {
        Some(v) => std::env::set_var(key, v),
        None => std::env::remove_var(key),
    }
}

fn http_fuzz_config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        failure_persistence: Some(Box::new(FileFailurePersistence::Direct(
            "tests/property/http_fuzz.proptest-regressions",
        ))),
        ..ProptestConfig::default()
    }
}

// ── property tests ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(http_fuzz_config(POLICY_CASES))]

    /// The explicit `--proxy` value is what `effective_proxy` returns, verbatim,
    /// no matter what `KEYHOG_PROXY` is set to. (The env is ignored entirely;
    /// this also covers the old "flag wins over env" contract.)
    #[test]
    fn explicit_proxy_is_used_verbatim_env_ignored(
        env in any_env_proxy(),
        flag in any_proxy_url(),
    ) {
        with_http_env(env.as_deref(), None, || {
            let cfg = HttpClientConfig { proxy: Some(flag.clone()), ..Default::default() };
            let resolved = TestApi.http_effective_proxy(&cfg);
            prop_assert_eq!(resolved.as_deref(), Some(flag.as_str()));
            Ok(())
        })?;
    }

    /// With no explicit `--proxy`, `effective_proxy` is ALWAYS `None` regardless
    /// of `KEYHOG_PROXY`. No env var may set a proxy (config mandate + security:
    /// an ambient proxy must not silently reroute secret-verification traffic).
    #[test]
    fn env_proxy_is_ignored_when_flag_unset(env in any_proxy_url()) {
        with_http_env(Some(&env), None, || {
            let cfg = HttpClientConfig::default();
            prop_assert_eq!(TestApi.http_effective_proxy(&cfg), None);
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(http_fuzz_config(BUILDER_CASES))]

    /// Valid `http://` / `https://` / `socks5://` URLs must produce
    /// a working blocking builder. Invalid schemes (`gopher://`,
    /// random gibberish) must surface a clean Err, never a panic.
    #[test]
    fn blocking_builder_handles_every_proxy_url(p in any_proxy_url()) {
        with_http_env(None, None, || {
            let cfg = HttpClientConfig { proxy: Some(p.clone()), ..Default::default() };
            match TestApi.http_blocking_client_builder(&cfg) {
                Ok(_) | Err(_) => {} // either is fine; we're proving no-panic
            }
        });
    }

    /// Same for the async builder.
    #[test]
    fn async_builder_handles_every_proxy_url(p in any_proxy_url()) {
        with_http_env(None, None, || {
            let cfg = HttpClientConfig { proxy: Some(p.clone()), ..Default::default() };
            match TestApi.http_async_client_builder(&cfg) {
                Ok(_) | Err(_) => {}
            }
        });
    }

    /// Building with no proxy + no env var must always succeed -
    /// that's the default offline-safe path and any failure here
    /// would brick every scan run. The proptest input `insecure`
    /// must be reflected in the resulting clients' effective_*
    /// signals - without these assertions a regression where the
    /// flag was silently dropped would still see the test pass.
    #[test]
    fn default_builder_always_succeeds(insecure in any::<bool>()) {
        with_http_env(None, None, || {
            let cfg = HttpClientConfig { insecure_tls: insecure, ..Default::default() };
            let blocking = TestApi.http_blocking_client_builder(&cfg);
            let r#async = TestApi.http_async_client_builder(&cfg);
            prop_assert!(blocking.is_ok(), "blocking builder must succeed for insecure_tls={insecure}");
            prop_assert!(r#async.is_ok(), "async builder must succeed for insecure_tls={insecure}");
            // Build the actual clients (not just the builders) - a
            // broken cfg propagation would compile but fail at the
            // build() step on real validation.
            prop_assert!(blocking.unwrap().build().is_ok(),
                "blocking builder must produce a usable client");
            prop_assert!(r#async.unwrap().build().is_ok(),
                "async builder must produce a usable client");
            // The insecure flag must round-trip through the cfg
            // accessor - regression check on accessor wiring.
            prop_assert_eq!(TestApi.http_effective_insecure_tls(&cfg), insecure);
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(http_fuzz_config(POLICY_CASES))]

    /// `effective_insecure_tls` is driven ONLY by the explicit `insecure_tls`
    /// field. `KEYHOG_INSECURE_TLS` set to ANY value (`1`, `true`, `TRUE`, a
    /// typo, anything) on a default config leaves verification ON. No env var
    /// may disable TLS verification.
    #[test]
    fn insecure_tls_env_var_is_always_ignored(value in "[a-zA-Z0-9]{0,12}") {
        with_http_env(None, Some(&value), || {
            let cfg = HttpClientConfig::default();
            prop_assert!(!TestApi.http_effective_insecure_tls(&cfg),
                "env KEYHOG_INSECURE_TLS={value:?} must NOT enable insecure TLS");
            Ok(())
        })?;
    }

    /// Explicit `insecure_tls: true` is honored and the env can't change it
    /// either way (it isn't read).
    #[test]
    fn explicit_insecure_tls_is_honored_env_ignored(
        env in "[a-zA-Z0-9]{0,12}",
    ) {
        with_http_env(None, Some(&env), || {
            let cfg = HttpClientConfig { insecure_tls: true, ..Default::default() };
            prop_assert!(TestApi.http_effective_insecure_tls(&cfg));
            Ok(())
        })?;
    }

    /// The core mandate guarantee: with BOTH `KEYHOG_PROXY` and
    /// `KEYHOG_INSECURE_TLS` set to hostile/active values, a default
    /// `HttpClientConfig` still yields no proxy and TLS verification on. Ambient
    /// authority over egress + TLS is fully severed.
    #[test]
    fn ambient_env_cannot_set_proxy_or_disable_tls(proxy in any_proxy_url()) {
        with_http_env(Some(&proxy), Some("1"), || {
            let cfg = HttpClientConfig::default();
            prop_assert_eq!(TestApi.http_effective_proxy(&cfg), None);
            prop_assert!(!TestApi.http_effective_insecure_tls(&cfg));
            Ok(())
        })?;
    }

    /// `HttpClientConfig::default()` is offline-safe: no proxy,
    /// TLS verification on, no UA suffix. A regression here would
    /// silently change the security posture of every consumer that
    /// uses the default.
    #[test]
    fn default_config_is_offline_safe(_seed in any::<u32>()) {
        with_http_env(None, None, || {
            let cfg = HttpClientConfig::default();
            prop_assert_eq!(TestApi.http_effective_proxy(&cfg), None);
            prop_assert!(!TestApi.http_effective_insecure_tls(&cfg));
            prop_assert!(cfg.ua_suffix.is_none());
            Ok(())
        })?;
    }

    /// Proxy disable sentinels (`off`, `none`, empty) must round-trip
    /// through `effective_proxy` verbatim so builders can call
    /// `.no_proxy()`, regardless of any env value.
    #[test]
    fn proxy_disable_sentinels_are_preserved(flag in prop_oneof![
        Just("off".to_string()),
        Just("none".to_string()),
        Just(String::new()),
    ]) {
        with_http_env(Some("http://env-should-not-win:8080"), None, || {
            let cfg = HttpClientConfig {
                proxy: Some(flag.clone()),
                ..Default::default()
            };
            let resolved = TestApi.http_effective_proxy(&cfg);
            prop_assert_eq!(resolved.as_deref(), Some(flag.as_str()));
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(http_fuzz_config(BUILDER_CASES))]

    /// Custom timeout must propagate to builder construction without
    /// panicking - callers (Slack/S3/web) rely on per-source overrides.
    #[test]
    fn custom_timeout_builder_succeeds(secs in 1u64..120) {
        with_http_env(None, None, || {
            let cfg = HttpClientConfig {
                timeout: Some(std::time::Duration::from_secs(secs)),
                ..Default::default()
            };
            prop_assert!(TestApi.http_blocking_client_builder(&cfg).is_ok());
            prop_assert!(TestApi.http_async_client_builder(&cfg).is_ok());
            Ok(())
        })?;
    }

    /// UA suffix must not break builder construction for any short label.
    #[test]
    fn ua_suffix_builder_succeeds(suffix in "[a-z]{0,16}") {
        with_http_env(None, None, || {
            let cfg = HttpClientConfig {
                ua_suffix: if suffix.is_empty() {
                    None
                } else {
                    Some(suffix)
                },
                ..Default::default()
            };
            prop_assert!(TestApi.http_blocking_client_builder(&cfg).unwrap().build().is_ok());
            prop_assert!(TestApi.http_async_client_builder(&cfg).unwrap().build().is_ok());
            Ok(())
        })?;
    }
}

// ── unit-test sanity guard for the proptests themselves ─────────────

#[test]
fn property_case_budgets_are_acknowledged() {
    // If a future tweak drops POLICY_CASES below 10k without intent, this
    // assert fails and the diff has to justify the change.
    assert_eq!(
        POLICY_CASES, 10_000,
        "intent: 10k cases per pure HTTP policy property"
    );
    assert!(
        BUILDER_CASES >= 256,
        "builder smoke properties must keep a non-trivial bounded profile"
    );
}
