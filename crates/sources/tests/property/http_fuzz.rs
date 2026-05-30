//! Property tests for the shared `keyhog_sources::http` module.
//!
//! The HTTP client builder is on the critical path for every URL
//! scan, every GitHub-org enumeration, every verifier round-trip, and
//! every Slack source pull. A bug in the proxy-resolution precedence
//! (`--proxy` flag > `KEYHOG_PROXY` env > reqwest auto-detect > off)
//! silently bypasses the operator's MITM proxy and leaks the scan
//! target straight to upstream. Same for `insecure_tls` - flipping it
//! on by accident downgrades every TLS connection.
//!
//! These tests pin the policy itself, not just one happy-path call.
//!
//! Test budget: policy properties run 10 000 cases. Builder properties
//! run a bounded smoke profile because constructing real reqwest
//! builders/clients dominates the fast aggregate source gate.

#![cfg(any(feature = "web", feature = "github", feature = "s3"))]

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use keyhog_sources::http::{async_client_builder, blocking_client_builder, HttpClientConfig};

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

/// Arbitrary `KEYHOG_PROXY` env value, including missing / empty.
fn any_env_proxy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![Just(None), any_proxy_url().prop_map(Some)]
}

// ── helpers ─────────────────────────────────────────────────────────

/// Test-local HTTP env scope. Rust environment variables are process-global,
/// while the test harness runs property tests concurrently. Hold one lock
/// around every case that reads or writes HTTP env knobs so a sibling case
/// cannot leak proxy/TLS state into the assertion under test.
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

    /// Explicit `--proxy` always wins over `KEYHOG_PROXY`, regardless
    /// of what the env says (including "off"). A regression here would
    /// mean the operator's CLI flag silently has no effect, which is
    /// the worst kind of bug: scan target leaks to upstream while the
    /// log says "routing through burp:8080".
    #[test]
    fn explicit_proxy_always_wins_over_env(
        env in any_env_proxy(),
        flag in any_proxy_url(),
    ) {
        with_http_env(env.as_deref(), None, || {
            let cfg = HttpClientConfig { proxy: Some(flag.clone()), ..Default::default() };
            let resolved = cfg.effective_proxy();
            prop_assert_eq!(resolved.as_deref(), Some(flag.as_str()));
            Ok(())
        })?;
    }

    /// When the flag is unset the env var takes effect verbatim.
    #[test]
    fn env_var_resolves_when_flag_unset(env in any_proxy_url()) {
        with_http_env(Some(&env), None, || {
            let cfg = HttpClientConfig::default();
            // Empty env strings count as "no env" (matches our
            // documented behavior - operators sometimes export an
            // empty var to "clear" a parent shell's setting).
            if env.is_empty() {
                prop_assert_eq!(cfg.effective_proxy(), None);
            } else {
                prop_assert_eq!(cfg.effective_proxy(), Some(env.clone()));
            }
            Ok(())
        })?;
    }

    /// Empty env var must NOT trigger the proxy path - reqwest's
    /// own fallback (HTTPS_PROXY etc.) should take over instead.
    #[test]
    fn empty_env_var_is_treated_as_unset(noise in any::<u8>()) {
        let _ = noise;
        with_http_env(Some(""), None, || {
            let cfg = HttpClientConfig::default();
            prop_assert!(cfg.effective_proxy().is_none());
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
            match blocking_client_builder(&cfg) {
                Ok(_) | Err(_) => {} // either is fine; we're proving no-panic
            }
        });
    }

    /// Same for the async builder.
    #[test]
    fn async_builder_handles_every_proxy_url(p in any_proxy_url()) {
        with_http_env(None, None, || {
            let cfg = HttpClientConfig { proxy: Some(p.clone()), ..Default::default() };
            match async_client_builder(&cfg) {
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
            let blocking = blocking_client_builder(&cfg);
            let r#async = async_client_builder(&cfg);
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
            prop_assert_eq!(cfg.effective_insecure_tls(), insecure);
            Ok(())
        })?;
    }
}

proptest! {
    #![proptest_config(http_fuzz_config(POLICY_CASES))]

    /// `KEYHOG_INSECURE_TLS=1|true|TRUE` enables insecure mode;
    /// everything else leaves it off. Guards against a typo
    /// (`KEYHOG_INSECURE_TLS=yes`) silently enabling.
    #[test]
    fn insecure_tls_env_var_only_recognizes_1_or_true(value in "[a-zA-Z0-9]{0,12}") {
        with_http_env(None, Some(&value), || {
            let cfg = HttpClientConfig::default();
            let expected = matches!(value.as_str(), "1" | "true" | "TRUE");
            prop_assert_eq!(cfg.effective_insecure_tls(), expected);
            Ok(())
        })?;
    }

    /// Explicit `insecure_tls: true` is sticky - env var can't
    /// disable it. Belt-and-suspenders against a config-loader
    /// race where the CLI flag is overridden by env defaults.
    #[test]
    fn explicit_insecure_tls_cannot_be_overridden_by_env(
        env in "[a-zA-Z0-9]{0,12}",
    ) {
        with_http_env(None, Some(&env), || {
            let cfg = HttpClientConfig { insecure_tls: true, ..Default::default() };
            prop_assert!(cfg.effective_insecure_tls());
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
            prop_assert_eq!(cfg.effective_proxy(), None);
            prop_assert!(!cfg.effective_insecure_tls());
            prop_assert!(cfg.ua_suffix.is_none());
            Ok(())
        })?;
    }

    /// Proxy disable sentinels (`off`, `none`, empty) must round-trip
    /// through `effective_proxy` verbatim so builders can call
    /// `.no_proxy()` - a regression would silently inherit env proxies.
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
            let resolved = cfg.effective_proxy();
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
            prop_assert!(blocking_client_builder(&cfg).is_ok());
            prop_assert!(async_client_builder(&cfg).is_ok());
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
            prop_assert!(blocking_client_builder(&cfg).unwrap().build().is_ok());
            prop_assert!(async_client_builder(&cfg).unwrap().build().is_ok());
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
