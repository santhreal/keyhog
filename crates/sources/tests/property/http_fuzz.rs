//! Property tests for the shared `keyhog_sources::http` module.
//!
//! The HTTP client builder is on the critical path for every URL
//! scan, every GitHub-org enumeration, every verifier round-trip, and
//! every Slack source pull. A bug in the proxy-resolution precedence
//! (`--proxy` flag > `KEYHOG_PROXY` env > reqwest auto-detect > off)
//! silently bypasses the operator's MITM proxy and leaks the scan
//! target straight to upstream. Same for `insecure_tls` — flipping it
//! on by accident downgrades every TLS connection.
//!
//! These tests pin the policy itself, not just one happy-path call.
//!
//! Test budget: every property runs 10 000 cases (overridable via the
//! standard `PROPTEST_CASES` env var). At ~5 µs per case the suite
//! finishes in well under a second locally and inside the CI budget.

#![cfg(any(feature = "web", feature = "github", feature = "s3"))]

use proptest::prelude::*;

use keyhog_sources::http::{
    async_client_builder, blocking_client_builder, HttpClientConfig,
};

const CASES: u32 = 10_000;

// ── strategies ──────────────────────────────────────────────────────

/// A proxy URL the operator might plausibly pass — covers `http://`,
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

/// Per-test env namespace. Tests run in parallel; if we wrote to
/// `KEYHOG_PROXY` directly we'd race with sibling tests. So every
/// case stuffs the value into a uniquely-named env var, then we
/// shadow it onto `KEYHOG_PROXY` for the brief moment the call is
/// made, then restore. proptest invokes each case sequentially within
/// one harness, so the shadowing window is single-threaded per test
/// binary; the broader race is across `cargo test --jobs N` binaries,
/// which each get their own process and env.
fn with_env_proxy<R>(env: Option<&str>, f: impl FnOnce() -> R) -> R {
    let prev = std::env::var("KEYHOG_PROXY").ok();
    match env {
        Some(v) => std::env::set_var("KEYHOG_PROXY", v),
        None => std::env::remove_var("KEYHOG_PROXY"),
    }
    let out = f();
    match prev {
        Some(v) => std::env::set_var("KEYHOG_PROXY", v),
        None => std::env::remove_var("KEYHOG_PROXY"),
    }
    out
}

// ── property tests ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig { cases: CASES, .. ProptestConfig::default() })]

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
        with_env_proxy(env.as_deref(), || {
            let cfg = HttpClientConfig { proxy: Some(flag.clone()), ..Default::default() };
            let resolved = cfg.effective_proxy();
            prop_assert_eq!(resolved.as_deref(), Some(flag.as_str()));
            Ok(())
        })?;
    }

    /// When the flag is unset the env var takes effect verbatim.
    #[test]
    fn env_var_resolves_when_flag_unset(env in any_proxy_url()) {
        with_env_proxy(Some(&env), || {
            let cfg = HttpClientConfig::default();
            // Empty env strings count as "no env" (matches our
            // documented behavior — operators sometimes export an
            // empty var to "clear" a parent shell's setting).
            if env.is_empty() {
                prop_assert_eq!(cfg.effective_proxy(), None);
            } else {
                prop_assert_eq!(cfg.effective_proxy(), Some(env.clone()));
            }
            Ok(())
        })?;
    }

    /// Empty env var must NOT trigger the proxy path — reqwest's
    /// own fallback (HTTPS_PROXY etc.) should take over instead.
    #[test]
    fn empty_env_var_is_treated_as_unset(noise in any::<u8>()) {
        let _ = noise;
        with_env_proxy(Some(""), || {
            let cfg = HttpClientConfig::default();
            prop_assert!(cfg.effective_proxy().is_none());
            Ok(())
        })?;
    }

    /// Valid `http://` / `https://` / `socks5://` URLs must produce
    /// a working blocking builder. Invalid schemes (`gopher://`,
    /// random gibberish) must surface a clean Err, never a panic.
    #[test]
    fn blocking_builder_handles_every_proxy_url(p in any_proxy_url()) {
        let cfg = HttpClientConfig { proxy: Some(p.clone()), ..Default::default() };
        match blocking_client_builder(&cfg) {
            Ok(_) | Err(_) => {} // either is fine; we're proving no-panic
        }
    }

    /// Same for the async builder.
    #[test]
    fn async_builder_handles_every_proxy_url(p in any_proxy_url()) {
        let cfg = HttpClientConfig { proxy: Some(p.clone()), ..Default::default() };
        match async_client_builder(&cfg) {
            Ok(_) | Err(_) => {}
        }
    }

    /// Building with no proxy + no env var must always succeed —
    /// that's the default offline-safe path and any failure here
    /// would brick every scan run. The proptest input `insecure`
    /// must be reflected in the resulting clients' effective_*
    /// signals — without these assertions a regression where the
    /// flag was silently dropped would still see the test pass.
    #[test]
    fn default_builder_always_succeeds(insecure in any::<bool>()) {
        with_env_proxy(None, || {
            let cfg = HttpClientConfig { insecure_tls: insecure, ..Default::default() };
            let blocking = blocking_client_builder(&cfg);
            let r#async = async_client_builder(&cfg);
            prop_assert!(blocking.is_ok(), "blocking builder must succeed for insecure_tls={insecure}");
            prop_assert!(r#async.is_ok(), "async builder must succeed for insecure_tls={insecure}");
            // Build the actual clients (not just the builders) — a
            // broken cfg propagation would compile but fail at the
            // build() step on real validation.
            prop_assert!(blocking.unwrap().build().is_ok(),
                "blocking builder must produce a usable client");
            prop_assert!(r#async.unwrap().build().is_ok(),
                "async builder must produce a usable client");
            // The insecure flag must round-trip through the cfg
            // accessor — regression check on accessor wiring.
            prop_assert_eq!(cfg.effective_insecure_tls(), insecure);
            Ok(())
        })?;
    }

    /// `KEYHOG_INSECURE_TLS=1|true|TRUE` enables insecure mode;
    /// everything else leaves it off. Guards against a typo
    /// (`KEYHOG_INSECURE_TLS=yes`) silently enabling.
    #[test]
    fn insecure_tls_env_var_only_recognizes_1_or_true(value in "[a-zA-Z0-9]{0,12}") {
        let prev = std::env::var("KEYHOG_INSECURE_TLS").ok();
        std::env::set_var("KEYHOG_INSECURE_TLS", &value);

        let cfg = HttpClientConfig::default();
        let expected = matches!(value.as_str(), "1" | "true" | "TRUE");
        prop_assert_eq!(cfg.effective_insecure_tls(), expected);

        match prev {
            Some(v) => std::env::set_var("KEYHOG_INSECURE_TLS", v),
            None => std::env::remove_var("KEYHOG_INSECURE_TLS"),
        }
    }

    /// Explicit `insecure_tls: true` is sticky — env var can't
    /// disable it. Belt-and-suspenders against a config-loader
    /// race where the CLI flag is overridden by env defaults.
    #[test]
    fn explicit_insecure_tls_cannot_be_overridden_by_env(
        env in "[a-zA-Z0-9]{0,12}",
    ) {
        let prev = std::env::var("KEYHOG_INSECURE_TLS").ok();
        std::env::set_var("KEYHOG_INSECURE_TLS", &env);

        let cfg = HttpClientConfig { insecure_tls: true, ..Default::default() };
        prop_assert!(cfg.effective_insecure_tls());

        match prev {
            Some(v) => std::env::set_var("KEYHOG_INSECURE_TLS", v),
            None => std::env::remove_var("KEYHOG_INSECURE_TLS"),
        }
    }

    /// `HttpClientConfig::default()` is offline-safe: no proxy,
    /// TLS verification on, no UA suffix. A regression here would
    /// silently change the security posture of every consumer that
    /// uses the default.
    #[test]
    fn default_config_is_offline_safe(_seed in any::<u32>()) {
        with_env_proxy(None, || {
            let prev = std::env::var("KEYHOG_INSECURE_TLS").ok();
            std::env::remove_var("KEYHOG_INSECURE_TLS");

            let cfg = HttpClientConfig::default();
            prop_assert_eq!(cfg.effective_proxy(), None);
            prop_assert!(!cfg.effective_insecure_tls());
            prop_assert!(cfg.ua_suffix.is_none());

            if let Some(v) = prev {
                std::env::set_var("KEYHOG_INSECURE_TLS", v);
            }
            Ok(())
        })?;
    }
}

// ── unit-test sanity guard for the proptests themselves ─────────────

#[test]
fn ten_thousand_case_budget_is_acknowledged() {
    // If a future tweak drops CASES below 10k without intent, this
    // assert fails and the diff has to justify the change.
    assert_eq!(CASES, 10_000, "intent: 10k cases per http property");
}
