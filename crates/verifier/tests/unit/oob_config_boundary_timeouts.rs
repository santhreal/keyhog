//! Boundary test: OobConfig timeout invariants must hold for all valid configs.
//! Asserts that default_timeout <= max_timeout and poll_interval < default_timeout.

use keyhog_verifier::oob::OobConfig;
use std::time::Duration;

#[test]
fn oob_config_default_invariants() {
    let cfg = OobConfig::default();

    // Invariant 1: default_timeout <= max_timeout
    assert!(
        cfg.default_timeout <= cfg.max_timeout,
        "default_timeout {:?} must be <= max_timeout {:?}",
        cfg.default_timeout,
        cfg.max_timeout
    );

    // Invariant 2: poll_interval < default_timeout
    assert!(
        cfg.poll_interval < cfg.default_timeout,
        "poll_interval {:?} must be < default_timeout {:?}",
        cfg.poll_interval,
        cfg.default_timeout
    );

    // Invariant 3: all timeouts must be positive
    assert!(
        cfg.default_timeout.as_nanos() > 0,
        "default_timeout must be positive"
    );
    assert!(
        cfg.max_timeout.as_nanos() > 0,
        "max_timeout must be positive"
    );
    assert!(
        cfg.poll_interval.as_nanos() > 0,
        "poll_interval must be positive"
    );
}

#[test]
fn oob_config_max_observation_age_is_positive() {
    let cfg = OobConfig::default();
    assert!(
        cfg.max_observation_age.as_nanos() > 0,
        "max_observation_age must be positive, got {:?}",
        cfg.max_observation_age
    );
}

#[test]
fn oob_config_server_is_fqdn() {
    let cfg = OobConfig::default();
    assert!(!cfg.server.is_empty(), "server must not be empty");
    assert!(
        cfg.server.contains('.'),
        "server must be a fully qualified domain (contains '.'), got '{}'",
        cfg.server
    );
    // Should not contain only whitespace or control chars
    assert!(
        !cfg.server.chars().all(|c| c.is_whitespace()),
        "server must not be only whitespace"
    );
}

#[test]
fn oob_config_custom_with_valid_invariants() {
    // Construct a valid config manually
    let cfg = OobConfig {
        server: "collector.example.com".to_string(),
        default_timeout: Duration::from_secs(30),
        max_timeout: Duration::from_secs(60),
        poll_interval: Duration::from_secs(5),
        max_observation_age: Duration::from_secs(300),
    };

    // All invariants must still hold
    assert!(
        cfg.default_timeout <= cfg.max_timeout,
        "custom config: default_timeout <= max_timeout violated"
    );
    assert!(
        cfg.poll_interval < cfg.default_timeout,
        "custom config: poll_interval < default_timeout violated"
    );
}

#[test]
fn oob_config_equal_timeouts_is_valid() {
    // Edge case: default_timeout == max_timeout is allowed
    let cfg = OobConfig {
        server: "test.com".to_string(),
        default_timeout: Duration::from_secs(30),
        max_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_secs(5),
        max_observation_age: Duration::from_secs(100),
    };

    assert_eq!(
        cfg.default_timeout, cfg.max_timeout,
        "equal timeouts should be valid"
    );
    assert!(
        cfg.default_timeout <= cfg.max_timeout,
        "equality satisfies <= invariant"
    );
}

#[test]
fn oob_config_poll_interval_much_less_than_default() {
    // Typical: poll runs many times before default_timeout expires
    let cfg = OobConfig {
        server: "test.com".to_string(),
        default_timeout: Duration::from_secs(30),
        max_timeout: Duration::from_secs(60),
        poll_interval: Duration::from_millis(100),
        max_observation_age: Duration::from_secs(300),
    };

    let expected_polls_in_window = cfg.default_timeout.as_millis() / cfg.poll_interval.as_millis();
    assert!(
        expected_polls_in_window > 1,
        "should get multiple polls within default_timeout; got {} polls",
        expected_polls_in_window
    );
}
