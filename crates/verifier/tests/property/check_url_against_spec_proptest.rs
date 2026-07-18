//! Property / invariant coverage for the verifier's TOP-LEVEL egress guard
//! (`domain_allowlist::check_url_against_spec`, reached via the `VerifierTestApi`
//! facade). This is the single call every live-verification request passes
//! through before a VALIDATED credential is sent anywhere, so it is the last
//! line against credential exfiltration. It composes three decisions:
//!   1. the verify URL must PARSE,
//!   2. the detector's service must HAVE a domain allowlist, and
//!   3. the URL's parsed HOST must be IN that allowlist.
//! A gap in the composition sends a live secret to an unlicensed host.
//!
//! The primitives (`effective_allowlist`, `host_is_allowed`) have their own
//! fixed-vector + property coverage; this file locks the COMPOSED entry point:
//! that it equals `host_is_allowed` over the effective allowlist, fails closed
//! when no allowlist is configured or the URL cannot be parsed, and, crucially
//!, screens the PARSED host, defeating userinfo/appended-suffix host-confusion
//! evasions. Dependency-free fixed-seed LCG, same convention as the sibling
//! property files.

use crate::common::{lcg, rand_domain, rand_label};
use keyhog_core::VerifySpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

const SAMPLES: usize = 20_000;

/// A spec with an explicit allowlist and an EMPTY service, so no builtin service
/// domains merge in: `effective_allowlist` returns exactly `domains`, making the
/// composition equivalence below exact.
fn spec_with_domains(domains: Vec<String>) -> VerifySpec {
    VerifySpec {
        allowed_domains: domains,
        ..VerifySpec::default()
    }
}

#[test]
fn entry_point_equals_host_is_allowed_over_the_allowlist() {
    // With an explicit allowlist configured, the composed guard's verdict is
    // EXACTLY `host_is_allowed(parsed_host, allowlist)`. The host is drawn to mix
    // apex (allow), subdomain (allow), and unrelated (deny) cases so both the
    // Ok and Err branches are exercised densely. Hosts are lowercase-letter
    // labels, so `Url::host_str()` returns them verbatim.
    let mut state = 0xC0DE_0001;
    let mut ok_seen = 0usize;
    let mut err_seen = 0usize;
    for _ in 0..SAMPLES {
        let base = rand_domain(&mut state);
        let host = match lcg(&mut state) % 3 {
            0 => base.clone(),
            1 => format!("{}.{}", rand_label(&mut state), base),
            _ => rand_domain(&mut state),
        };
        let spec = spec_with_domains(vec![base.clone()]);
        let url = format!("https://{host}/some/path?q=1");
        let via_entry = TestApi.check_url_against_spec(&url, &spec).is_ok();
        let via_primitive = TestApi.host_is_allowed(&host, &[base.clone()]);
        assert_eq!(
            via_entry, via_primitive,
            "entry/primitive disagree: host={host} base={base}"
        );
        if via_entry {
            ok_seen += 1;
        } else {
            err_seen += 1;
        }
    }
    // Both verdict branches must actually occur, or the equivalence proved little.
    assert!(ok_seen > 100, "too few Ok verdicts ({ok_seen})");
    assert!(err_seen > 100, "too few Err verdicts ({err_seen})");
}

#[test]
fn no_configured_allowlist_fails_closed_for_any_url() {
    // A service with neither explicit domains nor a builtin allowlist licenses
    // NOTHING: every URL is blocked (fail-closed), even benign public ones.
    let spec = VerifySpec::default();
    assert!(
        TestApi.effective_allowlist(&spec).is_none(),
        "precondition: empty spec has no effective allowlist"
    );
    for url in [
        "https://example.com/",
        "https://api.internal.test/x",
        "https://8.8.8.8/",
        "http://localhost/",
    ] {
        assert!(
            TestApi.check_url_against_spec(url, &spec).is_err(),
            "a service with no allowlist must block every URL: {url}"
        );
    }
}

#[test]
fn unparseable_or_hostless_url_fails_closed() {
    // Even WITH a valid allowlist, a URL that cannot be parsed or carries no host
    // is blocked (the guard never falls open on a malformed target).
    let spec = spec_with_domains(vec!["api.example.com".to_string()]);
    for bad in [
        "not a url",
        "://missing-scheme",
        "http://",
        "",
        "   ",
        "ht!tp://api.example.com/",
    ] {
        assert!(
            TestApi.check_url_against_spec(bad, &spec).is_err(),
            "unparseable/hostless URL must fail closed: {bad:?}"
        );
    }

    let hostless = TestApi
        .check_url_against_spec("mailto:security@example.com", &spec)
        .expect_err("a parseable URL without a host must be blocked");
    assert_eq!(hostless, "blocked: verify URL has no host");
}

#[test]
fn parsed_host_defeats_host_confusion_evasions() {
    // The guard screens the PARSED host, not the raw string, so classic
    // host-confusion exfil vectors are all blocked while the legitimate exact and
    // subdomain hosts are allowed.
    let spec = spec_with_domains(vec!["api.example.com".to_string()]);

    // Legitimate: exact apex and a real subdomain.
    assert!(TestApi
        .check_url_against_spec("https://api.example.com/v1/keys", &spec)
        .is_ok());
    assert!(TestApi
        .check_url_against_spec("https://eu.api.example.com/v1", &spec)
        .is_ok());

    // Appended-suffix confusion: the allowed name is only a PREFIX of the real
    // host, which belongs to the attacker.
    assert!(TestApi
        .check_url_against_spec("https://api.example.com.attacker.io/", &spec)
        .is_err());
    // The allowed name appears only in the path (the real host is the attacker).
    assert!(TestApi
        .check_url_against_spec("https://attacker.io/api.example.com", &spec)
        .is_err());
    // Userinfo trick: everything before `@` is credentials, the real host is
    // `attacker.io`. A raw-string matcher would be fooled; the parsed-host guard
    // is not.
    assert!(TestApi
        .check_url_against_spec("https://api.example.com@attacker.io/", &spec)
        .is_err());
    // A different-tenant sibling under a shared prefix is not a subdomain.
    assert!(TestApi
        .check_url_against_spec("https://notapi.example.com/", &spec)
        .is_err());
}
