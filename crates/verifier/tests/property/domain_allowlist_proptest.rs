//! Property / invariant coverage for the verifier's egress DOMAIN ALLOWLIST
//! matcher (`domain_allowlist::host_is_allowed`, reached via the
//! `VerifierTestApi` facade — the predicate is `pub(crate)`). This is the gate
//! that decides whether a VALIDATED credential may be sent to a given host, so a
//! hole here is a direct credential-exfil vector: a host the matcher wrongly
//! allows receives a live secret, and a shared-tenant subdomain wrongly allowed
//! sends one tenant's credential to a DIFFERENT tenant's store.
//!
//! Fixed-vector coverage lives in `new_verifier_allowlist_cache` and
//! `regression_bogon_ipv6_and_tenant_suffix_gaps`; this file asserts the
//! matcher's INVARIANTS across a deterministic sweep of random hosts and
//! allowlists. Dependency-free by design (fixed-seed LCG, same convention as
//! `ssrf_ip_screen_proptest`), so any failing case is byte-for-byte reproducible.
//! Every assertion pins the exact boolean the matcher must return.

use crate::common::{lcg, rand_domain, rand_label};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

const SAMPLES: usize = 50_000;

#[test]
fn exact_apex_is_always_allowed() {
    // A domain always matches itself exactly — the `host == allowed` fast path,
    // taken even for shared-tenant suffixes (their apex is legitimate).
    let mut state = 0xA11C_0001;
    for _ in 0..SAMPLES {
        let d = rand_domain(&mut state);
        assert!(
            TestApi.host_is_allowed(&d, &[d.clone()]),
            "exact apex {d} must be allowed by itself"
        );
    }
    assert!(
        TestApi.host_is_allowed("myshopify.com", &["myshopify.com".to_string()]),
        "a shared-tenant suffix still matches its own apex exactly"
    );
}

#[test]
fn empty_host_or_empty_allowlist_is_rejected() {
    // Fail-closed: no host, no allowlist, or an allowlist of only empty/dot
    // entries licenses nothing.
    assert!(!TestApi.host_is_allowed("", &["example.com".to_string()]));
    assert!(!TestApi.host_is_allowed("api.example.com", &[]));
    assert!(!TestApi.host_is_allowed("", &[]));
    assert!(!TestApi.host_is_allowed(
        "api.example.com",
        &["".to_string(), ".".to_string(), "..".to_string()]
    ));
}

#[test]
fn matching_is_ascii_case_insensitive() {
    // The verdict must not change when either side's ASCII case changes — a
    // case-sensitive matcher would let `API.EXAMPLE.COM` bypass an `example.com`
    // allowlist (or vice-versa).
    let mut state = 0xCA5E_0002;
    for _ in 0..SAMPLES {
        let host = format!("{}.{}", rand_label(&mut state), rand_domain(&mut state));
        let d = rand_domain(&mut state);
        let base = TestApi.host_is_allowed(&host, &[d.clone()]);
        assert_eq!(
            base,
            TestApi.host_is_allowed(&host.to_uppercase(), &[d.to_uppercase()]),
            "case fold of both sides changed the verdict for host={host} allowed={d}"
        );
        assert_eq!(
            base,
            TestApi.host_is_allowed(&host.to_uppercase(), &[d.clone()]),
            "uppercasing only the host changed the verdict for host={host} allowed={d}"
        );
    }
}

#[test]
fn trailing_dots_do_not_change_the_verdict() {
    // FQDN trailing dots are stripped on both host and allowlist entry, so a
    // root-labelled `api.example.com.` is treated identically to `api.example.com`.
    let mut state = 0xD07D_0003;
    for _ in 0..SAMPLES {
        let host = format!("{}.{}", rand_label(&mut state), rand_domain(&mut state));
        let d = rand_domain(&mut state);
        let base = TestApi.host_is_allowed(&host, &[d.clone()]);
        assert_eq!(
            base,
            TestApi.host_is_allowed(&format!("{host}."), &[format!("{d}.")]),
            "trailing dots changed the verdict for host={host} allowed={d}"
        );
    }
}

#[test]
fn subdomain_of_ordinary_domain_is_allowed() {
    // An ordinary (non-shared-tenant) allowlisted domain licenses its whole
    // subtree: any depth of dot-separated labels below it is allowed.
    let mut state = 0x5B00_0005;
    let base = "example.com".to_string();
    for _ in 0..SAMPLES {
        let depth = 1 + (lcg(&mut state) % 3) as usize;
        let mut host = String::new();
        for _ in 0..depth {
            host.push_str(&rand_label(&mut state));
            host.push('.');
        }
        host.push_str(&base);
        assert!(
            TestApi.host_is_allowed(&host, &[base.clone()]),
            "subdomain {host} of ordinary {base} must be allowed"
        );
    }
}

#[test]
fn suffix_without_dot_boundary_is_not_confused_for_subdomain() {
    // The classic suffix-confusion attack: `evilexample.com` ends with
    // `example.com` but is a DIFFERENT domain. Without the dot-boundary check the
    // matcher would allow it and leak the credential. A label glued directly onto
    // the base (no separating dot) must never be treated as a subdomain.
    let mut state = 0xB0C0_0004;
    let base = "example.com".to_string();
    for _ in 0..SAMPLES {
        let glued = format!("{}{}", rand_label(&mut state), base); // e.g. "evilexample.com"
        assert!(
            !TestApi.host_is_allowed(&glued, &[base.clone()]),
            "glued suffix {glued} must NOT be treated as a subdomain of {base}"
        );
    }
}

#[test]
fn shared_tenant_suffix_allows_only_apex_never_subdomain() {
    // The anti-cross-tenant-exfil guard: a shared-tenant suffix (`myshopify.com`)
    // is a platform apex whose subdomains belong to UNRELATED tenants. The apex
    // itself is allowed, but no `{store}.myshopify.com` subdomain ever is —
    // otherwise one store's credential could be verified against another's.
    let mut state = 0x5A7E_0007;
    let shared = "myshopify.com".to_string();
    assert!(
        TestApi.host_is_allowed(&shared, &[shared.clone()]),
        "the shared-tenant apex itself is allowed"
    );
    for _ in 0..SAMPLES {
        let sub = format!("{}.{}", rand_label(&mut state), shared);
        assert!(
            !TestApi.host_is_allowed(&sub, &[shared.clone()]),
            "shared-tenant subdomain {sub} must be REJECTED (different tenant)"
        );
    }
    // Contrast: an ordinary domain DOES allow its subdomain — proving the
    // rejection above is specifically the exact-only guard, not a blanket block.
    assert!(TestApi.host_is_allowed("shop.example.com", &["example.com".to_string()]));
}

#[test]
fn adding_allowlist_entries_is_monotonic() {
    // The matcher is `.any()` over the allowlist, so adding an entry can only ADD
    // allows, never remove one. If a host was allowed by list `[a]`, it stays
    // allowed by `[a, b]` for any `b`.
    let mut state = 0x0270_0008;
    for _ in 0..SAMPLES {
        let host = format!(
            "{}.{}.{}",
            rand_label(&mut state),
            rand_label(&mut state),
            rand_label(&mut state)
        );
        let a = rand_domain(&mut state);
        let b = rand_domain(&mut state);
        if TestApi.host_is_allowed(&host, &[a.clone()]) {
            assert!(
                TestApi.host_is_allowed(&host, &[a.clone(), b.clone()]),
                "adding {b} removed the allow of {host} by {a}"
            );
        }
    }
}
