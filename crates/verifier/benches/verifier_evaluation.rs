use criterion::{criterion_group, criterion_main, Criterion};
use keyhog_core::json_selector;
use keyhog_core::VerificationResult;
use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_url};
use keyhog_verifier::testing::{
    aws_uri_encode, canonical_query_string, TestApi, TestVerificationCache, VerifierTestApi,
    VerifierTestCache,
};
use std::collections::HashMap;
use std::hint::black_box;
use std::net::IpAddr;
use std::time::Duration;

/// WHY: Measures live verification template interpolation and field sanitization latency,
/// ensuring dynamic URL/Header/Body generation per finding remains sub-microsecond.
fn bench_template_interpolation(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier_template_interpolation");

    let mut companions = HashMap::new();
    companions.insert("account_id".to_string(), "123456789012".to_string());
    companions.insert("region".to_string(), "us-east-1".to_string());
    companions.insert("tenant".to_string(), "acme-corp".to_string());

    let match_val = "AKIAIOSFODNN7EXAMPLE";
    let url_template = "https://api.{{companion.tenant}}.example.com/v1/accounts/{{companion.account_id}}/keys/{{match}}";
    let header_template = "Bearer {{match}}:{{companion.account_id}}";

    group.bench_function("interpolate_url", |b| {
        b.iter(|| {
            let res = TestApi.interpolate_url(
                black_box(url_template),
                black_box(match_val),
                black_box(&companions),
            );
            let _ = black_box(res);
        });
    });

    group.bench_function("interpolate_http_value", |b| {
        b.iter(|| {
            let res = TestApi.interpolate_http_value(
                black_box(header_template),
                black_box(match_val),
                black_box(&companions),
            );
            let _ = black_box(res);
        });
    });

    group.bench_function("resolve_field", |b| {
        b.iter(|| {
            let res = TestApi.resolve_field(
                black_box("companion.account_id"),
                black_box(match_val),
                black_box(&companions),
            );
            let _ = black_box(res);
        });
    });

    group.finish();
}

/// WHY: Measures JSON response parsing, selector extraction, and metadata extraction
/// over API response payloads.
fn bench_response_selection_and_classification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier_response_selection");

    let selector_str = "$.data.user.organizations[0].membership.role";
    json_selector::validate(selector_str).expect("validate selector");

    let response_json: serde_json::Value = serde_json::json!({
        "status": "ok",
        "data": {
            "user": {
                "id": "usr_987654",
                "email": "developer@company.local",
                "organizations": [
                    {
                        "id": "org_112233",
                        "name": "Acme Engineering",
                        "membership": {
                            "role": "admin",
                            "active": true
                        }
                    }
                ]
            }
        }
    });

    group.bench_function("json_selector_validate", |b| {
        b.iter(|| {
            let sel = json_selector::validate(black_box(selector_str));
            let _ = black_box(sel);
        });
    });

    group.bench_function("json_selector_select_value", |b| {
        b.iter(|| {
            let val = json_selector::select(black_box(&response_json), black_box(selector_str));
            let _ = black_box(val);
        });
    });

    group.finish();
}

/// WHY: Measures concurrent in-memory verification cache lookups, insertions,
/// and LRU/expired eviction throughput.
fn bench_verification_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier_cache_operations");

    let cache = TestVerificationCache::with_max_entries(Duration::from_secs(300), 5000);

    for i in 0..1000 {
        let cred = format!("cred_key_{i:04}");
        cache.put(
            &cred,
            "aws-access-key",
            VerificationResult::Live,
            HashMap::new(),
        );
    }

    group.bench_function("cache_get_hit", |b| {
        b.iter(|| {
            let hit = cache.get(black_box("cred_key_0500"), black_box("aws-access-key"));
            let _ = black_box(hit);
        });
    });

    group.bench_function("cache_get_miss", |b| {
        b.iter(|| {
            let miss = cache.get(black_box("nonexistent_cred"), black_box("aws-access-key"));
            let _ = black_box(miss);
        });
    });

    group.bench_function("cache_put_new_entry", |b| {
        let mut counter = 10000;
        b.iter(|| {
            counter += 1;
            let cred = format!("cred_bench_{counter}");
            cache.put(
                black_box(&cred),
                black_box("github-token"),
                black_box(VerificationResult::Live),
                HashMap::new(),
            );
        });
    });

    group.finish();
}

/// WHY: Measures SSRF screening, bogon detection, and domain allowlist matching latency
/// to ensure every network verification probe is safely evaluated without bottlenecking.
fn bench_ssrf_and_domain_policy(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier_ssrf_and_domain_policy");

    let urls = [
        "https://api.github.com/user",
        "https://api.stripe.com/v1/charges",
        "https://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "https://10.0.1.50/internal",
        "https://[::1]/status",
        "https://api.slack.com/api/auth.test",
    ];

    let ips: [IpAddr; 6] = [
        "8.8.8.8".parse().unwrap(),
        "127.0.0.1".parse().unwrap(),
        "10.0.0.1".parse().unwrap(),
        "169.254.169.254".parse().unwrap(),
        "2001:4860:4860::8888".parse().unwrap(),
        "::1".parse().unwrap(),
    ];

    let allowlist = vec![
        "github.com".to_string(),
        "stripe.com".to_string(),
        "slack.com".to_string(),
    ];

    group.bench_function("is_private_url_batch", |b| {
        b.iter(|| {
            for url in &urls {
                let blocked = is_private_url(black_box(url));
                let _ = black_box(blocked);
            }
        });
    });

    group.bench_function("is_private_ip_addr_batch", |b| {
        b.iter(|| {
            for ip in &ips {
                let blocked = is_private_ip_addr(black_box(ip));
                let _ = black_box(blocked);
            }
        });
    });

    group.bench_function("host_is_allowed_matching", |b| {
        b.iter(|| {
            let allowed_gh =
                TestApi.host_is_allowed(black_box("api.github.com"), black_box(&allowlist));
            let allowed_stripe =
                TestApi.host_is_allowed(black_box("hooks.stripe.com"), black_box(&allowlist));
            let allowed_evil =
                TestApi.host_is_allowed(black_box("evil.internal.local"), black_box(&allowlist));
            let _ = black_box((allowed_gh, allowed_stripe, allowed_evil));
        });
    });

    group.finish();
}

/// WHY: Measures AWS SigV4 canonical URI encoding, query string sorting, and format conversions.
fn bench_sigv4_canonicalization(c: &mut Criterion) {
    let mut group = c.benchmark_group("verifier_sigv4_canonicalization");

    let raw_uri = "/v1/projects/my-proj:runJob/tasks/task-001 with spaces & symbols";
    let query_params = vec![
        ("Action".to_string(), "GetCallerIdentity".to_string()),
        ("Version".to_string(), "2011-06-15".to_string()),
        (
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ),
        (
            "X-Amz-Credential".to_string(),
            "AKIAIOSFODNN7EXAMPLE/20260819/us-east-1/sts/aws4_request".to_string(),
        ),
    ];

    group.bench_function("aws_uri_encode", |b| {
        b.iter(|| {
            let encoded = aws_uri_encode(black_box(raw_uri));
            let _ = black_box(encoded);
        });
    });

    group.bench_function("canonical_query_string", |b| {
        b.iter(|| {
            let qs = canonical_query_string(black_box(&query_params));
            let _ = black_box(qs);
        });
    });

    group.bench_function("format_sigv4_timestamps", |b| {
        b.iter(|| {
            let (date, datetime) = TestApi.format_sigv4_timestamps(black_box(1787140800));
            let _ = black_box((date, datetime));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_template_interpolation,
    bench_response_selection_and_classification,
    bench_verification_cache_operations,
    bench_ssrf_and_domain_policy,
    bench_sigv4_canonicalization,
);
criterion_main!(benches);
