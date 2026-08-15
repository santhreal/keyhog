//! Profiling-instrumentation contract tests for keyhog-verifier.
//!
//! Every instrumented seam in the verifier (queue scheduling, worker tasks,
//! semaphore queue waits, request construction, TLS/client setup, response
//! parse, cache hit/store, retry scheduling, domain allowlist evaluation) must
//! record the exact Stage / annotation the instrumentation contract assigns it
//! while a `keyhog_profile::Runtime` is active, and must record nothing when no
//! runtime is entered on the calling thread.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use keyhog_core::{
    CredentialHash, DedupedMatch, MatchLocation, MetadataSpec, ProviderEvidenceSensitivity,
    SensitiveString, Severity, SuccessSpec, VerificationResult, VerifySpec,
};
use keyhog_profile::{AnnotationId, Stage};
use keyhog_verifier::testing::{
    TestApi, TestVerificationCache, VerifierTestApi, VerifierTestCache,
};
use keyhog_verifier::{VerificationEngine, VerifyConfig};

/// Run `f` with a recording runtime current on this thread, then drain the
/// fixed-stage counters accumulated while it was entered.
fn measure(f: impl FnOnce()) -> Vec<keyhog_profile::StageMeasurement> {
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let measurements = runtime.scope(|| {
        f();
        keyhog_profile::take_stage_measurements()
    });
    keyhog_profile::reset();
    measurements
}

/// Total recorded calls for one stage across the drained measurements.
fn stage_calls(measurements: &[keyhog_profile::StageMeasurement], stage: Stage) -> u64 {
    measurements
        .iter()
        .filter(|measurement| measurement.stage == stage)
        .map(|measurement| measurement.calls)
        .sum()
}

/// One deduplicated match whose detector id is absent from the engine, so
/// `verify_all` resolves it to `Unverifiable` without any network I/O.
fn offline_group() -> DedupedMatch {
    DedupedMatch {
        detector_id: Arc::from("profiling-test-detector"),
        detector_name: Arc::from("Profiling Test Detector"),
        service: Arc::from("profiling-test-service"),
        severity: Severity::High,
        credential: SensitiveString::from("profiling-test-secret"),
        credential_hash: CredentialHash::ZERO,
        companions: HashMap::new(),
        primary_location: MatchLocation {
            source: Arc::from("profiling-test"),
            file_path: Some(Arc::from("fixture.txt")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        additional_locations: Vec::new(),
        entropy: None,
        confidence: Some(0.9),
        evidence: keyhog_core::EvidenceVerdict::review_unattributed(),
    }
}

/// WHY: the contract assigns verifier cache hits to `Stage::IncrementalLookup`
/// and cache stores to `Stage::ResultMerge`, with a miss deliberately silent so
/// hit-vs-miss ratios are derivable. This test locks that mapping: one store,
/// one hit, one miss must yield exactly one ResultMerge call and exactly one
/// IncrementalLookup call. A regression that spans misses (or drops the store
/// span) breaks these exact counts.
#[test]
fn cache_hit_store_and_miss_record_exact_stages() {
    let measurements = measure(|| {
        let cache = TestVerificationCache::new(Duration::from_secs(60));
        cache.put(
            "secret",
            "detector",
            VerificationResult::Live,
            HashMap::new(),
        );
        assert!(cache.get("secret", "detector").is_some());
        assert!(cache.get("absent", "detector").is_none());
    });
    assert_eq!(stage_calls(&measurements, Stage::ResultMerge), 1);
    assert_eq!(stage_calls(&measurements, Stage::IncrementalLookup), 1);
}

/// WHY: domain-allowlist enforcement is suppression-stage policy work per the
/// contract. Both the accept and the refuse outcome pass through
/// `check_url_against_spec`, so two evaluations must record exactly two
/// `Stage::Suppression` calls. Locks out a regression that only instruments
/// one outcome arm.
#[test]
fn domain_allowlist_evaluation_records_suppression() {
    let measurements = measure(|| {
        let spec = VerifySpec {
            service: "github".into(),
            allowed_domains: vec![],
            ..VerifySpec::default()
        };
        assert!(TestApi
            .check_url_against_spec("https://api.github.com/user", &spec)
            .is_ok());
        assert!(TestApi
            .check_url_against_spec("https://attacker.example.com/exfil", &spec)
            .is_err());
    });
    assert_eq!(stage_calls(&measurements, Stage::Suppression), 2);
}

/// WHY: response parsing (success contract, error backstop, provider-evidence
/// extraction, AWS STS XML/JSON parse, STS failure classification) is
/// live-verification parse work per the contract. One call to each of the five
/// parse seams must record exactly five `Stage::LiveVerification` calls. Locks
/// out a dropped span at any single parse site.
#[test]
fn response_parse_sites_record_live_verification() {
    let measurements = measure(|| {
        assert!(TestApi.body_indicates_error_for_test("{\"error\": \"boom\"}"));
        let success = SuccessSpec {
            status: Some(200),
            json_path: Some("$.ok".into()),
            ..SuccessSpec::default()
        };
        assert!(TestApi.evaluate_success_for_test(&success, 200, "{\"ok\": true}"));
        let specs = [MetadataSpec {
            name: "account_id".into(),
            json_path: "$.account".into(),
            sensitivity: ProviderEvidenceSensitivity::Public,
        }];
        assert!(TestApi
            .extract_metadata_for_test(&specs, "{\"account\": \"12345\"}")
            .is_ok());
        let sts_body = "{\"GetCallerIdentityResponse\":{\"GetCallerIdentityResult\":\
             {\"Arn\":\"arn:aws:iam::123456789012:user/test\",\
             \"Account\":\"123456789012\",\"UserId\":\"AIDATEST\"}}}";
        assert!(TestApi.parse_aws_sts_success_metadata(sts_body).is_ok());
        let (verdict, _) = TestApi.classify_aws_sts_failure(403, "AccessDenied");
        assert!(matches!(verdict, VerificationResult::Dead));
    });
    assert_eq!(stage_calls(&measurements, Stage::LiveVerification), 5);
}

/// WHY: outbound request construction (header/body template interpolation into
/// the `reqwest::RequestBuilder`) is a sync live-verification seam per the
/// contract. One built request must record exactly one
/// `Stage::LiveVerification` call, without any network I/O. Locks out a
/// regression that drops the construction span from
/// `apply_header_body_templates`.
#[test]
fn request_construction_records_live_verification() {
    let measurements = measure(|| {
        let (headers, body) = TestApi.built_request_header_body_for_test(
            &[("authorization", "Bearer {{match}}")],
            Some("token={{match}}"),
            "secret",
            &HashMap::new(),
        );
        assert_eq!(headers.len(), 1);
        assert!(body.is_some());
    });
    assert_eq!(stage_calls(&measurements, Stage::LiveVerification), 1);
}

/// WHY: the DNS-pinned TLS client build is the verifier's TLS/client-setup
/// seam per the contract. After clearing the pinned-client cache, one pinned
/// build must record exactly one `Stage::LiveVerification` call. Locks out a
/// regression that drops the span from `build_pinned_client` (the cache makes
/// a second uncleaned build silent, which is why the cache is cleared first).
#[test]
fn pinned_client_build_records_live_verification() {
    let measurements = measure(|| {
        TestApi.clear_pinned_request_client_cache();
        let addrs = [SocketAddr::from(([127, 0, 0, 1], 443))];
        assert!(TestApi
            .pinned_request_client_for_test(
                "profiling-pin-keyhog.invalid",
                &addrs,
                Duration::from_millis(10),
                false,
            )
            .is_ok());
    });
    assert_eq!(stage_calls(&measurements, Stage::LiveVerification), 1);
}

/// WHY: the contract requires async verification sections to use
/// `instrument_future` (a sync `Span` guard cannot cross `.await` in a Send
/// future). Wrapping a stub future must record exactly one
/// `Stage::LiveVerification` call and pass the output through unchanged,
/// proving the wiring used by the real send/read paths. Locks out a
/// regression where the wrapper stops recording or alters the output.
#[tokio::test]
async fn instrument_future_records_async_verify_work() {
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let guard = runtime.enter();
    let value = keyhog_profile::instrument_future(Stage::LiveVerification, async { 7_u8 }).await;
    assert_eq!(value, 7);
    let measurements = keyhog_profile::take_stage_measurements();
    drop(guard);
    keyhog_profile::reset();
    assert_eq!(stage_calls(&measurements, Stage::LiveVerification), 1);
}

/// WHY: the engine's queue paths must emit `AnnotationId::QueueDepth` at every
/// scheduling decision and each spawned worker plus its two semaphore queue
/// waits must land in `Stage::LiveVerification`, with the verdict cache store
/// in `Stage::ResultMerge`. One offline group (unknown detector, so no network)
/// yields exactly: 2 queue-depth annotations (initial fill loop records
/// pending+in-flight depth 1 twice: once before the spawn, once before the
/// loop sees the drained iterator), 3 LiveVerification calls (task wrapper +
/// global + service permit acquire), 1 ResultMerge call (Unverifiable is
/// cacheable), and 0 IncrementalLookup calls (both cache probes miss).
/// Multi-thread flavor proves `instrument_future` propagates the runtime
/// across worker threads. Locks out regressions in queue-depth accounting and
/// in the async task/acquire wrapping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_verify_all_records_queue_and_worker_stages() {
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let guard = runtime.enter();

    let engine = VerificationEngine::new(&[], VerifyConfig::default())
        .expect("offline engine construction must succeed");
    let findings = engine.verify_all(vec![offline_group()]).await;

    let measurements = keyhog_profile::take_stage_measurements();
    let (_, annotations, _) = runtime.take_session_typed_events();
    drop(guard);
    keyhog_profile::reset();

    assert_eq!(findings.len(), 1);
    assert!(matches!(
        findings[0].verification,
        VerificationResult::Unverifiable
    ));
    assert_eq!(stage_calls(&measurements, Stage::LiveVerification), 3);
    assert_eq!(stage_calls(&measurements, Stage::ResultMerge), 1);
    assert_eq!(stage_calls(&measurements, Stage::IncrementalLookup), 0);
    let queue_depths: Vec<u64> = annotations
        .iter()
        .filter(|annotation| annotation.annotation_id == AnnotationId::QueueDepth)
        .map(|annotation| annotation.value)
        .collect();
    assert_eq!(queue_depths, vec![1, 1]);
}

/// WHY: the contract assigns retry scheduling to
/// `AnnotationId::RetryAttempt`. The metadata-preservation fixture drives the
/// real retry loop through two transient attempts, so exactly one retry is
/// scheduled (attempt index 1) and exactly one annotation with value 1 must be
/// recorded. Locks out a regression that annotates the initial attempt or
/// drops the annotation from the backoff path.
#[tokio::test]
async fn retry_loop_records_retry_attempt_annotation() {
    keyhog_profile::reset();
    let runtime = keyhog_profile::Runtime::new();
    let guard = runtime.enter();

    let (result, _) = TestApi.retry_loop_preserves_metadata_on_exhaustion().await;

    let (_, annotations, _) = runtime.take_session_typed_events();
    drop(guard);
    keyhog_profile::reset();

    assert!(matches!(result, VerificationResult::Error(_)));
    let retries: Vec<u64> = annotations
        .iter()
        .filter(|annotation| annotation.annotation_id == AnnotationId::RetryAttempt)
        .map(|annotation| annotation.value)
        .collect();
    assert_eq!(retries, vec![1]);
}

/// WHY: instrumentation must be silent without an active runtime so production
/// runs pay no recording cost and produce no measurements. Driving the sync
/// instrumented paths (cache store/hit, allowlist evaluation, response parse,
/// request construction) with no runtime entered must drain zero calls for
/// every stage they use. Locks out a regression that records unconditionally.
#[test]
fn sync_paths_are_silent_without_runtime() {
    keyhog_profile::reset();
    let cache = TestVerificationCache::new(Duration::from_secs(60));
    cache.put(
        "secret",
        "detector",
        VerificationResult::Live,
        HashMap::new(),
    );
    assert!(cache.get("secret", "detector").is_some());
    let spec = VerifySpec {
        service: "github".into(),
        allowed_domains: vec![],
        ..VerifySpec::default()
    };
    assert!(TestApi
        .check_url_against_spec("https://api.github.com/user", &spec)
        .is_ok());
    assert!(TestApi.body_indicates_error_for_test("{\"error\": \"boom\"}"));
    let (headers, _) = TestApi.built_request_header_body_for_test(
        &[("authorization", "Bearer {{match}}")],
        None,
        "secret",
        &HashMap::new(),
    );
    assert_eq!(headers.len(), 1);

    let measurements = keyhog_profile::take_stage_measurements();
    keyhog_profile::reset();
    assert_eq!(stage_calls(&measurements, Stage::IncrementalLookup), 0);
    assert_eq!(stage_calls(&measurements, Stage::ResultMerge), 0);
    assert_eq!(stage_calls(&measurements, Stage::Suppression), 0);
    assert_eq!(stage_calls(&measurements, Stage::LiveVerification), 0);
}

/// WHY: the async engine path must be equally silent without an active
/// runtime: `instrument_future` wrappers and queue annotations record nothing
/// when no runtime is current, so an uninstrumented production scan is
/// measurement-free. Same offline fixture as the recording test; drains zero
/// calls for every stage the path uses when active. Locks out a regression
/// where the async wrappers record unconditionally.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_engine_path_is_silent_without_runtime() {
    keyhog_profile::reset();
    let engine = VerificationEngine::new(&[], VerifyConfig::default())
        .expect("offline engine construction must succeed");
    let findings = engine.verify_all(vec![offline_group()]).await;
    assert_eq!(findings.len(), 1);

    let measurements = keyhog_profile::take_stage_measurements();
    keyhog_profile::reset();
    assert_eq!(stage_calls(&measurements, Stage::LiveVerification), 0);
    assert_eq!(stage_calls(&measurements, Stage::ResultMerge), 0);
    assert_eq!(stage_calls(&measurements, Stage::IncrementalLookup), 0);
}
