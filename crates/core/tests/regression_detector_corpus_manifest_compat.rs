//! KH-1263 compatibility contract for directory-scoped detector corpora.
//!
//! A canonical manifest makes bounded forward skew classifiable without
//! weakening current/legacy typo guards. Production loads reject every newer
//! declared schema to preserve complete recall and schema-bound identity; only
//! the explicit gate-off authoring path may inspect compatible siblings while
//! skipping whole incompatible detectors.

use std::path::Path;

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{
    load_detector_corpus, load_detectors, DetectorCorpusManifest, SpecError, SuccessPolicy,
    DETECTOR_CORPUS_MANIFEST_FILE, DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION,
    DETECTOR_CORPUS_MIN_SCHEMA_VERSION, DETECTOR_CORPUS_SCHEMA_VERSION,
};

const VALID_DETECTOR: &str = r#"
[detector]
id = "current"
name = "Current"
service = "current"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["current_"]

[[detector.patterns]]
regex = "current_[A-Z0-9]{8}"
"#;

const FUTURE_DETECTOR: &str = r#"
[detector]
id = "future"
name = "Future"
service = "future"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
future_only = { knob = 1 }
keywords = ["future_"]

[[detector.patterns]]
regex = "future_[A-Z0-9]{8}"
"#;

fn write_detector(dir: &Path, name: &str, body: &str) {
    let source = keyhog_core::testing::detector_toml_with_fixture_confidence(body);
    std::fs::write(dir.join(name), source).expect("write detector fixture");
}

fn write_manifest(dir: &Path, body: &str) {
    std::fs::write(dir.join(DETECTOR_CORPUS_MANIFEST_FILE), body)
        .expect("write corpus manifest fixture");
}

fn strict_rejection_detail(error: SpecError) -> String {
    match error {
        SpecError::DetectorCorpusRejected { detail, .. } => detail,
        other => panic!("expected DetectorCorpusRejected, got {other:?}"),
    }
}
fn effective_digest(detectors_dir: &Path, manifest_override: Option<&str>) -> String {
    let mut detector_paths = std::fs::read_dir(detectors_dir)
        .expect("read detector corpus")
        .map(|entry| entry.expect("read detector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "toml")
                && path
                    .file_name()
                    .is_some_and(|name| name != DETECTOR_CORPUS_MANIFEST_FILE)
        })
        .collect::<Vec<_>>();
    detector_paths.sort();

    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut mix = |bytes: &[u8]| {
        for &byte in bytes {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for path in &detector_paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("UTF-8 detector file name");
        let content = std::fs::read_to_string(path).expect("read detector TOML");
        mix(name.as_bytes());
        mix(&[0]);
        mix(content.as_bytes());
        mix(&[0]);
    }
    let manifest = manifest_override.map(str::to_owned).unwrap_or_else(|| {
        std::fs::read_to_string(detectors_dir.join(DETECTOR_CORPUS_MANIFEST_FILE))
            .expect("read corpus manifest")
    });
    mix(DETECTOR_CORPUS_MANIFEST_FILE.as_bytes());
    mix(&[0]);
    mix(manifest.as_bytes());
    mix(&[0]);
    format!("{}-{hash:016x}", detector_paths.len())
}

/// Regression: a current manifest is metadata, not a detector TOML, and a
/// healthy current-schema corpus must load without changing detector identity.
#[test]
fn current_manifest_loads_valid_corpus_and_is_not_counted_as_a_detector() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!("schema_version = {}\n", DETECTOR_CORPUS_SCHEMA_VERSION),
    );
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);

    let detectors = load_detectors(dir.path()).expect("current corpus must load");
    assert_eq!(detectors.len(), 1, "manifest must not enter detector count");
    assert_eq!(detectors[0].id, "current");
}

/// Regression: `deny_unknown_fields` remains load-bearing for a same-version
/// corpus; a misspelled field must fail with file/schema context and repair
/// guidance rather than silently defaulting the intended field.
#[test]
fn same_version_unknown_field_is_typo_fatal_with_repair_guidance() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!("schema_version = {}\n", DETECTOR_CORPUS_SCHEMA_VERSION),
    );
    let typo = VALID_DETECTOR.replace("severity = \"high\"", "sevrity = \"high\"");
    write_detector(dir.path(), "typo.toml", &typo);

    let detail = strict_rejection_detail(
        load_detectors(dir.path()).expect_err("same-version typo must fail closed"),
    );
    assert!(
        detail.contains("typo.toml"),
        "missing file context: {detail}"
    );
    assert!(
        detail.contains(&format!("schema {}", DETECTOR_CORPUS_SCHEMA_VERSION)),
        "missing schema context: {detail}"
    );
    assert!(
        detail.contains("sevrity"),
        "missing unknown field: {detail}"
    );
    assert!(
        detail.contains("Fix: correct"),
        "missing repair guidance: {detail}"
    );
}

/// Regression: the one-version forward window classifies newer fields without
/// interpreting them, but a public/gated load still rejects the partial corpus
/// with a typed error so production scanning never silently drops recall.
#[test]
fn supported_future_schema_rejects_partial_public_load_with_typed_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!(
            "schema_version = {}\n",
            DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION
        ),
    );
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);
    write_detector(dir.path(), "future.toml", FUTURE_DETECTOR);

    let error = load_detectors(dir.path()).expect_err("partial production corpus must fail");
    match &error {
        SpecError::ForwardIncompatibleCorpus {
            skipped_count,
            total,
            detail,
            ..
        } => {
            assert_eq!(*skipped_count, 1);
            assert_eq!(*total, 2);
            assert!(detail.contains("future.toml"));
            assert!(detail.contains("future_only"));
        }
        other => panic!("expected ForwardIncompatibleCorpus, got {other:?}"),
    }
    let rendered = error.to_string();
    assert!(rendered.contains("partial corpus"));
    assert!(rendered.contains("update keyhog"));
}

/// Regression: even when every detector happens to use current fields, a newer
/// declared schema changes parsing semantics and corpus identity. Production
/// loads therefore return a typed update requirement rather than downgrading
/// the manifest to this binary's schema.
#[test]
fn supported_future_version_with_current_fields_is_not_identity_downgraded() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!(
            "schema_version = {}\n",
            DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION
        ),
    );
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);

    let error = load_detectors(dir.path()).expect_err("forward schema needs a newer binary");
    match error {
        SpecError::ForwardIncompatibleCorpus {
            declared_schema,
            supported_schema,
            skipped_count,
            total,
            detail,
            ..
        } => {
            assert_eq!(declared_schema, DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION);
            assert_eq!(supported_schema, DETECTOR_CORPUS_SCHEMA_VERSION);
            assert_eq!(skipped_count, 0);
            assert_eq!(total, 1);
            assert!(detail.contains(DETECTOR_CORPUS_MANIFEST_FILE));
            assert!(detail.contains("effective corpus identity"));
        }
        other => panic!("expected ForwardIncompatibleCorpus, got {other:?}"),
    }
}

/// Regression: forward compatibility is bounded, so a corpus more than one
/// schema ahead is rejected before any detector can be partially interpreted.
#[test]
fn unsupported_future_version_fails_before_detector_loading() {
    let dir = tempfile::tempdir().expect("tempdir");
    let unsupported = DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION + 1;
    write_manifest(dir.path(), &format!("schema_version = {unsupported}\n"));
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);

    let error = load_detectors(dir.path()).expect_err("unbounded future schema must fail");
    match error {
        SpecError::UnsupportedCorpusSchema {
            found,
            current,
            max_forward,
            path,
        } => {
            assert_eq!(found, unsupported);
            assert_eq!(current, DETECTOR_CORPUS_SCHEMA_VERSION);
            assert_eq!(max_forward, DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION);
            assert!(path.ends_with(DETECTOR_CORPUS_MANIFEST_FILE));
        }
        other => panic!("expected UnsupportedCorpusSchema, got {other:?}"),
    }
}

/// Regression: a future corpus containing only unknown-field detectors fails
/// with the same typed forward-incompatibility error as a mixed corpus; no
/// production path may turn version skew into an empty successful scan.
#[test]
fn future_only_incompatible_corpus_fails_with_typed_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!(
            "schema_version = {}\n",
            DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION
        ),
    );
    write_detector(dir.path(), "future.toml", FUTURE_DETECTOR);

    let error = load_detectors(dir.path()).expect_err("zero-compatible-detector corpus must fail");
    match &error {
        SpecError::ForwardIncompatibleCorpus {
            skipped_count,
            total,
            detail,
            ..
        } => {
            assert_eq!(*skipped_count, 1);
            assert_eq!(*total, 1);
            assert!(detail.contains("future.toml"));
        }
        other => panic!("expected ForwardIncompatibleCorpus, got {other:?}"),
    }
    assert!(error.to_string().contains("update keyhog"));
}

/// Regression: a missing manifest deterministically means legacy schema 1,
/// preserving strict unknown-field handling while enabling only its explicitly
/// versioned conservative migrations.
#[test]
fn missing_manifest_defaults_to_legacy_strict_schema() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_detector(dir.path(), "future.toml", FUTURE_DETECTOR);

    let detail = strict_rejection_detail(
        load_detectors(dir.path()).expect_err("manifest-free unknown field must stay fatal"),
    );
    assert!(detail.contains(&format!("schema {DETECTOR_CORPUS_MIN_SCHEMA_VERSION}")));
    assert!(detail.contains("future_only"));
    assert!(detail.contains("supported newer schema"));
}
/// Regression: schema-v1/missing-manifest status-only verifier contracts
/// predate the explicit policy field. They migrate deterministically to the
/// conservative error-body backstop, never status-authoritative success.
#[test]
fn missing_manifest_migrates_legacy_status_only_success_conservatively() {
    let dir = tempfile::tempdir().expect("tempdir");
    let legacy = format!(
        "{VALID_DETECTOR}\n\
         [detector.verify]\n\
         url = \"https://api.example.test/verify\"\n\
         allowed_domains = [\"api.example.test\"]\n\
         [detector.verify.success]\n\
         status = 200\n"
    );
    write_detector(dir.path(), "legacy.toml", &legacy);

    let detectors = load_detectors(dir.path()).expect("legacy status-only contract migrates");
    let success = detectors[0]
        .verify
        .as_ref()
        .expect("verify")
        .success
        .as_ref()
        .expect("success");
    assert_eq!(success.policy, Some(SuccessPolicy::StatusWithErrorBackstop));
}
/// Regression: an explicit schema-1 manifest selects the exact same legacy
/// migration as a missing manifest. Status-only success becomes the conservative
/// error-body backstop because treating status as authoritative would broaden
/// verification and could misclassify provider error responses as active.
#[test]
fn explicit_schema_one_migrates_status_only_success_to_error_backstop() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!("schema_version = {DETECTOR_CORPUS_MIN_SCHEMA_VERSION}\n"),
    );
    let legacy = format!(
        "{VALID_DETECTOR}\n\
         [detector.verify]\n\
         url = \"https://api.example.test/verify\"\n\
         allowed_domains = [\"api.example.test\"]\n\
         [detector.verify.success]\n\
         status = 200\n"
    );
    write_detector(dir.path(), "legacy-v1.toml", &legacy);

    let detectors = load_detectors(dir.path()).expect("explicit schema-1 contract migrates");
    let policy = detectors[0]
        .verify
        .as_ref()
        .expect("verify")
        .success
        .as_ref()
        .expect("success")
        .policy;
    assert_eq!(policy, Some(SuccessPolicy::StatusWithErrorBackstop));
}

/// Regression: the same absent policy under the current schema is an authoring
/// error, proving the legacy migration is selected by schema rather than by
/// detector shape alone.
#[test]
fn current_manifest_requires_explicit_verifier_success_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!("schema_version = {DETECTOR_CORPUS_SCHEMA_VERSION}\n"),
    );
    let current = format!(
        "{VALID_DETECTOR}\n\
         [detector.verify]\n\
         url = \"https://api.example.test/verify\"\n\
         allowed_domains = [\"api.example.test\"]\n\
         [detector.verify.success]\n\
         status = 200\n"
    );
    write_detector(dir.path(), "current.toml", &current);

    let detail = strict_rejection_detail(
        load_detectors(dir.path()).expect_err("current-schema policy omission must fail"),
    );
    assert!(detail.contains("current.toml"));
    assert!(detail.contains("policy must classify success"));
}

/// Regression: the current schema keeps policy classification explicit, but does not
/// collapse the three classifications into one behavior. Each supported value
/// must survive the production load path exactly so authors can distinguish
/// positive body evidence, conservative status evidence, and a reviewed
/// provider-authoritative status contract.
#[test]
fn current_manifest_accepts_all_three_explicit_success_policies() {
    let cases = [
        (
            "body_positive",
            "body_contains = \"accepted\"\n",
            SuccessPolicy::BodyPositive,
        ),
        (
            "status_with_error_backstop",
            "",
            SuccessPolicy::StatusWithErrorBackstop,
        ),
        (
            "status_authoritative",
            "",
            SuccessPolicy::StatusAuthoritative,
        ),
    ];

    for (policy_name, body_evidence, expected) in cases {
        let dir = tempfile::tempdir().expect("tempdir");
        write_manifest(
            dir.path(),
            &format!("schema_version = {DETECTOR_CORPUS_SCHEMA_VERSION}\n"),
        );
        let current = format!(
            "{VALID_DETECTOR}\n\
             [detector.verify]\n\
             url = \"https://api.example.test/verify\"\n\
             allowed_domains = [\"api.example.test\"]\n\
             [detector.verify.success]\n\
             status = 200\n\
             policy = \"{policy_name}\"\n\
             {body_evidence}"
        );
        write_detector(dir.path(), "current.toml", &current);

        let detectors = load_detectors(dir.path())
            .unwrap_or_else(|error| panic!("current policy {policy_name} must load: {error}"));
        let policy = detectors[0]
            .verify
            .as_ref()
            .expect("verify")
            .success
            .as_ref()
            .expect("success")
            .policy;
        assert_eq!(policy, Some(expected), "policy {policy_name} changed");
    }
}

/// Regression: a non-integer version is a manifest error with the canonical
/// path and a direct version repair, not a misleading detector parse failure.
#[test]
fn malformed_manifest_version_has_context_and_repair_guidance() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(dir.path(), "schema_version = \"next\"\n");
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);

    let error = load_detectors(dir.path()).expect_err("malformed version must fail");
    assert!(matches!(error, SpecError::InvalidCorpusManifest { .. }));
    let rendered = error.to_string();
    assert!(rendered.contains(DETECTOR_CORPUS_MANIFEST_FILE));
    assert!(rendered.contains("schema_version"));
    assert!(rendered.contains("Fix:"));
}

/// Regression: one directory has one scalar schema contract. Encoding multiple
/// versions in the manifest is rejected as malformed instead of choosing one
/// by file order and producing nondeterministic mixed-version behavior.
#[test]
fn mixed_schema_versions_in_one_manifest_are_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(dir.path(), "schema_version = [1, 2]\n");
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);

    let error = load_detectors(dir.path()).expect_err("mixed schema versions must fail");
    assert!(matches!(error, SpecError::InvalidCorpusManifest { .. }));
    let rendered = error.to_string();
    assert!(rendered.contains(DETECTOR_CORPUS_MANIFEST_FILE));
    assert!(rendered.contains("schema_version"));
}

/// Regression: manifest serialization round-trips the sole compatibility
/// signal exactly, preventing an accidental rename or lossy version default.
#[test]
fn corpus_manifest_round_trips_exact_schema_version() {
    let manifest = DetectorCorpusManifest {
        schema_version: DETECTOR_CORPUS_SCHEMA_VERSION,
    };
    let encoded = toml::to_string(&manifest).expect("serialize corpus manifest");
    assert_eq!(
        encoded,
        format!("schema_version = {DETECTOR_CORPUS_SCHEMA_VERSION}\n")
    );
    let decoded: DetectorCorpusManifest = toml::from_str(&encoded).expect("parse round trip");
    assert_eq!(decoded, manifest);
}

/// Regression: a manifest-free directory and a current-schema directory can
/// normalize to byte-for-byte equal specs. Their digests must still differ
/// because schema 1 and schema 3 assign different meaning to the corpus;
/// spec equality cannot erase that compatibility boundary.
#[test]
fn equal_specs_under_legacy_and_current_schema_have_distinct_digests() {
    let legacy = tempfile::tempdir().expect("legacy tempdir");
    let current = tempfile::tempdir().expect("current tempdir");
    write_detector(legacy.path(), "current.toml", VALID_DETECTOR);
    write_detector(current.path(), "current.toml", VALID_DETECTOR);
    write_manifest(
        current.path(),
        &format!("schema_version = {}\n", DETECTOR_CORPUS_SCHEMA_VERSION),
    );

    let legacy = load_detector_corpus(legacy.path()).expect("legacy corpus loads");
    let current = load_detector_corpus(current.path()).expect("manifest corpus loads");
    assert_eq!(legacy.schema_version, DETECTOR_CORPUS_MIN_SCHEMA_VERSION);
    assert_eq!(current.schema_version, DETECTOR_CORPUS_SCHEMA_VERSION);
    assert_eq!(
        serde_json::to_vec(&legacy.specs).expect("serialize legacy specs"),
        serde_json::to_vec(&current.specs).expect("serialize current specs"),
        "the fixture must isolate schema identity from detector contents"
    );
    assert_ne!(
        legacy.compute_digest().expect("legacy digest"),
        current.compute_digest().expect("current digest"),
        "normalized legacy and current corpora must not share evidence identity"
    );
}

/// Regression: the canonical BLAKE3 corpus identity consumed by caches, daemon
/// handshakes, and autoroute evidence binds the manifest path and schema
/// version; it must not retain the pre-manifest unbound v1 identity.
#[test]
fn effective_corpus_sha_is_schema_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!("schema_version = {}\n", DETECTOR_CORPUS_SCHEMA_VERSION),
    );
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);
    let detectors = load_detectors(dir.path()).expect("current corpus loads");
    let encoded = serde_json::to_vec(&detectors).expect("serialize canonical detector set");

    let mut expected = blake3::Hasher::new();
    expected.update(b"keyhog-effective-detector-corpus-v2\0");
    expected.update(DETECTOR_CORPUS_MANIFEST_FILE.as_bytes());
    expected.update(&[0]);
    expected.update(&DETECTOR_CORPUS_SCHEMA_VERSION.to_le_bytes());
    expected.update(&encoded);
    assert_eq!(
        keyhog_core::compute_detector_corpus_digest(&detectors).expect("effective digest"),
        *expected.finalize().as_bytes()
    );

    let mut legacy_unbound = blake3::Hasher::new();
    legacy_unbound.update(b"keyhog-effective-detector-corpus-v1\0");
    legacy_unbound.update(&encoded);
    assert_ne!(
        keyhog_core::compute_detector_corpus_digest(&detectors).expect("effective digest"),
        *legacy_unbound.finalize().as_bytes(),
        "schema-bound corpus identity must invalidate pre-manifest evidence"
    );
}

/// Regression: the public effective corpus identity exactly matches the
/// canonical detector bytes plus manifest path/bytes, and changing only schema
/// metadata changes the identity used by caches and autoroute evidence.
#[test]
fn detector_digest_is_bound_to_corpus_manifest_bytes() {
    let detectors_dir = keyhog_core::testing::crate_source_path("../../detectors");
    let current = effective_digest(&detectors_dir, None);
    assert_eq!(keyhog_core::detector_digest(), current);

    let manifest = std::fs::read_to_string(detectors_dir.join(DETECTOR_CORPUS_MANIFEST_FILE))
        .expect("read current corpus manifest");
    let future = manifest.replace(
        &format!("schema_version = {DETECTOR_CORPUS_SCHEMA_VERSION}"),
        &format!("schema_version = {DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION}"),
    );
    assert_ne!(
        effective_digest(&detectors_dir, Some(&future)),
        current,
        "schema-only manifest changes must invalidate effective corpus identity"
    );
}

/// Regression: only the explicit gate-off authoring/testing path may inspect
/// compatible siblings from a forward corpus. It still skips the whole future
/// detector, never silently deserializing and dropping its unknown field.
#[test]
fn gate_off_still_skips_whole_forward_detector() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_manifest(
        dir.path(),
        &format!(
            "schema_version = {}\n",
            DETECTOR_CORPUS_MAX_FORWARD_SCHEMA_VERSION
        ),
    );
    write_detector(dir.path(), "current.toml", VALID_DETECTOR);
    write_detector(dir.path(), "future.toml", FUTURE_DETECTOR);

    let detectors = CoreTestApi::load_detectors_with_gate(&TestApi, dir.path(), false)
        .expect("forward corpus loads with authoring gate disabled");
    assert_eq!(detectors.len(), 1);
    assert_eq!(detectors[0].id, "current");
}
