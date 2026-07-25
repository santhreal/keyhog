//! KH-057: generic password/key length ceilings apply to the complete value in
//! UTF-8 bytes, never to a regex prefix.
#![cfg(feature = "entropy")]


use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::sync::Arc;

fn detector_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn scanner() -> CompiledScanner {
    let mut detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    detectors
        .iter_mut()
        .find(|detector| detector.id == "generic-password")
        .expect("generic-password")
        // Isolate the byte-bound contract from this detector's confidence floor.
        .min_confidence = None;
    let mut config = ScannerConfig::default();
    config.min_confidence = 0.0;
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(config)
}

fn candidate(len: usize, mut state: u64) -> String {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    let mut value = String::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        value.push(ALPHABET[state as usize % ALPHABET.len()] as char);
    }
    value
}

fn password_candidate(len: usize, state: u64) -> String {
    let mut value = candidate(len, state)
        .replace('_', "A")
        .replace('-', "b");
    for index in (8..len).step_by(17) {
        value.replace_range(index..index + 1, "#");
    }
    value
}

fn scan(scanner: &CompiledScanner, body: String, path: &str) -> (Vec<RawMatch>, Vec<DogfoodEvent>) {
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    let findings = telemetry::with_scan_telemetry(&trace, || {
        scanner.scan_with_backend(&chunk, ScanBackend::CpuFallback)
    })
    .expect("CPU fallback scan");
    (findings, trace.drain().dogfood_events)
}

fn generic_findings(findings: &[RawMatch]) -> Vec<(&str, &str, usize)> {
    findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.detector_id.as_ref(),
                "generic-password" | "generic-api-key"
            )
        })
        .map(|finding| {
            (
                finding.detector_id.as_ref(),
                finding.credential.as_ref(),
                finding.location.offset,
            )
        })
        .collect()
}

fn assert_too_long(events: &[DogfoodEvent], path: &str) {
    let matching = events
        .iter()
        .filter(|event| {
            matches!(
                event,
                DogfoodEvent::ShapeSuppressed {
                    path: Some(event_path),
                    reason,
                    ..
                } if event_path == path && reason == "value_too_long"
            )
        })
        .count();
    assert_eq!(
        matching, 1,
        "the whole rejected value must emit one exact value_too_long event: {events:#?}"
    );
}

/// Regression: the two generic families own distinct inclusive byte ceilings in
/// their detector schemas; scanner code must not replace them with one default.
#[test]
fn detector_specs_own_password_and_key_length_ceilings() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    for (detector_id, expected_max) in [
        ("generic-password", 256usize),
        ("generic-api-key", 512usize),
    ] {
        let detector = detectors
            .iter()
            .find(|detector| detector.id == detector_id)
            .unwrap_or_else(|| panic!("missing detector {detector_id}"));
        assert_eq!(detector.max_len, Some(expected_max), "{detector_id}");
    }
}

/// Regression: the password owner admits 255/256 bytes, rejects 257 whole, and
/// leaves a neighboring API-key finding at its exact source span.
#[test]
fn password_family_enforces_255_256_257_byte_boundaries() {
    let scanner = scanner();
    for (len, accepted) in [(255, true), (256, true), (257, false)] {
        let password = password_candidate(len, 0x0570_0000 + len as u64);
        let safe_key = candidate(48, 0x057a_11ce + len as u64);
        let body = format!("password=\"{password}\"\napi_key={safe_key}\n");
        let password_offset = body.find(&password).expect("password offset");
        let key_offset = body.find(&safe_key).expect("key offset");
        let path = "/srv/app/.env";
        let (findings, events) = scan(&scanner, body, path);
        let generic = generic_findings(&findings);

        assert_eq!(
            generic
                .iter()
                .filter(|(detector, _, _)| *detector == "generic-password")
                .copied()
                .collect::<Vec<_>>(),
            if accepted {
                vec![("generic-password", password.as_str(), password_offset)]
            } else {
                Vec::new()
            },
            "password boundary {len} emitted the wrong bytes/span: {generic:#?}; events: {events:#?}"
        );
        assert!(
            generic.contains(&("generic-api-key", safe_key.as_str(), key_offset)),
            "rejecting the password must not consume its safe neighbor: {generic:#?}"
        );
        assert_eq!(generic.len(), if accepted { 2 } else { 1 }, "{generic:#?}");
        assert!(
            generic.iter().all(|(_, credential, _)| {
                !password.starts_with(credential) || *credential == password
            }),
            "a password prefix was emitted as a credential: {generic:#?}"
        );
        if !accepted {
            assert_too_long(&events, path);
        }
    }
}

/// Regression: the API-key owner admits 511/512 bytes, rejects 513 whole, and
/// preserves the exact span of a neighboring password finding.
#[test]
fn key_family_enforces_511_512_513_byte_boundaries() {
    let scanner = scanner();
    for (len, accepted) in [(511, true), (512, true), (513, false)] {
        let key = candidate(len, 0x057b_0000 + len as u64);
        let safe_password = password_candidate(32, 0x057c_11ce + len as u64);
        let body = format!("{{\"api_key\":\"{key}\"}}\npassword={safe_password}\n");
        let key_offset = body.find(&key).expect("key offset");
        let password_offset = body.find(&safe_password).expect("password offset");
        let path = format!("kh057-key-{len}.json");
        let (findings, events) = scan(&scanner, body, &path);
        let generic = generic_findings(&findings);

        assert_eq!(
            generic
                .iter()
                .filter(|(detector, _, _)| *detector == "generic-api-key")
                .copied()
                .collect::<Vec<_>>(),
            if accepted {
                vec![("generic-api-key", key.as_str(), key_offset)]
            } else {
                Vec::new()
            },
            "key boundary {len} emitted the wrong bytes/span: {generic:#?}"
        );
        assert!(
            generic.contains(&(
                "generic-password",
                safe_password.as_str(),
                password_offset
            )),
            "rejecting the key must not consume its safe neighbor: {generic:#?}"
        );
        assert_eq!(generic.len(), if accepted { 2 } else { 1 }, "{generic:#?}");
        assert!(
            generic
                .iter()
                .all(|(_, credential, _)| !key.starts_with(credential) || *credential == key),
            "an API-key prefix was emitted as a credential: {generic:#?}"
        );
        if !accepted {
            assert_too_long(&events, &path);
        }
    }
}

/// Regression: max lengths count UTF-8 bytes rather than Unicode scalar values;
/// a 257-byte quoted password must not leak its 255-byte ASCII prefix.
#[test]
fn unicode_length_is_measured_in_utf8_bytes_without_prefix_emission() {
    let scanner = scanner();
    let ascii_prefix = password_candidate(255, 0x057d_11ce);
    let password = format!("{ascii_prefix}é");
    assert_eq!(password.chars().count(), 256);
    assert_eq!(password.len(), 257);
    let safe_key = candidate(48, 0x057a_11ce + 255);
    let body = format!("password=\"{password}\"\napi_key={safe_key}\n");
    let key_offset = body.find(&safe_key).expect("key offset");
    let path = "kh057-unicode.env";
    let (findings, events) = scan(&scanner, body, path);
    let generic = generic_findings(&findings);

    assert!(
        generic
            .iter()
            .all(|(_, credential, _)| *credential != ascii_prefix && *credential != password),
        "neither the overlong Unicode value nor its ASCII prefix may emit: {generic:#?}"
    );
    assert!(
        generic.contains(&("generic-api-key", safe_key.as_str(), key_offset)),
        "Unicode rejection must preserve the neighboring finding: {generic:#?}"
    );
    assert_eq!(generic.len(), 1, "{generic:#?}");
    assert_too_long(&events, path);
}

/// Regression: a delimiter inside a quoted overlong password belongs to the
/// whole wrapper and cannot turn its left side into a prefix-only finding.
#[test]
fn quoted_embedded_delimiter_is_rejected_as_one_password_value() {
    let scanner = scanner();
    let left = password_candidate(128, 0x057f_11ce);
    let right = password_candidate(128, 0x0580_11ce);
    let password = format!("{left};{right}");
    assert_eq!(password.len(), 257);
    let safe_key = candidate(40, 0x0581_11ce);
    let body = format!("password=\"{password}\"\napi_key={safe_key}\n");
    let key_offset = body.find(&safe_key).expect("key offset");
    let path = "kh057-delimiter.env";
    let (findings, events) = scan(&scanner, body, path);
    let generic = generic_findings(&findings);

    assert!(
        generic
            .iter()
            .all(|(_, credential, _)| *credential != left && *credential != password),
        "the delimiter must not make the left prefix reportable: {generic:#?}; events: {events:#?}"
    );
    assert!(
        generic.contains(&("generic-api-key", safe_key.as_str(), key_offset)),
        "delimiter rejection must preserve the neighboring finding: {generic:#?}"
    );
    assert_eq!(generic.len(), 1, "{generic:#?}");
    assert_too_long(&events, path);
}

/// Regression: an escaped quote in a quoted wrapper is content, not the end of
/// the API key; the complete 513-byte encoded value is rejected with exact telemetry.
#[test]
fn escaped_wrapper_does_not_truncate_overlong_key() {
    let scanner = scanner();
    let left = candidate(250, 0x0582_11ce);
    let right = candidate(261, 0x0583_11ce);
    let key = format!(r#"{left}\"{right}"#);
    assert_eq!(key.len(), 513);
    let safe_password = password_candidate(32, 0x0584_11ce);
    let body = format!("api_key=\"{key}\"\npassword={safe_password}\n");
    let password_offset = body.find(&safe_password).expect("password offset");
    let path = "kh057-encoded-wrapper.env";
    let (findings, events) = scan(&scanner, body, path);
    let generic = generic_findings(&findings);

    assert!(
        generic
            .iter()
            .all(|(_, credential, _)| *credential != left && *credential != key),
        "the escaped wrapper must not emit the left key prefix: {generic:#?}"
    );
    assert!(
        generic.contains(&(
            "generic-password",
            safe_password.as_str(),
            password_offset
        )),
        "encoded-wrapper rejection must preserve the neighboring finding: {generic:#?}"
    );
    assert_eq!(generic.len(), 1, "{generic:#?}");
    assert_too_long(&events, path);
}
