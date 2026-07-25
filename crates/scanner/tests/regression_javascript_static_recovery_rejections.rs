#![cfg(feature = "decode")]

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry, StaticRecoveryStatus};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::Arc;

const SECRET: &str = concat!("ghp_", "69121b4cdeeff121c88dffac1f9dbc2giIjE");
const CRYPTOJS_CIPHERTEXT: &str =
    "U2FsdGVkX18AESIzRFVmd4gAG90IBfANYeQRW2joYGicJIAQKVwf/Qhcc0SZhoi6oSIms0UnVPuMaiFkNHu2pw==";

const XOR_LITERAL: &str = concat!(
    "const data = [177,109,7,171,232,62,227,128,231,103,67,151,186,98,183,212,",
    "176,52,69,197,189,63,234,214,176,99,22,151,239,97,235,214,180,102,69,147,",
    "183,78,184,247]; const xorKey = [214,5,119,244,222,7,210,178]; ",
    "String.fromCharCode(...data.map((b, i) => b ^ xorKey[i % xorKey.length]));",
);
const AES_JOINED_BUFFERS: &str = concat!(
    "const joinedKey = [\"75aa41b547fb2b20b1c35bf524115e07\",",
    "\"7c7d5dd5c173271fe67c03c2d781192d\"].join(''); ",
    "const joinedPayload = [\"X1VL9YbGVjOgjoQWE2fjtUL6\",",
    "\"3C7dbUU9DXwze8i9Ejb9yqL5UEABmPYwofE18q5J\"].join(''); ",
    "const joinedDecipher = crypto.createDecipheriv('aes-256-cbc', ",
    "Buffer.from(joinedKey, 'hex'), ",
    "Buffer.from(\"667daed70df5f3b0c37d48833c330c1c\", 'hex')); ",
    "Buffer.concat([joinedDecipher.update(Buffer.from(joinedPayload, 'base64')), ",
    "joinedDecipher.final()]).toString('utf8');",
);

fn scanner() -> CompiledScanner {
    CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("compile embedded detector corpus")
        .with_config(ScannerConfig::thorough())
}

#[derive(Debug)]
struct Trace {
    events: Vec<DogfoodEvent>,
    static_recovery_rejections: std::collections::BTreeMap<String, u64>,
    static_recovery_status: StaticRecoveryStatus,
}

impl Deref for Trace {
    type Target = [DogfoodEvent];

    fn deref(&self) -> &Self::Target {
        &self.events
    }
}

fn scan_with_trace(source: &str) -> (Vec<RawMatch>, Trace) {
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let chunk = Chunk {
        data: source.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("malformed-recovery.js".into()),
            ..Default::default()
        },
    };
    let matches = telemetry::with_scan_telemetry(&trace, || {
        scanner().scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback).expect("selected backend scan succeeds")
            .into_iter()
            .flatten()
            .collect()
    });
    let snapshot = trace.drain();
    (
        matches,
        Trace {
            events: snapshot.dogfood_events,
            static_recovery_rejections: snapshot.static_recovery_rejections,
            static_recovery_status: snapshot.static_recovery_status,
        },
    )
}

fn scan_many_with_trace(sources: &[String]) -> (Vec<Vec<RawMatch>>, Trace) {
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    let chunks: Vec<Chunk> = sources
        .iter()
        .enumerate()
        .map(|(index, source)| Chunk {
            data: source.clone().into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(format!("accounting-{index}.js").into()),
                ..Default::default()
            },
        })
        .collect();
    let matches = telemetry::with_scan_telemetry(&trace, || {
        scanner().scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback).expect("selected backend scan succeeds")
    });
    let snapshot = trace.drain();
    (
        matches,
        Trace {
            events: snapshot.dogfood_events,
            static_recovery_rejections: snapshot.static_recovery_rejections,
            static_recovery_status: snapshot.static_recovery_status,
        },
    )
}

fn scan_sources(sources: &[String]) -> Vec<Vec<RawMatch>> {
    let chunks: Vec<Chunk> = sources
        .iter()
        .enumerate()
        .map(|(index, source)| Chunk {
            data: source.clone().into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(format!("malformed-cryptojs-{index}.js").into()),
                ..Default::default()
            },
        })
        .collect();
    scanner().scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback).expect("selected backend scan succeeds")
}

fn rejection_reasons(events: &[DogfoodEvent]) -> BTreeSet<&str> {
    events
        .iter()
        .filter_map(|event| match event {
            DogfoodEvent::StaticRecoveryRejected {
                decoder, reason, ..
            } => {
                assert_eq!(decoder, "javascript-static");
                Some(reason.as_ref())
            }
            DogfoodEvent::ExampleSuppressed { .. } | DogfoodEvent::ShapeSuppressed { .. } => None,
        })
        .collect()
}

fn cryptojs_program(ciphertext: &str, passphrase: &str) -> String {
    format!(
        "const CryptoJS = require(\"crypto-js\"); \
         function decryptAES(encryptedData, keyMaterial) {{ \
           const bytes = CryptoJS.AES.decrypt(encryptedData, keyMaterial); \
           return bytes.toString(CryptoJS.enc.Utf8); \
         }} \
         let secretKey = \"{passphrase}\"; \
         let encryptedMessage = \"{ciphertext}\"; \
         let decryptedMessage = decryptAES(encryptedMessage, secretKey); \
         console.log(decryptedMessage);"
    )
}

fn exact_target_found(matches: &[RawMatch]) -> bool {
    matches.iter().any(|matched| {
        matched.detector_id.as_ref() == "github-classic-pat"
            && matched.credential.as_ref() == SECRET
    })
}

fn aes_bound_program(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> String {
    let payload = base64::engine::general_purpose::STANDARD.encode(ciphertext);
    format!(
        "const key = Buffer.from(\"{}\", 'hex'); \
         const iv = Buffer.from(\"{}\", 'hex'); \
         const payload = Buffer.from(\"{payload}\", 'base64'); \
         const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv); \
         return Buffer.concat([decipher.update(payload), decipher.final()]).toString('utf8');",
        hex::encode(key),
        hex::encode(iv),
    )
}

fn encrypt_one_block(key: &[u8; 32], iv: &[u8; 16], plaintext: [u8; 16]) -> [u8; 16] {
    let cipher = Aes256::new(key.into());
    let mut block_bytes = plaintext;
    for (byte, prior) in block_bytes.iter_mut().zip(iv) {
        *byte ^= prior;
    }
    let mut block = aes::Block::from(block_bytes);
    cipher.encrypt_block(&mut block);
    block.into()
}

#[test]
fn malformed_xor_bindings_are_typed_and_plain_source_still_scans() {
    let source = format!(
        "const planted = '{SECRET}'; \
         const badLiteral = [256]; \
         const badBase64 = JSON.parse(Buffer.from('=', 'base64').toString('utf8')); \
         const badUtf8 = JSON.parse(Buffer.from('/w==', 'base64').toString('utf8')); \
         const badJson = JSON.parse(Buffer.from('WyJub3QtYS1ieXRlIl0=', 'base64').toString('utf8')); \
         const keyLiteral = [1]; const keyBase64 = [1]; \
         const keyUtf8 = [1]; const keyJson = [1]; \
         String.fromCharCode(...badLiteral.map((b, i) => b ^ keyLiteral[i % keyLiteral.length])); \
         String.fromCharCode(...badBase64.map((b, i) => b ^ keyBase64[i % keyBase64.length])); \
         String.fromCharCode(...badUtf8.map((b, i) => b ^ keyUtf8[i % keyUtf8.length])); \
         String.fromCharCode(...badJson.map((b, i) => b ^ keyJson[i % keyJson.length]));"
    );
    let (matches, events) = scan_with_trace(&source);
    assert!(matches.iter().any(|matched| {
        matched.detector_id.as_ref() == "github-classic-pat"
            && matched.credential.as_ref() == SECRET
    }));
    assert_eq!(
        rejection_reasons(&events),
        BTreeSet::from([
            "json_base64",
            "json_byte_array",
            "json_utf8",
            "literal_byte_array_element",
        ])
    );
    assert!(events.iter().all(|event| match event {
        DogfoodEvent::StaticRecoveryRejected { path, .. } => {
            path.as_deref() == Some("malformed-recovery.js")
        }
        _ => true,
    }));
}

#[test]
fn malformed_aes_buffer_encodings_are_typed() {
    let source = concat!(
        "const badHex = Buffer.from('0', 'hex'); ",
        "const badBase64 = Buffer.from('=', 'base64'); ",
        "const validKey = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'); ",
        "const iv1 = Buffer.from('00000000000000000000000000000000', 'hex'); ",
        "const iv2 = Buffer.from('00000000000000000000000000000000', 'hex'); ",
        "const validPayload = Buffer.from('AAAAAAAAAAAAAAAAAAAAAA==', 'base64'); ",
        "const decipher1 = crypto.createDecipheriv('aes-256-cbc', badHex, iv1); ",
        "Buffer.concat([decipher1.update(validPayload), decipher1.final()]).toString('utf8'); ",
        "const decipher2 = crypto.createDecipheriv('aes-256-cbc', validKey, iv2); ",
        "Buffer.concat([decipher2.update(badBase64), decipher2.final()]).toString('utf8');",
    );
    let (_, events) = scan_with_trace(source);
    assert_eq!(
        rejection_reasons(&events),
        BTreeSet::from(["buffer_base64", "buffer_hex"])
    );
}

#[test]
fn cryptojs_wrong_passphrase_and_invalid_base64_fail_closed() {
    let (wrong_key_matches, wrong_key_events) =
        scan_with_trace(&cryptojs_program(CRYPTOJS_CIPHERTEXT, "mySecretKey124"));
    assert!(!exact_target_found(&wrong_key_matches));
    assert_eq!(
        rejection_reasons(&wrong_key_events),
        BTreeSet::from(["aes_padding"])
    );

    let (bad_base64_matches, bad_base64_events) =
        scan_with_trace(&cryptojs_program("=", "mySecretKey123"));
    assert!(!exact_target_found(&bad_base64_matches));
    assert_eq!(
        rejection_reasons(&bad_base64_events),
        BTreeSet::from(["buffer_base64"])
    );
}

#[test]
fn cryptojs_malformed_envelopes_and_ambiguous_data_flow_do_not_recover() {
    let mut truncated = base64::engine::general_purpose::STANDARD
        .decode(CRYPTOJS_CIPHERTEXT)
        .expect("decode fixed CryptoJS fixture");
    truncated.pop();
    let truncated = base64::engine::general_purpose::STANDARD.encode(truncated);

    let base = cryptojs_program(CRYPTOJS_CIPHERTEXT, "mySecretKey123");
    let duplicate_parameters = base
        .replacen(
            "function decryptAES(encryptedData, keyMaterial)",
            "function decryptAES(value, value)",
            1,
        )
        .replacen(
            "AES.decrypt(encryptedData, keyMaterial)",
            "AES.decrypt(value, value)",
            1,
        );
    let local_output_collision = base
        .replacen(
            "function decryptAES(encryptedData, keyMaterial)",
            "function decryptAES(bytes, keyMaterial)",
            1,
        )
        .replacen(
            "AES.decrypt(encryptedData, keyMaterial)",
            "AES.decrypt(bytes, keyMaterial)",
            1,
        );
    let inaccessible_bindings = base
        .replacen("let secretKey", "{ let secretKey", 1)
        .replacen("let decryptedMessage", "} let decryptedMessage", 1);
    let commented_function = base
        .replacen("function decryptAES", "/* function decryptAES", 1)
        .replacen("} let secretKey", "} */ let secretKey", 1);
    let cases = [
        cryptojs_program(&CRYPTOJS_CIPHERTEXT.replacen('U', "V", 1), "mySecretKey123"),
        cryptojs_program(&truncated, "mySecretKey123"),
        base.replacen(
            "let decryptedMessage",
            "secretKey = \"replacement\"; let decryptedMessage",
            1,
        ),
        base.replacen(
            "let encryptedMessage",
            "let encryptedMessage = \"duplicate\"; let encryptedMessage",
            1,
        ),
        base.replace(
            "decryptAES(encryptedMessage, secretKey)",
            "decryptAES(secretKey, encryptedMessage)",
        ),
        base.replacen(
            "AES.decrypt(encryptedData, keyMaterial)",
            "AES.decrypt(otherData, keyMaterial)",
            1,
        ),
        base.replacen("CryptoJS.enc.Utf8", "Other.enc.Utf8", 1),
        base.replacen(
            "function decryptAES",
            "CryptoJS = other; function decryptAES",
            1,
        ),
        duplicate_parameters,
        local_output_collision,
        base.replacen(
            "const CryptoJS = require(\"crypto-js\");",
            "{ const CryptoJS = require(\"crypto-js\"); }",
            1,
        ),
        inaccessible_bindings,
        base.replacen(
            "let decryptedMessage",
            "{ let secretKey = \"replacement\"; } let decryptedMessage",
            1,
        ),
        base.replacen(
            "let decryptedMessage",
            "eval(\"secret\" + \"Key = 'replacement'\"); let decryptedMessage",
            1,
        ),
        base.replacen(
            "let decryptedMessage",
            "Function(\"return 1\")(); let decryptedMessage",
            1,
        ),
        commented_function,
    ];

    for (source, matches) in cases.iter().zip(scan_sources(&cases)) {
        assert!(
            !exact_target_found(&matches),
            "ambiguous or malformed CryptoJS source must not recover: {source}"
        );
    }
}

#[test]
fn unreferenced_malformed_bindings_do_not_emit_rejections() {
    let key = [7u8; 32];
    let iv = [11u8; 16];
    let valid_ciphertext = encrypt_one_block(&key, &iv, [16u8; 16]);
    let source = format!(
        "const unusedLiteral = [256]; \
         const unusedJson = JSON.parse(Buffer.from('=', 'base64').toString('utf8')); \
         const data = [65]; const xorKey = [0]; \
         String.fromCharCode(...data.map((b, i) => b ^ xorKey[i % xorKey.length])); \
         const unusedHex = Buffer.from('0', 'hex'); {}",
        aes_bound_program(&key, &iv, &valid_ciphertext)
    );
    let (_, events) = scan_with_trace(&source);
    assert!(
        rejection_reasons(&events).is_empty(),
        "only bindings referenced by a matched expression may emit: {events:?}"
    );
}

#[test]
fn distinct_rejected_expressions_have_exact_counts_and_offsets() {
    let source = concat!(
        "const bad1 = [256]; const key1 = [1]; ",
        "String.fromCharCode(...bad1.map((b, i) => b ^ key1[i % key1.length])); ",
        "const bad2 = [257]; const key2 = [1]; ",
        "String.fromCharCode(...bad2.map((b, i) => b ^ key2[i % key2.length]));",
    );
    let (_, events) = scan_with_trace(source);
    let static_events = events
        .iter()
        .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
        .count();
    assert_eq!(static_events, 2, "expression details: {events:?}");
    assert_eq!(
        events
            .static_recovery_rejections
            .get("literal_byte_array_element"),
        Some(&2)
    );
    assert_eq!(
        rejection_reasons(&events),
        BTreeSet::from(["literal_byte_array_element"])
    );
    let offsets: BTreeSet<usize> = events
        .iter()
        .filter_map(|event| match event {
            DogfoodEvent::StaticRecoveryRejected {
                expression_offset, ..
            } => Some(*expression_offset),
            _ => None,
        })
        .collect();
    assert_eq!(offsets.len(), 2, "expression offsets must be distinct");
}

#[test]
fn equal_path_and_offset_rejections_keep_distinct_revision_identity() {
    let source = concat!(
        "const bad = [256]; const key = [1]; ",
        "String.fromCharCode(...bad.map((b, i) => b ^ key[i % key.length]));",
    );
    let chunks: Vec<Chunk> = ["commit-a", "commit-b"]
        .into_iter()
        .map(|commit| Chunk {
            data: source.into(),
            metadata: ChunkMetadata {
                source_type: "git-history".into(),
                path: Some("same.js".into()),
                commit: Some(commit.into()),
                ..Default::default()
            },
        })
        .collect();
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    telemetry::with_scan_telemetry(&trace, || {
        let findings = scanner().scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback).expect("selected backend scan succeeds");
        assert!(findings.iter().all(Vec::is_empty));
    });
    let snapshot = trace.drain();
    let revision_events = snapshot
        .dogfood_events
        .iter()
        .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
        .count();
    assert_eq!(
        revision_events, 2,
        "distinct revisions must not deduplicate"
    );
    assert_eq!(
        snapshot
            .static_recovery_rejections
            .get("literal_byte_array_element"),
        Some(&2)
    );
}

#[test]
fn repeated_evaluation_counts_each_attempt_without_duplicate_detail() {
    let source = concat!(
        "const bad = [256]; const key = [1]; ",
        "String.fromCharCode(...bad.map((b, i) => b ^ key[i % key.length]));",
    );
    let chunk = Chunk {
        data: source.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("overlap.js".into()),
            ..Default::default()
        },
    };
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    telemetry::with_scan_telemetry(&trace, || {
        let findings =
            scanner().scan_chunks_with_backend(&[chunk.clone(), chunk], ScanBackend::CpuFallback).expect("selected backend scan succeeds");
        assert!(findings.iter().all(Vec::is_empty));
    });
    let snapshot = trace.drain();
    assert_eq!(
        snapshot
            .static_recovery_rejections
            .get("literal_byte_array_element"),
        Some(&2),
        "the aggregate measures rejected evaluation attempts"
    );
    assert_eq!(
        snapshot
            .dogfood_events
            .iter()
            .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
            .count(),
        1,
        "detail deduplication must collapse the repeated expression identity"
    );
}

#[test]
fn absent_source_identity_does_not_collide_with_literal_sentinel_text() {
    let source = concat!(
        "const bad = [256]; const key = [1]; ",
        "String.fromCharCode(...bad.map((b, i) => b ^ key[i % key.length]));",
    );
    let chunks = vec![
        Chunk {
            data: source.into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: None,
                commit: None,
                ..Default::default()
            },
        },
        Chunk {
            data: source.into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some("<unknown>".into()),
                commit: Some("<none>".into()),
                ..Default::default()
            },
        },
    ];
    let trace = Arc::new(ScanTelemetry::new());
    trace.enable_dogfood();
    telemetry::with_scan_telemetry(&trace, || {
        let findings = scanner().scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback).expect("selected backend scan succeeds");
        assert!(findings.iter().all(Vec::is_empty));
    });
    let snapshot = trace.drain();
    assert_eq!(
        snapshot
            .dogfood_events
            .iter()
            .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
            .count(),
        2
    );
    assert_eq!(
        snapshot
            .static_recovery_rejections
            .get("literal_byte_array_element"),
        Some(&2)
    );
}

fn reverse_base64_program(invocation_count: usize, suffix: &str) -> String {
    let reversed: String = SECRET.chars().rev().collect();
    let encoded: String = base64::engine::general_purpose::STANDARD
        .encode(reversed)
        .chars()
        .rev()
        .collect();
    let invocations = (0..invocation_count)
        .map(|index| {
            format!(
                "const recovered{suffix}{index} = decodeString(atob('{encoded}'.split('').reverse().join('')));"
            )
        })
        .collect::<String>();
    format!(
        "function decodeString(str) {{ return str.split('').reverse().join(''); }} {invocations}"
    )
}

/// Regression: successful XOR, joined-buffer AES, and reverse/Base64 constructs
/// remain recoverable while the status reports every supported evaluation.
#[test]
fn supported_constructs_have_exact_status_counts() {
    let sources = vec![
        XOR_LITERAL.to_owned(),
        AES_JOINED_BUFFERS.to_owned(),
        reverse_base64_program(1, "supported"),
    ];
    let (matches, trace) = scan_many_with_trace(&sources);
    assert!(matches.iter().all(|per_chunk| exact_target_found(per_chunk)));
    assert_eq!(
        trace.static_recovery_status,
        StaticRecoveryStatus {
            supported: 3,
            unsupported: 0,
            erroneous: 0,
        }
    );
    assert!(trace.static_recovery_rejections.is_empty());
}

/// Production metrics are always-on; dogfood only controls bounded detail.
#[test]
fn exact_status_and_reasons_are_recorded_without_dogfood_capture() {
    let trace = Arc::new(ScanTelemetry::new());
    let sources = [
        XOR_LITERAL.to_owned(),
        format!(
            "eval('throw new Error()'); {}",
            reverse_base64_program(1, "unsupported")
        ),
        "const value = atob('abc'.split('').reverse().join('');".to_owned(),
    ];
    let chunks: Vec<Chunk> = sources
        .iter()
        .enumerate()
        .map(|(index, source)| Chunk {
            data: source.clone().into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(format!("always-on-{index}.js").into()),
                ..Default::default()
            },
        })
        .collect();

    telemetry::with_scan_telemetry(&trace, || {
        scanner()
            .scan_chunks_with_backend(&chunks, ScanBackend::CpuFallback)
            .expect("selected backend scan succeeds");
    });
    let snapshot = trace.drain();

    assert!(snapshot.dogfood_events.is_empty());
    assert_eq!(
        snapshot.static_recovery_status,
        StaticRecoveryStatus {
            supported: 1,
            unsupported: 1,
            erroneous: 1,
        }
    );
    assert_eq!(
        snapshot.static_recovery_rejections.get("unsupported_call"),
        Some(&1)
    );
    assert_eq!(
        snapshot.static_recovery_rejections.get("malformed_expression"),
        Some(&1)
    );
}

#[test]
fn daemon_merge_rejects_nonconserving_dispositions_before_mutation() {
    let before_status = telemetry::static_recovery_status();
    let before_reasons = telemetry::static_recovery_rejection_counts();
    let error = telemetry::merge_daemon_aggregates(
        &std::collections::BTreeMap::from([
            ("unsupported_call".to_owned(), 2),
            ("json_utf8".to_owned(), 3),
        ]),
        StaticRecoveryStatus {
            supported: 1,
            unsupported: 1,
            erroneous: 3,
        },
        4,
    )
    .expect_err("nonconserving totals must fail before global mutation");

    assert!(error.contains("aggregate conservation failed"));
    assert_eq!(telemetry::static_recovery_status(), before_status);
    assert_eq!(telemetry::static_recovery_rejection_counts(), before_reasons);
}

/// Regression: calls that could execute and computed access to recovery
/// primitives are rejected without execution and retain exact source offsets.
#[test]
fn unsupported_constructs_are_visible_and_nonexecuting() {
    let call_source = format!(
        "const planted = '{SECRET}'; eval('throw new Error()'); {}",
        reverse_base64_program(1, "call")
    );
    let (call_matches, call_trace) = scan_with_trace(&call_source);
    assert!(exact_target_found(&call_matches));
    assert_eq!(
        call_trace.static_recovery_rejections.get("unsupported_call"),
        Some(&1)
    );
    assert_eq!(call_trace.static_recovery_status.unsupported, 1);
    let call_offset = call_source
        .find("decodeString(atob")
        .expect("reverse/Base64 invocation");
    assert!(call_trace.events.iter().any(|event| matches!(
        event,
        DogfoodEvent::StaticRecoveryRejected {
            expression_offset,
            reason,
            ..
        } if *expression_offset == call_offset && reason.as_ref() == "unsupported_call"
    )));

    let dynamic_source = format!(
        "const method = holder['split']; {}",
        reverse_base64_program(1, "dynamic")
    );
    let (_, dynamic_trace) = scan_with_trace(&dynamic_source);
    assert_eq!(
        dynamic_trace
            .static_recovery_rejections
            .get("dynamic_property_access"),
        Some(&1)
    );
    assert_eq!(dynamic_trace.static_recovery_status.unsupported, 1);
    assert_eq!(dynamic_trace.static_recovery_status.supported, 0);
}

/// Regression: a syntactically incomplete join chain remains scanned but is
/// reported as an erroneous construct at the candidate's exact byte offset.
#[test]
fn malformed_construct_is_counted_at_exact_offset() {
    let source = "const value = atob('abc'.split('').reverse().join('');";
    let (_, trace) = scan_with_trace(source);
    assert_eq!(
        trace
            .static_recovery_rejections
            .get("malformed_expression"),
        Some(&1)
    );
    assert_eq!(trace.static_recovery_status.erroneous, 1);
    let offset = source.find("atob").expect("malformed candidate");
    assert!(trace.events.iter().any(|event| matches!(
        event,
        DogfoodEvent::StaticRecoveryRejected {
            expression_offset,
            reason,
            ..
        } if *expression_offset == offset && reason.as_ref() == "malformed_expression"
    )));
}

/// Regression: the static expression ceiling fails closed, records only the
/// first excluded construct, and does not produce partially recovered output.
#[test]
fn expression_resource_limit_has_bounded_exact_accounting() {
    let source = reverse_base64_program(65, "limited");
    let (matches, trace) = scan_with_trace(&source);
    assert!(!exact_target_found(&matches));
    assert_eq!(
        trace.static_recovery_rejections.get("resource_limit"),
        Some(&1)
    );
    assert_eq!(
        trace.static_recovery_status,
        StaticRecoveryStatus {
            supported: 0,
            unsupported: 0,
            erroneous: 1,
        }
    );
    assert_eq!(
        trace
            .events
            .iter()
            .filter(|event| matches!(event, DogfoodEvent::StaticRecoveryRejected { .. }))
            .count(),
        1
    );
    let excluded_offset = source
        .match_indices("decodeString(atob")
        .nth(64)
        .map(|(offset, _)| offset)
        .expect("sixty-fifth recovery invocation");
    assert!(trace.events.iter().any(|event| matches!(
        event,
        DogfoodEvent::StaticRecoveryRejected {
            expression_offset,
            reason,
            ..
        } if *expression_offset == excluded_offset && reason.as_ref() == "resource_limit"
    )));
}

#[test]
fn aes_key_iv_and_ciphertext_boundaries_emit_exact_reasons() {
    let key = [7u8; 32];
    let iv = [11u8; 16];
    let valid_plaintext = [16u8; 16];
    let valid_ciphertext = encrypt_one_block(&key, &iv, valid_plaintext);

    for key_len in [31usize, 33] {
        let (_, events) = scan_with_trace(&aes_bound_program(
            &vec![7; key_len],
            &iv,
            &valid_ciphertext,
        ));
        assert_eq!(
            rejection_reasons(&events),
            BTreeSet::from(["aes_key_length"]),
            "key length {key_len}"
        );
    }
    for iv_len in [15usize, 17] {
        let (_, events) = scan_with_trace(&aes_bound_program(
            &key,
            &vec![11; iv_len],
            &valid_ciphertext,
        ));
        assert_eq!(
            rejection_reasons(&events),
            BTreeSet::from(["aes_iv_length"]),
            "IV length {iv_len}"
        );
    }
    for ciphertext_len in [15usize, 17] {
        let (_, events) = scan_with_trace(&aes_bound_program(&key, &iv, &vec![3; ciphertext_len]));
        assert_eq!(
            rejection_reasons(&events),
            BTreeSet::from(["aes_ciphertext_block_length"]),
            "ciphertext length {ciphertext_len}"
        );
    }

    let (_, valid_events) = scan_with_trace(&aes_bound_program(&key, &iv, &valid_ciphertext));
    assert!(rejection_reasons(&valid_events).is_empty());
}

#[test]
fn aes_non_utf8_plaintext_and_invalid_padding_are_distinct() {
    let key = [19u8; 32];
    let iv = [23u8; 16];

    let mut non_utf8 = [15u8; 16];
    non_utf8[0] = 0xff;
    let non_utf8_ciphertext = encrypt_one_block(&key, &iv, non_utf8);
    let (_, non_utf8_events) = scan_with_trace(&aes_bound_program(&key, &iv, &non_utf8_ciphertext));
    assert_eq!(
        rejection_reasons(&non_utf8_events),
        BTreeSet::from(["aes_plaintext_utf8"])
    );

    let invalid_padding_ciphertext = encrypt_one_block(&key, &iv, [0u8; 16]);
    let (_, padding_events) =
        scan_with_trace(&aes_bound_program(&key, &iv, &invalid_padding_ciphertext));
    assert_eq!(
        rejection_reasons(&padding_events),
        BTreeSet::from(["aes_padding"])
    );
}
