#![cfg(feature = "decode")]

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::telemetry::{self, DogfoodEvent, ScanTelemetry};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};
use std::collections::BTreeSet;
use std::ops::Deref;
use std::sync::Arc;

const SECRET: &str = concat!("ghp_", "69121b4cdeeff121c88dffac1f9dbc2giIjE");

fn scanner() -> CompiledScanner {
    CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("compile embedded detector corpus")
        .with_config(ScannerConfig::thorough())
}

#[derive(Debug)]
struct Trace {
    events: Vec<DogfoodEvent>,
    static_recovery_rejections: std::collections::BTreeMap<String, u64>,
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
        scanner()
            .scan_chunks_with_backend(&[chunk], ScanBackend::CpuFallback)
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
        },
    )
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
