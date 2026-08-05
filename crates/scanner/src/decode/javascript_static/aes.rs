//! Static AES-256-CBC recovery for the bounded JavaScript grammar.

use super::{
    all_distinct, compile_static_regex, identifier_occurrence_count, quoted_label,
    record_static_limit, unquote_static_string, RecoveredPlaintext, StaticOperationBudget,
    BINDING_KEYWORD, BUFFER_CONSTRUCTOR, MAX_ARRAY_BINDINGS, MAX_BYTE_ARRAY_LEN, QUOTE,
};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use keyhog_core::ChunkMetadata;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use crate::telemetry::{record_static_recovery_rejection, StaticRecoveryRejection};

/// `aes-256-cbc` in any ASCII case and any string delimiter. Node's
/// `createDecipheriv` normalizes the algorithm name, so a program written
/// `AES-256-CBC` is the same program.
fn aes_256_cbc() -> String {
    quoted_label("aes-256-cbc")
}

static BUFFER_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        &format!(
            r"(?m)\b{BINDING_KEYWORD}\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*({BUFFER_CONSTRUCTOR}\s*\(\s*({QUOTE}[A-Za-z0-9+/=_-]+{QUOTE})\s*,\s*({QUOTE}(?i:hex|base64){QUOTE})\s*\))"
        ),
        "Buffer binding",
    )
});

static STRING_JOIN_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        &format!(
            r#"(?m)\b{BINDING_KEYWORD}\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(\[[^\]\r\n]+\])\s*\.\s*join\s*\(\s*(?:''|"")\s*\)"#
        ),
        "static string-array join binding",
    )
});

/// A plain immutable string literal used as an AES key, IV, or payload.
///
/// `const key = "…"` is the ordinary way to write what the join form
/// (`["…","…"].join("")`) writes the obfuscated way, and both are the same
/// constant. The body class admits no `\` and no `$`/`{`, so an escape or a
/// template substitution cannot match, and the occurrence check at the call
/// site rejects any binding that is written to again.
static STRING_LITERAL_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        &format!(
            r"(?m)\b{BINDING_KEYWORD}\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*({QUOTE}[A-Za-z0-9+/=_-]+{QUOTE})\s*;"
        ),
        "static string-literal binding",
    )
});

static AES_BOUND_RE: LazyLock<Regex> = LazyLock::new(|| {
    let algorithm = aes_256_cbc();
    compile_static_regex(
        &format!(
            r"(?s)\b{BINDING_KEYWORD}\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:crypto\s*\.\s*)?createDecipheriv\s*\(\s*{algorithm}\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*update\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*final\s*\(\s*\)"
        ),
        "AES-256-CBC bound-buffer expression",
    )
});

static AES_INLINE_BUFFER_RE: LazyLock<Regex> = LazyLock::new(|| {
    let algorithm = aes_256_cbc();
    let hex = quoted_label("hex");
    let base64 = quoted_label("base64");
    compile_static_regex(
        &format!(
            r"(?s)\b{BINDING_KEYWORD}\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:crypto\s*\.\s*)?createDecipheriv\s*\(\s*{algorithm}\s*,\s*{BUFFER_CONSTRUCTOR}\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*{hex}\s*\)\s*,\s*{BUFFER_CONSTRUCTOR}\s*\(\s*({QUOTE}[A-Fa-f0-9]+{QUOTE})\s*,\s*{hex}\s*\)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*update\s*\(\s*{BUFFER_CONSTRUCTOR}\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*{base64}\s*\)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*final\s*\(\s*\)"
        ),
        "AES-256-CBC inline-buffer expression",
    )
});

struct BufferBinding {
    bytes: Result<Vec<u8>, StaticRecoveryRejection>,
    source_start: usize,
    source_end: usize,
}

pub(super) fn recover_plaintexts(
    source: &str,
    metadata: &ChunkMetadata,
    base_offset: usize,
    emitted: &mut BTreeSet<RecoveredPlaintext>,
    budget: &mut StaticOperationBudget,
) {
    let buffers = collect_buffer_bindings(source);
    for captures in AES_BOUND_RE.captures_iter(source) {
        if !budget.take() {
            break;
        }
        let Some(decipher) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let Some(expression) = captures.get(0) else {
            continue;
        };
        let Some(expression_offset) =
            crate::engine::absolute_offset(base_offset, expression.start())
        else {
            record_static_limit("bound AES expression offset overflow");
            continue;
        };
        let Some(key_name) = captures.get(2).map(|value| value.as_str()) else {
            continue;
        };
        let Some(iv_name) = captures.get(3).map(|value| value.as_str()) else {
            continue;
        };
        let Some(update_decipher) = captures.get(4).map(|value| value.as_str()) else {
            continue;
        };
        let Some(payload_name) = captures.get(5).map(|value| value.as_str()) else {
            continue;
        };
        let Some(final_decipher) = captures.get(6).map(|value| value.as_str()) else {
            continue;
        };
        if decipher != update_decipher || decipher != final_decipher {
            continue;
        }
        if !all_distinct(&[decipher, key_name, iv_name, payload_name])
            || identifier_occurrence_count(source, decipher) != 3
            || identifier_occurrence_count(source, key_name) != 2
            || identifier_occurrence_count(source, iv_name) != 2
            || identifier_occurrence_count(source, payload_name) != 2
        {
            continue;
        }
        let (Some(key), Some(iv), Some(ciphertext)) = (
            buffers.get(key_name),
            buffers.get(iv_name),
            buffers.get(payload_name),
        ) else {
            continue;
        };
        let key = match resolve_binding(&key.bytes) {
            Ok(key) => key,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, reason);
                continue;
            }
        };
        let iv = match resolve_binding(&iv.bytes) {
            Ok(iv) => iv,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, reason);
                continue;
            }
        };
        let ciphertext_bytes = match resolve_binding(&ciphertext.bytes) {
            Ok(ciphertext) => ciphertext,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, reason);
                continue;
            }
        };
        if let Some(plaintext) =
            decrypt_aes_256_cbc(key, iv, ciphertext_bytes, metadata, expression_offset)
        {
            emitted.insert(RecoveredPlaintext {
                plaintext,
                source_start: ciphertext.source_start,
                source_end: ciphertext.source_end,
            });
        }
    }

    let strings = collect_static_string_bindings(source);
    for captures in AES_INLINE_BUFFER_RE.captures_iter(source) {
        if !budget.take() {
            break;
        }
        let Some(decipher) = captures.get(1).map(|value| value.as_str()) else {
            continue;
        };
        let Some(expression) = captures.get(0) else {
            continue;
        };
        let Some(expression_offset) =
            crate::engine::absolute_offset(base_offset, expression.start())
        else {
            record_static_limit("inline AES expression offset overflow");
            continue;
        };
        let Some(key_name) = captures.get(2).map(|value| value.as_str()) else {
            continue;
        };
        let Some(iv_hex) = captures.get(3).map(|value| value.as_str()) else {
            continue;
        };
        let Some(update_decipher) = captures.get(4).map(|value| value.as_str()) else {
            continue;
        };
        let Some(payload_name) = captures.get(5).map(|value| value.as_str()) else {
            continue;
        };
        let Some(final_decipher) = captures.get(6).map(|value| value.as_str()) else {
            continue;
        };
        if decipher != update_decipher || decipher != final_decipher {
            continue;
        }
        if !all_distinct(&[decipher, key_name, payload_name])
            || identifier_occurrence_count(source, decipher) != 3
            || identifier_occurrence_count(source, key_name) != 2
            || identifier_occurrence_count(source, payload_name) != 2
        {
            continue;
        }
        let (Some(key_hex), Some(payload_base64)) =
            (strings.get(key_name), strings.get(payload_name))
        else {
            continue;
        };
        let key_hex = match resolve_binding(key_hex) {
            Ok(key_hex) => key_hex,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, reason);
                continue;
            }
        };
        let payload_base64 = match resolve_binding(payload_base64) {
            Ok(payload) => payload,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, reason);
                continue;
            }
        };
        let Some(iv_hex) = unquote_static_string(iv_hex) else {
            continue;
        };
        let key = match hex::decode(key_hex) {
            Ok(key) => key,
            // LAW10: the typed dogfood event records the malformed literal without source bytes.
            Err(_) => {
                record_static_recovery_rejection(
                    metadata,
                    expression_offset,
                    StaticRecoveryRejection::BufferHex,
                );
                continue;
            }
        };
        let iv = match hex::decode(iv_hex) {
            Ok(iv) => iv,
            // LAW10: the typed dogfood event records the malformed literal without source bytes.
            Err(_) => {
                record_static_recovery_rejection(
                    metadata,
                    expression_offset,
                    StaticRecoveryRejection::BufferHex,
                );
                continue;
            }
        };
        let ciphertext = match crate::decode::base64_decode(payload_base64) {
            Ok(ciphertext) => ciphertext,
            Err(()) => {
                record_static_recovery_rejection(
                    metadata,
                    expression_offset,
                    StaticRecoveryRejection::BufferBase64,
                );
                continue;
            }
        };
        if let Some(plaintext) =
            decrypt_aes_256_cbc(&key, &iv, &ciphertext, metadata, expression_offset)
        {
            emitted.insert(RecoveredPlaintext {
                plaintext,
                source_start: expression.start(),
                source_end: expression.end(),
            });
        }
    }
}

fn collect_buffer_bindings(source: &str) -> HashMap<String, BufferBinding> {
    let mut bindings = HashMap::new();
    for (binding_index, captures) in BUFFER_BINDING_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS {
            record_static_limit("buffer binding ceiling");
            break;
        }
        let (Some(name), Some(binding), Some(value), Some(format)) = (
            captures.get(1),
            captures.get(2),
            captures.get(3),
            captures.get(4),
        ) else {
            continue;
        };
        let value_span = (binding.start(), binding.end());
        let (Some(value), Some(format)) = (
            unquote_static_string(value.as_str()),
            unquote_static_string(format.as_str()),
        ) else {
            continue;
        };
        // Node's encoding names are case-insensitive, so `'HEX'` and `'Base64'`
        // name the same codec. Normalize once, then allowlist exactly.
        let decoded = match format.to_ascii_lowercase().as_str() {
            "hex" => match hex::decode(value) {
                Ok(decoded) => Some(Ok(decoded)),
                Err(_) => Some(Err(StaticRecoveryRejection::BufferHex)), // LAW10: a referenced binding emits a recorded dogfood event; no source bytes are retained.
            },
            "base64" => match crate::decode::base64_decode(value) {
                Ok(decoded) => Some(Ok(decoded)),
                Err(()) => Some(Err(StaticRecoveryRejection::BufferBase64)),
            },
            _ => None,
        };
        if let Some(binding) = decoded {
            if binding
                .as_ref()
                .is_ok_and(|decoded| decoded.len() > MAX_BYTE_ARRAY_LEN)
            {
                record_static_limit("buffer byte ceiling");
                continue;
            }
            bindings.insert(
                name.as_str().to_owned(),
                BufferBinding {
                    bytes: binding,
                    source_start: value_span.0,
                    source_end: value_span.1,
                },
            );
        }
    }
    bindings
}

fn collect_static_string_bindings(
    source: &str,
) -> HashMap<String, Result<String, StaticRecoveryRejection>> {
    let mut bindings = HashMap::new();
    for (binding_index, captures) in STRING_JOIN_BINDING_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS {
            record_static_limit("string binding ceiling");
            break;
        }
        let (Some(name), Some(array)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let parts = match serde_json::from_str::<Vec<String>>(array.as_str()) {
            Ok(parts) => Ok(parts),
            Err(_) => Err(StaticRecoveryRejection::StringJoinJson), // LAW10: a referenced binding emits a recorded dogfood event; no source bytes are retained.
        };
        let total_len = parts
            .as_ref()
            .map(|parts| parts.iter().map(String::len).sum::<usize>())
            .unwrap_or(0); // LAW10: the typed error is recorded when referenced; scan findings are unchanged.
        let parts_empty = parts.as_ref().is_ok_and(Vec::is_empty);
        if parts_empty || total_len > MAX_BYTE_ARRAY_LEN {
            if total_len > MAX_BYTE_ARRAY_LEN {
                record_static_limit("joined string byte ceiling");
            }
            continue;
        }
        bindings.insert(name.as_str().to_owned(), parts.map(|parts| parts.concat()));
    }

    // Plain literal keys, IVs, and payloads are the same constant the join
    // form spells the long way; the two must recover identically. Both loops
    // share `MAX_ARRAY_BINDINGS` through the map length so the combined table
    // cannot exceed the advertised ceiling.
    for captures in STRING_LITERAL_BINDING_RE.captures_iter(source) {
        if bindings.len() >= MAX_ARRAY_BINDINGS {
            record_static_limit("string binding ceiling");
            break;
        }
        let (Some(name), Some(literal)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let Some(value) = unquote_static_string(literal.as_str()) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if value.len() > MAX_BYTE_ARRAY_LEN {
            record_static_limit("literal string byte ceiling");
            continue;
        }
        // A name already bound by the join form is ambiguous, not a second
        // reading of the same constant: leave the first and let the call
        // site's occurrence check reject the program.
        bindings
            .entry(name.as_str().to_owned())
            .or_insert_with(|| Ok(value.to_owned()));
    }
    bindings
}

fn resolve_binding<T>(
    binding: &Result<T, StaticRecoveryRejection>,
) -> Result<&T, StaticRecoveryRejection> {
    match binding {
        Ok(value) => Ok(value),
        Err(reason) => Err(*reason),
    }
}

pub(super) fn decrypt_aes_256_cbc(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    metadata: &ChunkMetadata,
    expression_offset: usize,
) -> Option<String> {
    let key: &[u8; 32] = match key.try_into() {
        Ok(key) => key,
        // LAW10: the typed dogfood event records the invalid key shape without key bytes.
        Err(_) => {
            record_static_recovery_rejection(
                metadata,
                expression_offset,
                StaticRecoveryRejection::AesKeyLength,
            );
            return None;
        }
    };
    let mut previous: [u8; 16] = match iv.try_into() {
        Ok(iv) => iv,
        // LAW10: the typed dogfood event records the invalid IV shape without IV bytes.
        Err(_) => {
            record_static_recovery_rejection(
                metadata,
                expression_offset,
                StaticRecoveryRejection::AesIvLength,
            );
            return None;
        }
    };
    if ciphertext.is_empty() {
        record_static_recovery_rejection(
            metadata,
            expression_offset,
            StaticRecoveryRejection::AesCiphertextBlockLength,
        );
        return None;
    }
    if ciphertext.len() > MAX_BYTE_ARRAY_LEN {
        record_static_limit("AES ciphertext byte ceiling");
        return None;
    }
    if !ciphertext.len().is_multiple_of(16) {
        record_static_recovery_rejection(
            metadata,
            expression_offset,
            StaticRecoveryRejection::AesCiphertextBlockLength,
        );
        return None;
    }

    let cipher = Aes256::new(key.into());
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for encrypted in ciphertext.chunks_exact(16) {
        let mut encrypted_block = [0u8; 16];
        encrypted_block.copy_from_slice(encrypted);
        let mut block = aes::Block::clone_from_slice(encrypted);
        cipher.decrypt_block(&mut block);
        plaintext.extend(block.iter().zip(previous).map(|(byte, prior)| byte ^ prior));
        previous = encrypted_block;
    }

    let padding = usize::from(*plaintext.last()?);
    if !(1..=16).contains(&padding)
        || plaintext.len() < padding
        || !plaintext[plaintext.len() - padding..]
            .iter()
            .all(|byte| usize::from(*byte) == padding)
    {
        record_static_recovery_rejection(
            metadata,
            expression_offset,
            StaticRecoveryRejection::AesPadding,
        );
        return None;
    }
    plaintext.truncate(plaintext.len() - padding);
    match String::from_utf8(plaintext) {
        Ok(plaintext) => Some(plaintext),
        // LAW10: the typed dogfood event records non-UTF8 output without plaintext bytes.
        Err(_) => {
            record_static_recovery_rejection(
                metadata,
                expression_offset,
                StaticRecoveryRejection::AesPlaintextUtf8,
            );
            None
        }
    }
}
