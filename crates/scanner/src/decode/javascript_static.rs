//! Bounded evaluation of static JavaScript secret-recovery expressions.
//!
//! This is deliberately not a JavaScript runtime. It recognizes a small,
//! side-effect-free grammar whose operands are fully embedded byte arrays and
//! whose result is therefore deterministic: `String.fromCharCode(...data.map(
//! (byte, index) => byte ^ key[index % key.length]))`. Both literal numeric
//! arrays and Base64-encoded JSON byte arrays are supported, along with a
//! bounded AES-256-CBC form using literal buffers or empty-joined strings.
//! Dynamic operands, mismatched identifiers, oversized programs, invalid
//! padding, and non-UTF-8 results fail closed while the original source remains
//! in the normal scan path.

use super::pipeline::push_decoded_text_chunk;
use super::Decoder;
use keyhog_core::Chunk;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use crate::telemetry::{record_static_recovery_rejection, StaticRecoveryRejection};

mod aes;

const MAX_STATIC_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_BYTE_ARRAY_LEN: usize = 64 * 1024;
const MAX_ARRAY_BINDINGS: usize = 32;
const MAX_STATIC_EXPRESSIONS: usize = 64;

static LITERAL_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r"(?m)\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\[([0-9,\x20\t\r\n]+)\]",
        "literal byte-array assignment",
    )
});

static BASE64_JSON_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?m)\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*JSON\s*\.\s*parse\s*\(\s*Buffer\s*\.\s*from\s*\(\s*(["'][A-Za-z0-9+/=_-]+["'])\s*,\s*(?:'base64'|"base64")\s*\)\s*\.\s*toString\s*\(\s*(?:'utf8'|"utf8")\s*\)\s*\)"#,
        "Base64 JSON byte-array assignment",
    )
});

static XOR_MAP_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r"String\s*\.\s*fromCharCode\s*\(\s*\.\.\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*map\s*\(\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*=>\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*%\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*length\s*\]\s*\)\s*\)",
        "static XOR map expression",
    )
});

pub(super) struct JavaScriptStaticDecoder;

impl Decoder for JavaScriptStaticDecoder {
    fn name(&self) -> &'static str {
        "javascript-static"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        if chunk.metadata.source_type.contains("/javascript-static") {
            return Vec::new();
        }

        let has_xor_expression = chunk.data.contains("fromCharCode") && chunk.data.contains('^');
        let has_aes_expression =
            chunk.data.contains("createDecipheriv") && chunk.data.contains("aes-256-cbc");
        if !has_xor_expression && !has_aes_expression {
            return Vec::new();
        }
        if chunk.data.len() > MAX_STATIC_SOURCE_BYTES {
            record_static_limit("source byte ceiling");
            return Vec::new();
        }

        let mut decoded_chunks = Vec::new();
        let mut emitted = BTreeSet::new();
        let path = chunk.metadata.path.as_deref();
        if has_xor_expression {
            recover_xor_plaintexts(&chunk.data, path, &mut emitted);
        }
        if has_aes_expression {
            aes::recover_plaintexts(&chunk.data, path, &mut emitted);
        }
        for plaintext in emitted {
            push_decoded_text_chunk(&mut decoded_chunks, chunk, plaintext, self.name());
        }
        decoded_chunks
    }
}

fn recover_xor_plaintexts(source: &str, path: Option<&str>, emitted: &mut BTreeSet<String>) {
    let bindings = collect_byte_array_bindings(source);
    if bindings.len() < 2 {
        return;
    }
    for (expression_index, captures) in XOR_MAP_RE.captures_iter(source).enumerate() {
        if expression_index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("XOR expression ceiling");
            break;
        }
        let Some((
            data_name,
            byte_parameter,
            index_parameter,
            byte_use,
            key_name,
            index_use,
            key_length_use,
        )) = capture_xor_names(&captures)
        else {
            continue;
        };
        if byte_parameter != byte_use || index_parameter != index_use || key_name != key_length_use
        {
            continue;
        }
        if data_name == key_name
            || identifier_occurrence_count(source, data_name) != 2
            || identifier_occurrence_count(source, key_name) != 3
        {
            continue;
        }
        let (Some(data), Some(key)) = (bindings.get(data_name), bindings.get(key_name)) else {
            continue;
        };
        let data = match data {
            Ok(data) => data,
            Err(reason) => {
                record_static_recovery_rejection(path, *reason);
                continue;
            }
        };
        let key = match key {
            Ok(key) => key,
            Err(reason) => {
                record_static_recovery_rejection(path, *reason);
                continue;
            }
        };
        if data.is_empty() || key.is_empty() || data.len() > MAX_BYTE_ARRAY_LEN {
            continue;
        }
        let plaintext: Vec<u8> = data
            .iter()
            .zip(key.iter().cycle())
            .map(|(byte, key_byte)| byte ^ key_byte)
            .collect();
        let plaintext = match String::from_utf8(plaintext) {
            Ok(plaintext) => plaintext,
            // LAW10: the typed dogfood event records this rejected expression without source bytes.
            Err(_) => {
                record_static_recovery_rejection(path, StaticRecoveryRejection::XorPlaintextUtf8);
                continue;
            }
        };
        emitted.insert(plaintext);
    }
}

fn compile_static_regex(pattern: &str, label: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(error) => panic!(
            "compiled-in JavaScript {label} regex failed to build: {error}. Fix the pattern literal."
        ),
    }
}

fn collect_byte_array_bindings(
    source: &str,
) -> HashMap<String, Result<Vec<u8>, StaticRecoveryRejection>> {
    let mut bindings = HashMap::new();
    for (binding_index, captures) in LITERAL_ARRAY_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS {
            record_static_limit("literal array binding ceiling");
            break;
        }
        let (Some(name), Some(body)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        if let Some(binding) = parse_byte_array(body.as_str()) {
            bindings.insert(name.as_str().to_owned(), binding);
        }
    }

    for (binding_index, captures) in BASE64_JSON_ARRAY_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS || bindings.len() >= MAX_ARRAY_BINDINGS {
            record_static_limit("encoded array binding ceiling");
            break;
        }
        let (Some(name), Some(encoded)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let Some(encoded) = unquote_static_string(encoded.as_str()) else {
            continue;
        };
        let decoded = match super::base64_decode(encoded) {
            Ok(decoded) => Ok(decoded),
            Err(()) => Err(StaticRecoveryRejection::JsonBase64),
        };
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(reason) => {
                bindings.insert(name.as_str().to_owned(), Err(reason));
                continue;
            }
        };
        if decoded.len() > MAX_BYTE_ARRAY_LEN.saturating_mul(4) {
            record_static_limit("encoded JSON byte ceiling");
            continue;
        }
        let text = match std::str::from_utf8(&decoded) {
            Ok(text) => Ok(text),
            Err(_) => Err(StaticRecoveryRejection::JsonUtf8), // LAW10: a referenced binding emits a recorded dogfood event; no source bytes are retained.
        };
        let text = match text {
            Ok(text) => text,
            Err(reason) => {
                bindings.insert(name.as_str().to_owned(), Err(reason));
                continue;
            }
        };
        let Some(binding) = parse_json_byte_array(text) else {
            continue;
        };
        bindings.insert(name.as_str().to_owned(), binding);
    }
    bindings
}

fn parse_byte_array(body: &str) -> Option<Result<Vec<u8>, StaticRecoveryRejection>> {
    let mut bytes = Vec::new();
    for value in body.split(',') {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if bytes.len() >= MAX_BYTE_ARRAY_LEN {
            record_static_limit("literal byte-array element ceiling");
            return None;
        }
        match value.parse::<u8>() {
            Ok(value) => bytes.push(value),
            Err(_) => return Some(Err(StaticRecoveryRejection::LiteralByteArrayElement)), // LAW10: a referenced binding emits a recorded dogfood event; no source bytes are retained.
        }
    }
    (!bytes.is_empty()).then_some(Ok(bytes))
}

fn parse_json_byte_array(text: &str) -> Option<Result<Vec<u8>, StaticRecoveryRejection>> {
    let values: Vec<u8> = match serde_json::from_str(text) {
        Ok(values) => values,
        Err(_) => return Some(Err(StaticRecoveryRejection::JsonByteArray)), // LAW10: a referenced binding emits a recorded dogfood event; no source bytes are retained.
    };
    if values.len() > MAX_BYTE_ARRAY_LEN {
        record_static_limit("decoded JSON array element ceiling");
        return None;
    }
    (!values.is_empty()).then_some(Ok(values))
}

fn record_static_limit(limit: &'static str) {
    crate::telemetry::record_decode_truncation();
    tracing::debug!(
        limit,
        "bounded JavaScript static recovery hit a safety ceiling; original source remains scanned"
    );
}

fn unquote_static_string(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let quote = *bytes.first()?;
    if bytes.len() < 2 || !matches!(quote, b'\'' | b'"') || bytes.last().copied() != Some(quote) {
        return None;
    }
    value.get(1..value.len() - 1)
}

fn identifier_occurrence_count(source: &str, identifier: &str) -> usize {
    source
        .match_indices(identifier)
        .filter(|(index, _)| {
            let before = index
                .checked_sub(1)
                .and_then(|at| source.as_bytes().get(at));
            let after = source.as_bytes().get(index + identifier.len());
            before.is_none_or(|byte| !is_identifier_byte(*byte))
                && after.is_none_or(|byte| !is_identifier_byte(*byte))
        })
        .count()
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn all_distinct(values: &[&str]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| values[index + 1..].iter().all(|other| value != other))
}

#[allow(clippy::type_complexity)]
fn capture_xor_names<'a>(
    captures: &'a regex::Captures<'a>,
) -> Option<(
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    &'a str,
)> {
    Some((
        captures.get(1)?.as_str(),
        captures.get(2)?.as_str(),
        captures.get(3)?.as_str(),
        captures.get(4)?.as_str(),
        captures.get(5)?.as_str(),
        captures.get(6)?.as_str(),
        captures.get(7)?.as_str(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use keyhog_core::ChunkMetadata;

    const SECRET: &str = concat!("ghp_", "69121b4cdeeff121c88dffac1f9dbc2giIjE");

    fn xor_program(encoded_arrays: bool, valid_callback: bool) -> String {
        let key = [19u8, 71, 211, 4, 99, 28, 8];
        let data: Vec<u8> = SECRET
            .as_bytes()
            .iter()
            .zip(key.iter().cycle())
            .map(|(byte, key_byte)| byte ^ key_byte)
            .collect();
        let assignments = if encoded_arrays {
            let engine = base64::engine::general_purpose::STANDARD;
            let data = engine.encode(serde_json::to_vec(&data).expect("serialize data"));
            let key = engine.encode(serde_json::to_vec(&key).expect("serialize key"));
            format!(
                "const _d = JSON.parse(Buffer.from('{data}', 'base64').toString('utf8')); \
                 const _k = JSON.parse(Buffer.from('{key}', 'base64').toString('utf8'));"
            )
        } else {
            format!("const _d = {data:?}; const _k = {key:?};")
        };
        let byte_use = if valid_callback { "b" } else { "other" };
        format!(
            "{assignments} return String.fromCharCode(..._d.map((b, i) => \
             {byte_use} ^ _k[i % _k.length]));"
        )
    }

    fn decode(source: String) -> Vec<Chunk> {
        JavaScriptStaticDecoder.decode_chunk(&Chunk {
            data: source.into(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                ..Default::default()
            },
        })
    }

    #[test]
    fn recovers_static_xor_byte_arrays() {
        let decoded = decode(xor_program(false, true));
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].data.as_ref(), SECRET);
    }

    #[test]
    fn recovers_base64_json_xor_byte_arrays() {
        let decoded = decode(xor_program(true, true));
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].data.as_ref(), SECRET);
    }

    #[test]
    fn recovers_xor_with_whitespace_around_member_access() {
        let source =
            xor_program(false, true).replace("String.fromCharCode", "String . fromCharCode");
        let decoded = decode(source);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].data.as_ref(), SECRET);
    }

    #[test]
    fn rejects_mismatched_callback_variables() {
        assert!(decode(xor_program(false, false)).is_empty());
    }

    #[test]
    fn rejects_xor_array_mutation_outside_the_static_expression() {
        let source = xor_program(false, true).replacen(
            "return String.fromCharCode",
            "_d[0] = 0; return String.fromCharCode",
            1,
        );
        assert!(decode(source).is_empty());
    }

    #[test]
    fn recovers_bound_buffer_aes_256_cbc() {
        let source = concat!(
            "const key = Buffer.from(\"75aa41b547fb2b20b1c35bf524115e077c7d5dd5c173271fe67c03c2d781192d\", 'hex'); ",
            "const iv = Buffer.from(\"667daed70df5f3b0c37d48833c330c1c\", 'hex'); ",
            "const payload = Buffer.from(\"X1VL9YbGVjOgjoQWE2fjtUL63C7dbUU9DXwze8i9Ejb9yqL5UEABmPYwofE18q5J\", 'base64'); ",
            "const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv); ",
            "return Buffer.concat([decipher.update(payload), decipher.final()]).toString('utf8');",
        );
        let decoded = decode(source.to_string());
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].data.as_ref(), SECRET);
    }

    #[test]
    fn recovers_joined_inline_buffer_aes_256_cbc() {
        let source = concat!(
            "const _key = [\"75aa41b547fb2b20b1c35bf524115e07\", ",
            "\"7c7d5dd5c173271fe67c03c2d781192d\"].join(''); ",
            "const _payload = [\"X1VL9YbGVjOgjoQWE2fjtUL6\", ",
            "\"3C7dbUU9DXwze8i9Ejb9yqL5UEABmPYwofE18q5J\"].join(''); ",
            "const _dec = crypto.createDecipheriv('aes-256-cbc', ",
            "Buffer.from(_key, 'hex'), Buffer.from(\"667daed70df5f3b0c37d48833c330c1c\", 'hex')); ",
            "return Buffer.concat([_dec.update(Buffer.from(_payload, 'base64')), ",
            "_dec.final()]).toString('utf8');",
        );
        let decoded = decode(source.to_string());
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].data.as_ref(), SECRET);
    }

    #[test]
    fn rejects_aes_expression_with_mismatched_decipher_binding() {
        let source = concat!(
            "const key = Buffer.from(\"75aa41b547fb2b20b1c35bf524115e077c7d5dd5c173271fe67c03c2d781192d\", 'hex'); ",
            "const iv = Buffer.from(\"667daed70df5f3b0c37d48833c330c1c\", 'hex'); ",
            "const payload = Buffer.from(\"X1VL9YbGVjOgjoQWE2fjtUL63C7dbUU9DXwze8i9Ejb9yqL5UEABmPYwofE18q5J\", 'base64'); ",
            "const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv); ",
            "return Buffer.concat([other.update(payload), decipher.final()]).toString('utf8');",
        );
        assert!(decode(source.to_string()).is_empty());
    }

    #[test]
    fn does_not_recurse_on_its_own_output() {
        let mut chunk = decode(xor_program(false, true)).remove(0);
        chunk.data = xor_program(false, true).into();
        assert!(JavaScriptStaticDecoder.decode_chunk(&chunk).is_empty());
    }
}
