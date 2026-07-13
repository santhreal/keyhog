//! Static AES-256-CBC recovery for the bounded JavaScript grammar.

use super::{
    all_distinct, compile_static_regex, identifier_occurrence_count, record_static_limit,
    unquote_static_string, MAX_ARRAY_BINDINGS, MAX_BYTE_ARRAY_LEN, MAX_STATIC_EXPRESSIONS,
};
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use regex::Regex;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

static BUFFER_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?m)\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*Buffer\s*\.\s*from\s*\(\s*(["'][A-Za-z0-9+/=_-]+["'])\s*,\s*(["'](?:hex|base64)["'])\s*\)"#,
        "Buffer binding",
    )
});

static STRING_JOIN_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?m)\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(\[[^\]\r\n]+\])\s*\.\s*join\s*\(\s*(?:''|"")\s*\)"#,
        "static string-array join binding",
    )
});

static AES_BOUND_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?s)\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:crypto\s*\.\s*)?createDecipheriv\s*\(\s*(?:'aes-256-cbc'|"aes-256-cbc")\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*update\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*final\s*\(\s*\)"#,
        "AES-256-CBC bound-buffer expression",
    )
});

static AES_INLINE_BUFFER_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?s)\bconst\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:crypto\s*\.\s*)?createDecipheriv\s*\(\s*(?:'aes-256-cbc'|"aes-256-cbc")\s*,\s*Buffer\s*\.\s*from\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*(?:'hex'|"hex")\s*\)\s*,\s*Buffer\s*\.\s*from\s*\(\s*(["'][A-Fa-f0-9]+["'])\s*,\s*(?:'hex'|"hex")\s*\)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*update\s*\(\s*Buffer\s*\.\s*from\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*(?:'base64'|"base64")\s*\)\s*\).*?([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*final\s*\(\s*\)"#,
        "AES-256-CBC inline-buffer expression",
    )
});

pub(super) fn recover_plaintexts(source: &str, emitted: &mut BTreeSet<String>) {
    let buffers = collect_buffer_bindings(source);
    for (expression_index, captures) in AES_BOUND_RE.captures_iter(source).enumerate() {
        if expression_index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("bound AES expression ceiling");
            break;
        }
        let Some(decipher) = captures.get(1).map(|value| value.as_str()) else {
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
        if let Some(plaintext) = decrypt_aes_256_cbc(key, iv, ciphertext) {
            emitted.insert(plaintext);
        }
    }

    let strings = collect_static_string_bindings(source);
    for (expression_index, captures) in AES_INLINE_BUFFER_RE.captures_iter(source).enumerate() {
        if expression_index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("inline AES expression ceiling");
            break;
        }
        let Some(decipher) = captures.get(1).map(|value| value.as_str()) else {
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
        let Some(iv_hex) = unquote_static_string(iv_hex) else {
            continue;
        };
        let (Ok(key), Ok(iv), Ok(ciphertext)) = (
            hex::decode(key_hex),
            hex::decode(iv_hex),
            crate::decode::base64_decode(payload_base64),
        ) else {
            continue;
        };
        if let Some(plaintext) = decrypt_aes_256_cbc(&key, &iv, &ciphertext) {
            emitted.insert(plaintext);
        }
    }
}

fn collect_buffer_bindings(source: &str) -> HashMap<String, Vec<u8>> {
    let mut bindings = HashMap::new();
    for (binding_index, captures) in BUFFER_BINDING_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS {
            record_static_limit("buffer binding ceiling");
            break;
        }
        let (Some(name), Some(value), Some(format)) =
            (captures.get(1), captures.get(2), captures.get(3))
        else {
            continue;
        };
        let (Some(value), Some(format)) = (
            unquote_static_string(value.as_str()),
            unquote_static_string(format.as_str()),
        ) else {
            continue;
        };
        let decoded = match format {
            "hex" => hex::decode(value).ok(),
            "base64" => crate::decode::base64_decode(value).ok(),
            _ => None,
        };
        if let Some(decoded) = decoded {
            if decoded.len() > MAX_BYTE_ARRAY_LEN {
                record_static_limit("buffer byte ceiling");
                continue;
            }
            bindings.insert(name.as_str().to_owned(), decoded);
        }
    }
    bindings
}

fn collect_static_string_bindings(source: &str) -> HashMap<String, String> {
    let mut bindings = HashMap::new();
    for (binding_index, captures) in STRING_JOIN_BINDING_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS {
            record_static_limit("string binding ceiling");
            break;
        }
        let (Some(name), Some(array)) = (captures.get(1), captures.get(2)) else {
            continue;
        };
        let Ok(parts) = serde_json::from_str::<Vec<String>>(array.as_str()) else {
            continue;
        };
        let total_len = parts.iter().map(String::len).sum::<usize>();
        if parts.is_empty() || total_len > MAX_BYTE_ARRAY_LEN {
            if total_len > MAX_BYTE_ARRAY_LEN {
                record_static_limit("joined string byte ceiling");
            }
            continue;
        }
        bindings.insert(name.as_str().to_owned(), parts.concat());
    }
    bindings
}

fn decrypt_aes_256_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Option<String> {
    if key.len() != 32 || iv.len() != 16 || ciphertext.is_empty() {
        return None;
    }
    if ciphertext.len() > MAX_BYTE_ARRAY_LEN {
        record_static_limit("AES ciphertext byte ceiling");
        return None;
    }
    if !ciphertext.len().is_multiple_of(16) {
        return None;
    }

    let cipher = Aes256::new_from_slice(key).ok()?;
    let mut previous = <[u8; 16]>::try_from(iv).ok()?;
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for encrypted in ciphertext.chunks_exact(16) {
        let encrypted_block = <[u8; 16]>::try_from(encrypted).ok()?;
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
        return None;
    }
    plaintext.truncate(plaintext.len() - padding);
    String::from_utf8(plaintext).ok()
}
