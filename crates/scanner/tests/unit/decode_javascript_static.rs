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

fn hex_xor_program() -> String {
    let key = [19u8, 71, 211, 4, 99, 28, 8];
    let data: Vec<u8> = SECRET
        .as_bytes()
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key_byte)| byte ^ key_byte)
        .collect();
    let literals = |values: &[u8]| {
        values
            .iter()
            .map(|value| format!("0x{value:02x}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "const _d = [{}]; const _k = [{}]; return String.fromCharCode(..._d.map((b, i) => b ^ _k[i % _k.length]));",
        literals(&data),
        literals(&key)
    )
}

fn decode(source: String) -> Vec<Chunk> {
    decode_at(source, 0)
}

fn decode_at(source: String, base_offset: usize) -> Vec<Chunk> {
    JavaScriptStaticDecoder.decode_chunk(&Chunk {
        data: source.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            base_offset,
            ..Default::default()
        },
    })
}

#[test]
fn static_recovery_fails_closed_when_expression_offset_overflows() {
    assert_eq!(decode_at(xor_program(false, true), 4096).len(), 1);
    assert!(
        decode_at(xor_program(false, true), usize::MAX).is_empty(),
        "a recoverable expression without a representable source offset must not emit misattributed plaintext"
    );
}

#[test]
fn recovers_static_xor_byte_arrays() {
    let decoded = decode(xor_program(false, true));
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].data.as_ref(), SECRET);
}

#[test]
fn recovers_static_xor_hex_byte_arrays() {
    let decoded = decode(hex_xor_program());
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].data.as_ref(), SECRET);
}

#[test]
fn rejects_out_of_range_hex_byte_array_elements() {
    let source = concat!(
        "const _d = [0x100]; const _k = [0x01]; ",
        "return String.fromCharCode(..._d.map((b, i) => b ^ _k[i % _k.length]));"
    );
    assert!(decode(source.to_string()).is_empty());
}

#[test]
fn recovers_base64_json_xor_byte_arrays() {
    let decoded = decode(xor_program(true, true));
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].data.as_ref(), SECRET);
}

#[test]
fn recovers_xor_with_whitespace_around_member_access() {
    let source = xor_program(false, true).replace("String.fromCharCode", "String . fromCharCode");
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
