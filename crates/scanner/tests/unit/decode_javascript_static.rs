use super::*;
use base64::Engine;
use keyhog_core::ChunkMetadata;

const SECRET: &str = concat!("ghp_", "69121b4cdeeff121c88dffac1f9dbc2giIjE");

const UPSTREAM_CRYPTOJS_AES: &str = concat!(
    "const CryptoJS = require(\"crypto-js\");\n",
    "function decryptAES(encryptedData, keyMaterial) {\n",
    "  const bytes = CryptoJS.AES.decrypt(encryptedData, keyMaterial);\n",
    "  return bytes.toString(CryptoJS.enc.Utf8);\n",
    "}\n",
    "let secretKey = \"mySecretKey123\";\n",
    "let encryptedMessage = \"U2FsdGVkX1/A/6wHmBj8+Fry+QrYVv97+87j7QLl5ZY=\";\n",
    "let decryptedMessage = decryptAES(encryptedMessage, secretKey);\n",
    "console.log(decryptedMessage);",
);

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

fn reverse_base64_literal(plaintext: &str) -> String {
    let reversed: String = plaintext.chars().rev().collect();
    base64::engine::general_purpose::STANDARD
        .encode(reversed)
        .chars()
        .rev()
        .collect()
}

fn reverse_base64_program(function: &str, parameter: &str, plaintext: &str) -> String {
    let encoded = reverse_base64_literal(plaintext);
    format!(
        "function {function}({parameter}) {{ return {parameter}.split('').reverse().join(''); }}\n\
         const recovered = {function}(atob('{encoded}'.split('').reverse().join('')));\n\
         console.log(recovered);"
    )
}

#[test]
fn reverse_base64_recovers_exact_literal_with_provenance() {
    let source = reverse_base64_program("decodeString", "str", SECRET);
    let encoded = reverse_base64_literal(SECRET);
    let base_offset = 8192;
    let decoded = decode_at(source.clone(), base_offset);
    assert_eq!(decoded.len(), 1);
    let span = decoded[0]
        .metadata
        .decoded_span
        .expect("reverse/Base64 recovery carries the spliced literal span");
    assert_eq!(&decoded[0].data[span.0..span.1], SECRET);
    assert_eq!(
        decoded[0].metadata.base_offset + span.0,
        base_offset + source.find(&encoded).expect("encoded literal provenance")
    );
    assert_eq!(
        decoded[0].metadata.source_type.as_ref(),
        "test/javascript-static"
    );
}

#[test]
fn recovers_upstream_reverse_base64_transform_semantics() {
    let upstream_ioc = "192.168.17.65";
    let decoded = decode(reverse_base64_program("decodeString", "str", upstream_ioc));
    assert_eq!(decoded.len(), 1);
    let span = decoded[0].metadata.decoded_span.expect("recovered span");
    assert_eq!(&decoded[0].data[span.0..span.1], upstream_ioc);
}

#[test]
fn reverse_base64_accepts_scope_safe_identifier_renaming() {
    let decoded = decode(reverse_base64_program("_decode", "_value", SECRET));
    assert_eq!(decoded.len(), 1);
    let span = decoded[0].metadata.decoded_span.expect("recovered span");
    assert_eq!(&decoded[0].data[span.0..span.1], SECRET);
}

#[test]
fn reverse_base64_rejects_alias_mutation_dynamic_and_changed_operators() {
    let valid = reverse_base64_program("decodeString", "str", SECRET);
    assert!(
        decode(valid.replace("const recovered = decodeString", "const recovered = other"))
            .is_empty()
    );
    assert!(decode(valid.replace(
        "const recovered =",
        "decodeString = other; const recovered ="
    ))
    .is_empty());
    assert!(
        decode(valid.replace("const recovered =", "const atob = other; const recovered ="))
            .is_empty()
    );
    assert!(decode(valid.replace(
        "const recovered =",
        "String.prototype.reverse = other; const recovered ="
    ))
    .is_empty());
    assert!(decode(valid.replace(
        "const recovered =",
        "globalThis['atob'] = other; const recovered ="
    ))
    .is_empty());
    assert!(decode(valid.replace(
        "const recovered =",
        "String.prototype['reverse'] = other; const recovered ="
    ))
    .is_empty());

    let encoded = reverse_base64_literal(SECRET);
    let dynamic = valid.replace(&format!("'{encoded}'.split('')"), "encoded.split('')");
    assert!(decode(format!("const encoded = '{encoded}'; {dynamic}")).is_empty());
    assert!(decode(valid.replacen(".join('')", ".join('-')", 1)).is_empty());
    assert!(decode(valid.rsplit_once(".join('')").map_or_else(
        || valid.clone(),
        |(prefix, suffix)| format!("{prefix}.join('-'){suffix}")
    ))
    .is_empty());
}

#[test]
fn reverse_base64_rejects_non_code_malformed_and_oversized_candidates() {
    let valid = reverse_base64_program("decodeString", "str", SECRET);
    assert!(decode(format!("/* {valid} */")).is_empty());

    let encoded = reverse_base64_literal(SECRET);
    let helper_end = valid.find('\n').expect("helper line");
    let helper = &valid[..helper_end];
    let quoted = format!(
        "{helper}\nconst decoy = \"decodeString(atob('{encoded}'.split('').reverse().join('')))\";"
    );
    assert!(decode(quoted).is_empty());

    let regex = format!(
        "{helper}\nconst decoy = /decodeString\\(atob\\('{encoded}'\\.split\\(''\\)\\.reverse\\(\\)\\.join\\(''\\)\\)\\)/;"
    );
    assert!(decode(regex).is_empty());

    let malformed = valid.replace(&encoded, "====");
    assert!(decode(malformed).is_empty());

    let oversized = "A".repeat(MAX_BYTE_ARRAY_LEN * 4 + 1);
    let oversized_source = format!(
        "{helper}\nconst recovered = decodeString(atob('{oversized}'.split('').reverse().join('')));"
    );
    assert!(decode(oversized_source).is_empty());
}

#[test]
fn reverse_base64_rejects_inaccessible_helper_and_offset_overflow() {
    let valid = reverse_base64_program("decodeString", "str", SECRET);
    assert!(
        decode(valid.replacen("function decodeString", "{ function decodeString", 1) + " }")
            .is_empty()
    );
    assert_eq!(decode_at(valid.clone(), usize::MAX).len(), 0);
    assert_eq!(decode_at(valid, 4096).len(), 1);
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
fn cryptojs_recovery_fails_closed_when_expression_offset_overflows() {
    assert_eq!(decode_at(UPSTREAM_CRYPTOJS_AES.to_owned(), 4096).len(), 1);
    assert!(
        decode_at(UPSTREAM_CRYPTOJS_AES.to_owned(), usize::MAX).is_empty(),
        "CryptoJS recovery without a representable source offset must not emit plaintext"
    );
}

#[test]
fn recovers_upstream_cryptojs_passphrase_aes_example() {
    let base_offset = 4096;
    let decoded = decode_at(UPSTREAM_CRYPTOJS_AES.to_owned(), base_offset);
    assert_eq!(decoded.len(), 1);
    let span = decoded[0]
        .metadata
        .decoded_span
        .expect("CryptoJS recovery carries its exact spliced span");
    assert_eq!(&decoded[0].data[span.0..span.1], "192.168.17.65");
    let call_start = UPSTREAM_CRYPTOJS_AES
        .find("decryptAES(encryptedMessage, secretKey)")
        .expect("fixed decrypt invocation");
    assert_eq!(
        decoded[0].metadata.base_offset + span.0,
        base_offset + call_start
    );
    assert!(
        decoded[0]
            .data
            .contains("let decryptedMessage = 192.168.17.65;"),
        "splicing only the invocation must preserve assignment context"
    );
}

#[test]
fn cryptojs_recovery_rejects_ambiguous_semantic_bindings() {
    let duplicate_parameter = UPSTREAM_CRYPTOJS_AES
        .replace(
            "function decryptAES(encryptedData, keyMaterial)",
            "function decryptAES(encryptedData, encryptedData)",
        )
        .replace(
            "AES.decrypt(encryptedData, keyMaterial)",
            "AES.decrypt(encryptedData, encryptedData)",
        );
    assert!(decode(duplicate_parameter).is_empty());

    let output_parameter_collision = UPSTREAM_CRYPTOJS_AES
        .replace("const bytes =", "const encryptedData =")
        .replace("return bytes.toString", "return encryptedData.toString");
    assert!(decode(output_parameter_collision).is_empty());
}

#[test]
fn cryptojs_recovery_rejects_inaccessible_lexical_bindings() {
    let inaccessible_require = UPSTREAM_CRYPTOJS_AES.replace(
        "const CryptoJS = require(\"crypto-js\");",
        "{ const CryptoJS = require(\"crypto-js\"); }",
    );
    assert!(decode(inaccessible_require).is_empty());

    let inaccessible_ciphertext = UPSTREAM_CRYPTOJS_AES.replace(
        "let encryptedMessage = \"U2FsdGVkX1/A/6wHmBj8+Fry+QrYVv97+87j7QLl5ZY=\";",
        "{ let encryptedMessage = \"U2FsdGVkX1/A/6wHmBj8+Fry+QrYVv97+87j7QLl5ZY=\"; }",
    );
    assert!(decode(inaccessible_ciphertext).is_empty());

    let shadowed_passphrase = UPSTREAM_CRYPTOJS_AES.replace(
        "let decryptedMessage",
        "{ let secretKey = \"replacement\"; }\nlet decryptedMessage",
    );
    assert!(decode(shadowed_passphrase).is_empty());
}

#[test]
fn cryptojs_recovery_rejects_dynamic_or_non_code_candidates() {
    let dynamic_eval = UPSTREAM_CRYPTOJS_AES.replace(
        "let secretKey = \"mySecretKey123\";",
        "eval(\"let secret\" + \"Key = \\\"mySecretKey123\\\";\");",
    );
    assert!(decode(dynamic_eval).is_empty());

    let function_constructor = format!("Function(\"return 1\")();\n{UPSTREAM_CRYPTOJS_AES}");
    assert!(decode(function_constructor).is_empty());

    let template_literal = format!("const unsupported = `value`;\n{UPSTREAM_CRYPTOJS_AES}");
    assert!(decode(template_literal).is_empty());

    let escaped_identifier = UPSTREAM_CRYPTOJS_AES.replace(
        "let decryptedMessage",
        "secr\\u0065tKey = \"replacement\"; let decryptedMessage",
    );
    assert!(decode(escaped_identifier).is_empty());

    let commented_function = UPSTREAM_CRYPTOJS_AES.replace(
        "function decryptAES(encryptedData, keyMaterial) {\n  const bytes = CryptoJS.AES.decrypt(encryptedData, keyMaterial);\n  return bytes.toString(CryptoJS.enc.Utf8);\n}",
        "/* function decryptAES(encryptedData, keyMaterial) {\n  const bytes = CryptoJS.AES.decrypt(encryptedData, keyMaterial);\n  return bytes.toString(CryptoJS.enc.Utf8);\n} */",
    );
    assert!(decode(commented_function).is_empty());
}

#[test]
fn cryptojs_recovery_ignores_identifiers_and_braces_inside_regex_literals() {
    let source = format!(
        "const marker = /CryptoJS[{{}}\\/ let ghost = decryptAES(encryptedMessage, secretKey);]/giu;\n{UPSTREAM_CRYPTOJS_AES}"
    );
    let decoded = decode(source);
    assert_eq!(decoded.len(), 1);
    let span = decoded[0]
        .metadata
        .decoded_span
        .expect("recovered plaintext span");
    assert_eq!(&decoded[0].data[span.0..span.1], "192.168.17.65");

    let invalid_flags = format!("const marker = /safe/gg;\n{UPSTREAM_CRYPTOJS_AES}");
    assert!(
        decode(invalid_flags).is_empty(),
        "a regex that makes Node reject the program cannot be treated as inert"
    );

    let escaped_newline = format!("const marker = /safe\\\ntext/;\n{UPSTREAM_CRYPTOJS_AES}");
    assert!(decode(escaped_newline).is_empty());
}

#[test]
fn cryptojs_recovery_rejects_side_effects_fake_loaders_and_control_flow() {
    let monkeypatched = UPSTREAM_CRYPTOJS_AES.replace(
        "let decryptedMessage",
        "require(\"crypto-js\").AES.decrypt = () => ({ toString: () => \"different\" });\nlet decryptedMessage",
    );
    assert!(decode(monkeypatched).is_empty());

    let fake_loader = format!(
        "function wrapper(require) {{\n{UPSTREAM_CRYPTOJS_AES}\n}}\nwrapper(() => ({{}}));"
    );
    assert!(decode(fake_loader).is_empty());

    let computed_eval = UPSTREAM_CRYPTOJS_AES.replace(
        "let decryptedMessage",
        "globalThis[\"ev\" + \"al\"](\"throw 0\");\nlet decryptedMessage",
    );
    assert!(decode(computed_eval).is_empty());

    let conditional = UPSTREAM_CRYPTOJS_AES.replace(
        "let decryptedMessage",
        "if (true) { console.log(\"side effect\"); }\nlet decryptedMessage",
    );
    assert!(decode(conditional).is_empty());

    for terminator in ["\r", "\u{2028}", "\u{2029}"] {
        let comment_escape = UPSTREAM_CRYPTOJS_AES.replace(
            "let decryptedMessage",
            &format!(
                "// apparently inert{terminator}require(\"crypto-js\").AES.decrypt = () => ({{}});\nlet decryptedMessage"
            ),
        );
        assert!(
            decode(comment_escape).is_empty(),
            "every JavaScript line terminator must end a line comment"
        );
    }
}

#[test]
fn cryptojs_recovery_rejects_base64url_ciphertext() {
    let urlsafe = UPSTREAM_CRYPTOJS_AES.replacen('/', "_", 1);
    assert_ne!(urlsafe, UPSTREAM_CRYPTOJS_AES);
    assert!(decode(urlsafe).is_empty());
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
