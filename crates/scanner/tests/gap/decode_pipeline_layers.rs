//! Integration tests for the decode-through pipeline (`keyhog_scanner::testing::decode_chunk`)
//! and the per-encoding primitives it composes.
//!
//! Coverage: every registered decoder (base64, hex, url-percent, JSON-unescape,
//! MIME encoded-word, octal-escape, unicode-escape, html named /
//! numeric entity, quoted-printable, z85, reverse, caesar) must surface a
//! planted secret either standalone or behind nested encoding layers, and the
//! per-root fan-out / wall-clock budget must bound a pathological input.
//!
//! Every expected value here is derived by reading
//! `crates/scanner/src/decode/*`:
//!   - `pipeline.rs`        : decode_chunk BFS, depth/dedup/budget, splice shape,
//!                            source_type = "{parent}/{decoder}".
//!   - `base64.rs`          : Base64Decoder floor 12, classify_base64 padding
//!                            rules, z85_decode 5-byte grouping.
//!   - `hex.rs`             : HexDecoder floor 16, `_` stripping, even-length.
//!   - `url.rs`             : url/qp/mime/octal/html entity decoders.
//!   - `json.rs`            : JSON-string escape extraction (>=4 content bytes).
//!   - `unicode_escape.rs`  : \uXXXX / \xXX.
//!   - `reverse.rs`         : >=16 chars + reversed contains a KNOWN_PREFIX.
//!   - `caesar.rs`          : >=16, non-source path, decoded contains a
//!                            KNOWN_PREFIX + digit + 8-alnum run.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::decode::{
    base64_decode, find_base64_strings, find_hex_strings, hex_decode, z85_decode,
};
use keyhog_scanner::testing::decode_caesar::{
    caesar_shift, is_source_code_path, looks_credential_shaped,
};
use keyhog_scanner::testing::{decode_chunk, AlphabetScreen};
use keyhog_scanner::testing::{looks_reversible, reverse_str};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a chunk with a neutral, non-source-code path so the Caesar
/// source-code gate (`is_source_code_path`) never short-circuits the pipeline.
fn chunk(data: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            path: Some("audit.log".into()),
            ..Default::default()
        },
    }
}

/// True if ANY decoded chunk's data contains `needle`.
fn any_decoded_contains(out: &[Chunk], needle: &str) -> bool {
    out.iter().any(|c| c.data.as_ref().contains(needle))
}

/// The first decoded chunk whose data contains `needle`, if any.
fn find_decoded<'a>(out: &'a [Chunk], needle: &str) -> Option<&'a Chunk> {
    out.iter().find(|c| c.data.as_ref().contains(needle))
}

/// Standard production decode-through call shape: depth 3, no validation, no
/// caller deadline, no screen (every decoded chunk is returned).
fn decode_all(c: &Chunk) -> Vec<Chunk> {
    decode_chunk(c, 3, false, None, None)
}

// A planted AWS access-key-id shaped secret; "AKIA" is in KNOWN_PREFIXES and it
// carries a digit + a long alnum run, which the reverse/caesar gates require.
const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

// ===========================================================================
// base64 primitive (base64_decode / classify_base64 / find_base64_strings)
// ===========================================================================

#[test]
fn base64_decode_standard_padded_roundtrips() {
    // "AKIAIOSFODNN7EXAMPLE" base64 == this 28-char standard-padded blob.
    let decoded = base64_decode("QUtJQUlPU0ZPRE5ON0VYQU1QTEU=").expect("valid standard base64");
    assert_eq!(decoded, SECRET.as_bytes());
}

#[test]
fn base64_decode_url_safe_no_pad_roundtrips() {
    // "-_-_" carries BOTH url-safe sigils (`-` and `_`), no padding, len%4==0,
    // so classify_base64 -> UrlSafeNoPad. URL_SAFE_NO_PAD decodes it to the
    // 3 bytes 0xFB 0xFF 0xBF.
    let decoded = base64_decode("-_-_").expect("valid url-safe no-pad base64");
    assert_eq!(decoded, &[0xFB, 0xFF, 0xBF]);
}

#[test]
fn base64_decode_no_pad_standard_alphabet_roundtrips() {
    // "aGVsbG8hIQ" has no url-safe/standard sigils and no '=' padding, len%4==2,
    // so classify_base64 -> StandardNoPad. Decodes to b"hello!!".
    let decoded = base64_decode("aGVsbG8hIQ").expect("valid standard no-pad base64");
    assert_eq!(decoded, b"hello!!");
}

#[test]
fn base64_decode_rejects_mixed_standard_and_urlsafe_alphabets() {
    // classify_base64: `has_standard && has_urlsafe` -> None -> Err.
    assert!(base64_decode("ab+cd-ef").is_err());
}

#[test]
fn base64_decode_rejects_padding_in_middle() {
    // has_valid_base64_padding: chars before first '=' must contain no '='.
    assert!(base64_decode("QU=tJQUlP").is_err());
}

#[test]
fn base64_decode_rejects_leading_padding() {
    // first_padding > 0 required.
    assert!(base64_decode("====").is_err());
}

#[test]
fn base64_decode_rejects_impossible_unpadded_length() {
    // len % 4 == 1 cannot decode as base64; admitting it wastes decode-through
    // work and lets duplicate classifiers drift from the canonical decoder.
    assert!(base64_decode("QUtJQUlPU0ZPRE5ON").is_err());
}

#[test]
fn base64_decode_rejects_oversize_input() {
    // MAX_BASE64_INPUT_LEN == 16 MiB; one byte over must Err before decoding.
    let big = "A".repeat(16 * 1024 * 1024 + 1);
    assert!(base64_decode(&big).is_err());
}

#[test]
fn find_base64_strings_honors_min_length_floor() {
    // Quoted candidate of 16 valid base64 chars is >= the floor 12.
    let found = find_base64_strings("token=\"QUtJQUlPU0ZPRE5O\"", 12);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, "QUtJQUlPU0ZPRE5O");
    // Same candidate is rejected when the floor exceeds its length.
    let none = find_base64_strings("token=\"QUtJQUlPU0ZPRE5O\"", 20);
    assert!(none.is_empty());
}

#[test]
fn find_base64_strings_rejects_invalid_padding_shape() {
    // "AB==CD" has padding mid-string -> classify_base64 None -> not a hit.
    let found = find_base64_strings("v=\"AB==CDEFGHIJKLMN\"", 4);
    assert!(found.iter().all(|e| e.value != "AB==CDEFGHIJKLMN"));
}

// ===========================================================================
// hex primitive (hex_decode / find_hex_strings)
// ===========================================================================

#[test]
fn hex_decode_roundtrips_secret() {
    // "AKIAIOSFODNN7EXAMPLE".hex() (40 chars).
    let decoded =
        hex_decode("414b4941494f53464f444e4e374558414d504c45").expect("valid even-length hex");
    assert_eq!(decoded, SECRET.as_bytes());
}

#[test]
fn hex_decode_strips_underscore_separators() {
    // hex.rs strips `_` before decoding: "41_4b_49_41" -> bytes "AKIA".
    let decoded = hex_decode("41_4b_49_41").expect("underscores stripped, even length");
    assert_eq!(decoded, b"AKIA");
}

#[test]
fn hex_decode_rejects_odd_length() {
    // cleaned length must be even.
    assert!(hex_decode("abc").is_err());
}

#[test]
fn hex_decode_rejects_non_hex_digit() {
    // hex_simd rejects 'g'.
    assert!(hex_decode("zz").is_err());
}

#[test]
fn find_hex_strings_floor_and_underscore_value_preserved() {
    // HexDecoder uses floor 16. find_hex_strings keeps the ORIGINAL value
    // (with `_`) so the splice can locate it in the parent.
    let found = find_hex_strings("key=41_4b_49_41_49_4f_53_46_4f_44", 16);
    assert_eq!(found.len(), 1);
    assert!(found[0].value.contains('_'));
    // Cleaned length 20 (>=16) and even -> accepted.
}

#[test]
fn find_hex_strings_rejects_below_floor() {
    let found = find_hex_strings("key=414b4941", 16);
    assert!(found.is_empty());
}

// ===========================================================================
// z85 primitive (z85_decode)
// ===========================================================================

#[test]
fn z85_decode_roundtrips_16_bytes() {
    // z85 of b"helloAKIA1234567" (16 bytes) == this 20-char blob.
    let decoded = z85_decode("xK#0@z:v2/k}$bJg=mfI").expect("valid z85, len multiple of 5");
    assert_eq!(decoded, b"helloAKIA1234567");
}

#[test]
fn z85_decode_rejects_non_multiple_of_five() {
    assert!(z85_decode("xK#0").is_err());
}

#[test]
fn z85_decode_rejects_out_of_alphabet_byte() {
    // 5-char input (multiple of 5) whose trailing space (0x20) is not in the
    // z85 alphabet -> z85_val returns Err -> decode fails.
    assert!(z85_decode("xK#0 ").is_err());
}

// ===========================================================================
// Single-layer surfacing through decode_chunk: each decoder reveals the secret
// ===========================================================================

#[test]
fn pipeline_surfaces_base64_single_layer() {
    let c = chunk("aws_secret = \"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\"");
    let out = decode_all(&c);
    let hit = find_decoded(&out, SECRET).expect("base64 layer must surface the secret");
    // Splice keeps the companion anchor adjacent to the decoded credential.
    assert!(hit.data.as_ref().contains("aws_secret"));
    // The original encoded blob must be replaced by the decoded text.
    assert!(!hit.data.as_ref().contains("QUtJQUlPU0ZPRE5ON0VYQU1QTEU"));
    // source_type records the decoder that produced it.
    assert!(hit.metadata.source_type.ends_with("/base64"));
}

#[test]
fn pipeline_surfaces_hex_single_layer() {
    let c = chunk("apikey: 414b4941494f53464f444e4e374558414d504c45");
    let out = decode_all(&c);
    let hit = find_decoded(&out, SECRET).expect("hex layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/hex"));
    assert!(hit.data.as_ref().contains("apikey"));
}

#[test]
fn pipeline_surfaces_url_percent_single_layer() {
    // Freestanding percent run captured by extract_encoded_values' pct_block.
    let c = chunk("token=%41%4B%49%41%49%4F%53%46%4F%44%4E%4E%37%45%58%41%4D%50%4C%45");
    let out = decode_all(&c);
    let hit = find_decoded(&out, SECRET).expect("url-percent layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/url"));
}

#[test]
fn pipeline_surfaces_json_unescape_single_layer() {
    // JsonDecoder unescapes `\uXXXX`/`\"`-style escapes inside JSON strings.
    // Use a JSON-string value with a \" escape so extract_escaped_json_strings
    // (which only collects strings containing a backslash escape) picks it up.
    // "AKIA\"IOSFODNN7EXAMPLE" -> unescaped contains AKIA"IOSFODNN7EXAMPLE.
    let c = chunk(r#"{"api_key": "AKIA\"IOSFODNN7EXAMPLE"}"#);
    let out = decode_all(&c);
    // After JSON unescape the `\"` becomes a literal quote.
    assert!(any_decoded_contains(&out, "AKIA\"IOSFODNN7EXAMPLE"));
    assert!(out
        .iter()
        .any(|c| c.metadata.source_type.ends_with("/json")));
}

#[test]
fn pipeline_surfaces_mime_encoded_word_single_layer() {
    // =?utf-8?B?<base64>?= ; B-encoding base64-decodes the inner blob.
    let c = chunk("Subject: =?utf-8?B?QUtJQUlPU0ZPRE5ON0VYQU1QTEU=?=");
    let out = decode_all(&c);
    let hit = find_decoded(&out, SECRET).expect("mime encoded-word layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/mime-encoded-word"));
}

#[test]
fn pipeline_surfaces_octal_escape_single_layer() {
    // \ddd octal escapes for "sk_test_12345678"; contains_octal_escape requires
    // a backslash + 3 octal digits run, which each \163 etc. satisfies.
    let planted = "sk_test_12345678";
    let c = chunk(
        "secret=\\163\\153\\137\\164\\145\\163\\164\\137\\061\\062\\063\\064\\065\\066\\067\\070",
    );
    let out = decode_all(&c);
    let hit = find_decoded(&out, planted).expect("octal-escape layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/octal-escape"));
}

#[test]
fn pipeline_surfaces_hex_escape_single_layer() {
    // \xXX escapes are owned by UnicodeEscapeDecoder, same as \uXXXX.
    let c = chunk(
        "secret=\\x41\\x4b\\x49\\x41\\x49\\x4f\\x53\\x46\\x4f\\x44\\x4e\\x4e\\x37\\x45\\x58\\x41\\x4d\\x50\\x4c\\x45",
    );
    let out = decode_all(&c);
    let hit = find_decoded(&out, SECRET).expect("unicode-escape layer must surface \\x secrets");
    assert!(hit.metadata.source_type.ends_with("/unicode-escape"));
}

#[test]
fn pipeline_surfaces_unicode_escape_single_layer() {
    // \uXXXX escapes for "ghp_TESTKEY12345".
    let planted = "ghp_TESTKEY12345";
    let c = chunk(
        "k=\\u0067\\u0068\\u0070\\u005f\\u0054\\u0045\\u0053\\u0054\\u004b\\u0045\\u0059\\u0031\\u0032\\u0033\\u0034\\u0035",
    );
    let out = decode_all(&c);
    assert!(any_decoded_contains(&out, planted));
}

#[test]
fn pipeline_surfaces_html_numeric_entity_single_layer() {
    // &#NN; decimal numeric entities -> "AKIA1234".
    let c = chunk("v=&#65;&#75;&#73;&#65;&#49;&#50;&#51;&#52;");
    let out = decode_all(&c);
    let hit =
        find_decoded(&out, "AKIA1234").expect("html numeric entity layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/html-numeric-entity"));
}

#[test]
fn pipeline_surfaces_html_named_entity_single_layer() {
    // Named entities: html_named_entity_decode only changes when a known
    // entity is present. `&amp;` -> `&`. Plant a token where `&amp;` joins
    // two halves so the decoded text differs from the input.
    let c = chunk("note=\"A&amp;B&amp;C&amp;DEFGHIJK\"");
    let out = decode_all(&c);
    // Decoded contains the collapsed ampersands.
    assert!(any_decoded_contains(&out, "A&B&C&DEFGHIJK"));
    assert!(out
        .iter()
        .any(|c| c.metadata.source_type.ends_with("/html-named-entity")));
}

#[test]
fn pipeline_surfaces_quoted_printable_single_layer() {
    // Quoted-Printable: `=XX` hex. has_qp_escape requires a well-formed =XX.
    // "=41=4B=49=41" -> "AKIA". Whole-line is also pushed as candidate.
    let c = chunk("X-Token: =41=4B=49=41=49=4F=53=46");
    let out = decode_all(&c);
    let hit =
        find_decoded(&out, "AKIAIOSF").expect("quoted-printable layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/quoted-printable"));
}

#[test]
fn pipeline_quoted_printable_preserves_literal_equals_after_valid_escape() {
    let c = chunk("X-Token: ghp=5Fabcdefghijklmnopqrstuvwxyz1234567890AB status=ok");
    let out = decode_all(&c);
    let hit = find_decoded(&out, "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB")
        .expect("valid quoted-printable escape must survive a later literal assignment");
    assert!(
        hit.data.as_ref().contains("status=ok"),
        "literal non-hex assignment must be preserved after quoted-printable decode: {}",
        hit.data
    );
    assert!(hit.metadata.source_type.ends_with("/quoted-printable"));
}

#[test]
fn pipeline_surfaces_z85_single_layer() {
    // z85 of b"helloAKIA1234567".
    let c = chunk("blob=\"xK#0@z:v2/k}$bJg=mfI\"");
    let out = decode_all(&c);
    let hit = find_decoded(&out, "helloAKIA1234567").expect("z85 layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/z85"));
}

#[test]
fn pipeline_surfaces_reverse_single_layer() {
    // Reversed AWS key. looks_reversible: >=16 chars, 12+ alnum run, reversed
    // contains a 3+ char KNOWN_PREFIX ("AKIA").
    let reversed = "ELPMAXE7NNDOFSOIAIKA"; // reverse of AKIAIOSFODNN7EXAMPLE
    let c = chunk(&format!("token={reversed}"));
    let out = decode_all(&c);
    let hit = find_decoded(&out, SECRET).expect("reverse layer must surface the secret");
    assert!(hit.metadata.source_type.ends_with("/reverse"));
}

#[test]
fn pipeline_surfaces_caesar_single_layer() {
    // Caesar-shifted (+5) AWS key; decoder tries shift 21 to recover it.
    // looks_credential_shaped gate: decoded has a digit, an 8-alnum run, and
    // contains the "AKIA" KNOWN_PREFIX.
    let c = chunk("token=FPNFNTXKTISS7JCFRUQJ");
    let out = decode_all(&c);
    // Caesar uses the NON-spliced push: the chunk is the bare decoded value
    // (`SECRET` verbatim) and its source_type records the caesar decoder.
    assert!(
        out.iter()
            .any(|d| d.data.as_ref() == SECRET && d.metadata.source_type.ends_with("/caesar")),
        "caesar layer must surface the bare secret under a /caesar source_type"
    );
}

// ===========================================================================
// Nested layers
// ===========================================================================

#[test]
fn pipeline_surfaces_double_base64_nested() {
    // base64(base64("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345")).
    // L1 = Z2hwX2FCY0RlRmdIaUprTG1Ob1BxUnNUdVZ3WHlaMDEyMzQ1
    // L2 = WjJod1gyRkNZMFJsUm1kSWFVcHJURzFPYjFCeFVuTlVkVlozV0hsYU1ERXlNelEx
    let inner = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
    let l2 = "WjJod1gyRkNZMFJsUm1kSWFVcHJURzFPYjFCeFVuTlVkVlozV0hsYU1ERXlNelEx";
    let c = chunk(&format!("k=\"{l2}\""));
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        any_decoded_contains(&out, inner),
        "two base64 layers must surface the inner secret at depth>=2"
    );
}

#[test]
fn pipeline_double_base64_needs_depth_two() {
    // With max_depth=1 only the first layer (L2->L1) is emitted; the inner
    // secret behind the second layer must NOT yet appear.
    let inner = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
    let l1 = "Z2hwX2FCY0RlRmdIaUprTG1Ob1BxUnNUdVZ3WHlaMDEyMzQ1";
    let l2 = "WjJod1gyRkNZMFJsUm1kSWFVcHJURzFPYjFCeFVuTlVkVlozV0hsYU1ERXlNelEx";
    let c = chunk(&format!("k=\"{l2}\""));
    let depth1 = decode_chunk(&c, 1, false, None, None);
    assert!(
        any_decoded_contains(&depth1, l1),
        "depth-1 must surface the first decoded layer (L1)"
    );
    assert!(
        !any_decoded_contains(&depth1, inner),
        "depth-1 must NOT reach the inner secret behind the second layer"
    );
}

#[test]
fn pipeline_surfaces_hex_then_base64_nested() {
    // hex( base64("AKIAIOSFODNN7EXAMPLE") ).
    // base64 = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=" -> hex of that ASCII string.
    let b64 = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";
    let hex_of_b64: String = b64.bytes().map(|b| format!("{b:02x}")).collect();
    let c = chunk(&format!("k={hex_of_b64}"));
    let out = decode_chunk(&c, 3, false, None, None);
    // Layer 1 (hex) yields the base64 text; layer 2 (base64) yields the secret.
    assert!(
        any_decoded_contains(&out, b64),
        "hex layer must yield the base64 text"
    );
    assert!(
        any_decoded_contains(&out, SECRET),
        "nested hex->base64 must surface the secret"
    );
}

#[test]
fn pipeline_surfaces_url_then_base64_nested() {
    // url-percent( base64("AKIAIOSFODNN7EXAMPLE") ): percent-encode the base64.
    let b64 = "QUtJQUlPU0ZPRE5ON0VYQU1QTEU=";
    let pct: String = b64.bytes().map(|b| format!("%{b:02X}")).collect();
    let c = chunk(&format!("k={pct}"));
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        any_decoded_contains(&out, b64),
        "url layer must yield base64 text"
    );
    assert!(
        any_decoded_contains(&out, SECRET),
        "nested url->base64 must surface the secret"
    );
}

// ===========================================================================
// Depth / dedup / source_type semantics
// ===========================================================================

#[test]
fn pipeline_depth_zero_returns_nothing() {
    // queue starts at depth 0; `depth >= max_depth` (0 >= 0) skips immediately.
    let c = chunk("k=\"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\"");
    let out = decode_chunk(&c, 0, false, None, None);
    assert!(out.is_empty(), "max_depth=0 must produce no decoded chunks");
}

#[test]
fn pipeline_never_reemits_the_root_chunk() {
    // The root data hash is pre-seeded into `seen`, so no decoded chunk equals
    // the root verbatim.
    let root = "k=\"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\"";
    let c = chunk(root);
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        out.iter().all(|d| d.data.as_ref() != root),
        "the original root chunk must never be re-emitted"
    );
}

#[test]
fn pipeline_decoded_chunks_are_unique_by_data() {
    // The `seen` HashSet dedups by data hash, so emitted chunks are distinct.
    let c = chunk("a=\"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\" b=\"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\"");
    let out = decode_chunk(&c, 3, false, None, None);
    let mut datas: Vec<&str> = out.iter().map(|c| c.data.as_ref()).collect();
    let before = datas.len();
    datas.sort_unstable();
    datas.dedup();
    assert_eq!(before, datas.len(), "decoded chunks must be unique by data");
}

#[test]
fn pipeline_nested_source_type_chains_decoder_names() {
    // A 2-layer base64 decode produces a chunk whose source_type chains both
    // decoder names: "<parent>/base64/base64".
    let l2 = "WjJod1gyRkNZMFJsUm1kSWFVcHJURzFPYjFCeFVuTlVkVlozV0hsYU1ERXlNelEx";
    let mut c = chunk(&format!("k=\"{l2}\""));
    c.metadata.source_type = "file".into();
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        out.iter()
            .any(|d| d.metadata.source_type == "file/base64/base64"),
        "nested decode must chain decoder names in source_type"
    );
    // The first layer is recorded as exactly "file/base64".
    assert!(out.iter().any(|d| d.metadata.source_type == "file/base64"));
}

#[test]
fn pipeline_inherits_parent_path_and_offset() {
    // Decoded chunks inherit the parent's path; base_offset is anchored to the
    // parent (>= parent base_offset since the splice only shifts forward).
    let mut c = chunk("k=\"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\"");
    c.metadata.base_offset = 4096;
    let out = decode_chunk(&c, 3, false, None, None);
    let hit = find_decoded(&out, SECRET).expect("secret surfaces");
    assert_eq!(hit.metadata.path.as_deref(), Some("audit.log"));
    assert!(hit.metadata.base_offset >= 4096);
}

// ===========================================================================
// validate=true drops NUL-containing decodes
// ===========================================================================

/// Build standard base64 of `bytes` (with `=` padding) using the canonical
/// alphabet, so test fixtures never depend on a hand-miscomputed literal.
fn b64_standard(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b0 = c[0] as u32;
        let b1 = *c.get(1).unwrap_or(&0) as u32;
        let b2 = *c.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[test]
fn pipeline_spliced_decode_base_line_tracks_window_start() {
    let padding = (0..120)
        .map(|i| format!("noise line {i:03}\n"))
        .collect::<String>();
    let blob = b64_standard(SECRET.as_bytes());
    let text = format!("{padding}aws_secret_access_key = \"{blob}\"\n");
    let c = Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            base_line: 7,
            path: Some("audit.log".into()),
            ..Default::default()
        },
    };

    let out = decode_all(&c);
    let hit = find_decoded(&out, SECRET).expect("spliced base64 secret decoded");
    let window_start = hit.metadata.base_offset - c.metadata.base_offset;
    let expected_base_line = c.metadata.base_line
        + c.data.as_ref().as_bytes()[..window_start]
            .iter()
            .filter(|&&b| b == b'\n')
            .count();

    assert!(
        window_start > 0,
        "fixture must force a nonzero splice window start"
    );
    assert_eq!(
        hit.metadata.base_line, expected_base_line,
        "decoded splice base_line must account for parent lines before the retained window"
    );
}

#[test]
fn pipeline_never_emits_nul_byte_decodes_under_either_validate_mode() {
    // base64 of bytes containing a NUL. `push_decoded_text_chunk_spliced`
    // rejects any decoded text with a control byte < 0x20 (except \n\r\t),
    // which includes NUL (0x00). So NO decoder ever emits a NUL-bearing chunk,
    // independent of the `validate` flag.
    let blob = b64_standard(b"AB\0CDEFGH");
    // Sanity: the blob really does base64-decode to bytes containing a NUL.
    assert!(base64_decode(&blob).unwrap().contains(&0u8));

    let c = chunk(&format!("k=\"{blob}\""));
    let validated = decode_chunk(&c, 3, true, None, None);
    let unvalidated = decode_chunk(&c, 3, false, None, None);

    assert!(
        validated.iter().all(|d| !d.data.as_bytes().contains(&0u8)),
        "no decoded chunk may contain a NUL byte (validate=true)"
    );
    assert!(
        unvalidated
            .iter()
            .all(|d| !d.data.as_bytes().contains(&0u8)),
        "no decoded chunk may contain a NUL byte (validate=false): the push \
         helper's control-byte filter already drops it"
    );
    // FINDING: decode_chunk's own `validate && contains(0u8)` guard
    // (pipeline.rs:163-165) is unreachable for NUL bytes because every decoder
    // funnels through push_decoded_text_chunk_spliced, which already rejects
    // control bytes < 0x20. The validate flag therefore does not change the
    // output for this NUL input.
    assert_eq!(
        validated.len(),
        unvalidated.len(),
        "validate flag is a no-op for NUL inputs (the spliced-push filter \
         already removed them upstream)"
    );
}

#[test]
fn pipeline_drops_other_control_byte_decodes() {
    // A decoded payload carrying 0x01 (SOH) is dropped by the push helper's
    // control-byte filter for BOTH validate modes -> not surfaced.
    let blob = b64_standard(b"AB\x01CDEFGH");
    assert!(base64_decode(&blob).unwrap().contains(&0x01u8));
    let c = chunk(&format!("k=\"{blob}\""));
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        out.iter().all(|d| !d.data.as_bytes().contains(&0x01u8)),
        "decoded chunks carrying control byte 0x01 must be dropped by the push filter"
    );
}

// ===========================================================================
// Per-decode budget bounds fan-out (MAX_DECODED_CHUNKS_PER_ROOT + caller deadline)
// ===========================================================================

#[test]
fn pipeline_fanout_bounded_under_per_root_cap() {
    // MAX_DECODED_CHUNKS_PER_ROOT == 1000. A dense chunk of distinct decodable
    // tokens cannot return more than the cap, regardless of decoder fan-out.
    let token = "a1b2c3d4e5f6g7h8,"; // 16 alnum + delimiter
    let mut data = String::with_capacity(256 * 1024);
    while data.len() < 256 * 1024 {
        data.push_str(token);
    }
    let c = chunk(&data);
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        out.len() <= 1000,
        "returned {} chunks; per-root fan-out cap (1000) must hold",
        out.len()
    );
}

#[test]
fn pipeline_wall_budget_bounds_pathological_input() {
    // A dense fan-out chunk must return well under a generous ceiling even with
    // a screen that rejects nearly everything. Default scans are bounded by
    // deterministic count/byte caps, not an implicit load-dependent timeout.
    use std::time::{Duration, Instant};
    let token = "a1b2c3d4e5f6g7h8,";
    let mut data = String::with_capacity(512 * 1024);
    while data.len() < 512 * 1024 {
        data.push_str(token);
    }
    let c = chunk(&data);
    let screen = AlphabetScreen::new(&["q".to_string()]);
    let start = Instant::now();
    let out = decode_chunk(&c, 3, false, None, Some(&screen));
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "decode_chunk ran {elapsed:?}; the per-root fan-out cap must bound it"
    );
    assert!(out.len() <= 1000);
}

#[test]
fn pipeline_caller_deadline_in_past_stops_immediately() {
    // An already-expired caller deadline fires on the first dequeue and the
    // pipeline returns essentially nothing.
    use std::time::Instant;
    let c = chunk("k=\"QUtJQUlPU0ZPRE5ON0VYQU1QTEU=\"");
    let past = Instant::now() - std::time::Duration::from_secs(1);
    let out = decode_chunk(&c, 3, false, Some(past), None);
    assert!(
        out.is_empty(),
        "an expired caller deadline must stop decode-through before any output"
    );
}

// ===========================================================================
// Negative / no-op behaviors (twins)
// ===========================================================================

#[test]
fn pipeline_plain_text_produces_no_decodes() {
    // No encoded run present -> no decoder fires.
    let c = chunk("the quick brown fox jumps over the lazy dog twice today");
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        out.is_empty(),
        "plain prose must produce zero decoded chunks"
    );
}

#[test]
fn pipeline_caesar_skipped_on_source_code_path() {
    // is_source_code_path(".rs") -> CaesarDecoder returns empty; the only path
    // that surfaces this Caesar-shifted blob is the caesar decoder, so a .rs
    // path must NOT surface the secret.
    let mut c = chunk("token=FPNFNTXKTISS7JCFRUQJ");
    c.metadata.path = Some("src/lib.rs".into());
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        !any_decoded_contains(&out, SECRET),
        "Caesar must be skipped on source-code paths"
    );
}

#[test]
fn pipeline_reverse_does_not_recurse_on_own_output() {
    // ReverseDecoder bails when source_type contains "/reverse". A chunk whose
    // source_type already records a reverse pass must yield no reverse output.
    let reversed = "ELPMAXE7NNDOFSOIAIKA";
    let mut c = chunk(&format!("token={reversed}"));
    c.metadata.source_type = "file/reverse".into();
    let out = decode_chunk(&c, 3, false, None, None);
    assert!(
        out.iter()
            .all(|d| !d.metadata.source_type.contains("/reverse/reverse")),
        "reverse must not recurse on its own output"
    );
}

// ===========================================================================
// Decoder gate primitives (pure functions)
// ===========================================================================

#[test]
fn looks_reversible_requires_known_prefix_after_reversal() {
    // reverse of "ELPMAXE7NNDOFSOIAIKA" == the AWS key -> contains "AKIA".
    assert!(looks_reversible("ELPMAXE7NNDOFSOIAIKA"));
    // A long alnum run with NO known prefix on reversal is rejected.
    assert!(!looks_reversible("ZYXWVUTSRQPONMLKJIHGFEDCBA"));
    // Below the 16-char floor.
    assert!(!looks_reversible("ELPMAXE7NND"));
}

#[test]
fn reverse_str_is_an_involution() {
    let s = "AKIAIOSFODNN7EXAMPLE";
    assert_eq!(reverse_str(&reverse_str(s)), s);
    assert_eq!(reverse_str("abc"), "cba");
}

#[test]
fn caesar_shift_wraps_alphabet_and_leaves_digits() {
    // shift 21 recovers the planted key; digits/punctuation are unchanged.
    assert_eq!(caesar_shift("FPNFNTXKTISS7JCFRUQJ", 21), SECRET);
    assert_eq!(caesar_shift("abc XYZ 123", 1), "bcd YZA 123");
    // shift 26 is the identity on letters.
    assert_eq!(caesar_shift("Hello123", 26), "Hello123");
}

#[test]
fn looks_credential_shaped_gates_on_digit_run_and_prefix() {
    // Real AWS key: digit + 8-alnum run + "AKIA" prefix -> shaped.
    assert!(looks_credential_shaped(SECRET));
    // No digit -> rejected even with a long run.
    assert!(!looks_credential_shaped(
        "AKIAIOSFODNNXEXAMPLE".replace('7', "X").as_str()
    ));
    // Has digit + run but no KNOWN_PREFIX substring -> rejected.
    assert!(!looks_credential_shaped("zzzz1234zzzzzzzz"));
}

#[test]
fn is_source_code_path_matches_extensions_and_filenames() {
    assert!(is_source_code_path(Some("src/main.rs")));
    assert!(is_source_code_path(Some("a/b/Makefile")));
    assert!(is_source_code_path(Some("DIR/Kconfig")));
    assert!(!is_source_code_path(Some("logs/audit.log")));
    assert!(!is_source_code_path(None));
    // Backslash paths are normalized.
    assert!(is_source_code_path(Some(r"src\app.py")));
}

// ===========================================================================
// Property-style loops (decode primitives are exact inverses of encoders)
// ===========================================================================

#[test]
fn proptest_hex_decode_inverts_lowercase_hex_encode() {
    // For a spread of byte patterns, lower-hex encode then hex_decode == input.
    for seed in 0u32..2000 {
        let n = (seed % 40) as usize; // 0..39 bytes
        let bytes: Vec<u8> = (0..n)
            .map(|i| ((seed.wrapping_mul(31) + i as u32) & 0xFF) as u8)
            .collect();
        let enc: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        // Empty input: even length (0) -> Ok(empty).
        let decoded = hex_decode(&enc).expect("lower-hex always decodes");
        assert_eq!(decoded, bytes, "hex roundtrip failed for seed {seed}");
    }
}

#[test]
fn proptest_base64_decode_inverts_standard_encode() {
    for seed in 1u32..1500 {
        let n = 1 + (seed % 30) as usize; // 1..30 bytes (skip empty: classify rejects "")
        let bytes: Vec<u8> = (0..n)
            .map(|i| ((seed.wrapping_mul(17) + i as u32) & 0xFF) as u8)
            .collect();
        let enc = b64_standard(&bytes);
        let decoded = base64_decode(&enc)
            .unwrap_or_else(|_| panic!("standard base64 must decode (seed {seed}, enc {enc})"));
        assert_eq!(decoded, bytes, "base64 roundtrip failed for seed {seed}");
    }
}

#[test]
fn proptest_caesar_shift_then_inverse_recovers_input() {
    // For every shift s, caesar_shift(caesar_shift(x, s), 26 - s) == x
    // on letters; digits/symbols are invariant under any shift.
    let samples = ["AKIAIOSFODNN7EXAMPLE", "Hello, World! 42", "zZaA09", ""];
    for x in samples {
        for s in 1u8..=25 {
            let enc = caesar_shift(x, s);
            let dec = caesar_shift(&enc, 26 - s);
            assert_eq!(dec, x, "caesar inverse failed for shift {s} on {x:?}");
        }
    }
}

#[test]
fn proptest_z85_decode_inverts_z85_encode_for_4byte_multiples() {
    const Z: &[u8; 85] =
        b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    let z85_enc = |bytes: &[u8]| -> String {
        assert!(bytes.len() % 4 == 0);
        let mut out = String::new();
        for c in bytes.chunks(4) {
            let mut val = ((c[0] as u32) << 24)
                | ((c[1] as u32) << 16)
                | ((c[2] as u32) << 8)
                | (c[3] as u32);
            let mut tmp = [0u8; 5];
            for j in (0..5).rev() {
                tmp[j] = Z[(val % 85) as usize];
                val /= 85;
            }
            for b in tmp {
                out.push(b as char);
            }
        }
        out
    };
    for seed in 1u32..1200 {
        let groups = 1 + (seed % 8) as usize; // 1..8 groups of 4 bytes
        let n = groups * 4;
        let bytes: Vec<u8> = (0..n)
            .map(|i| ((seed.wrapping_mul(13) + i as u32) & 0xFF) as u8)
            .collect();
        let enc = z85_enc(&bytes);
        assert_eq!(enc.len() % 5, 0);
        let decoded = z85_decode(&enc).expect("z85 multiple-of-5 must decode");
        assert_eq!(decoded, bytes, "z85 roundtrip failed for seed {seed}");
    }
}
