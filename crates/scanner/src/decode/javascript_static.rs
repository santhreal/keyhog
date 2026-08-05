//! Bounded evaluation of static JavaScript secret-recovery expressions.
//!
//! This is deliberately not a JavaScript runtime. It recognizes a small,
//! side-effect-free grammar whose operands are fully embedded byte arrays and
//! whose result is therefore deterministic: `String.fromCharCode(...data.map(
//! (byte, index) => byte ^ key[index % key.length]))`. Both literal numeric
//! arrays and Base64-encoded JSON byte arrays are supported, along with a
//! bounded AES-256-CBC forms using literal buffers, empty-joined strings, or
//! an exact CryptoJS passphrase wrapper with an OpenSSL `Salted__` envelope.
//! Dynamic operands, mismatched identifiers, oversized programs, invalid
//! padding, and non-UTF-8 results fail closed while the original source remains
//! in the normal scan path.

use super::pipeline::push_decoded_text_chunk_spliced_at;
use super::{DecodeAdmissionSketch, DecodeOutputSink, Decoder};
use keyhog_core::{Chunk, ChunkMetadata};
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use crate::telemetry::{
    record_static_recovery_rejection, record_static_recovery_supported, StaticRecoveryRejection,
};

mod aes;
mod cryptojs;
mod reverse_base64;

const MAX_STATIC_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_BYTE_ARRAY_LEN: usize = 64 * 1024;
const MAX_ARRAY_BINDINGS: usize = 32;
const MAX_STATIC_EXPRESSIONS: usize = 64;

/// Binding keywords whose declarations these grammars read.
///
/// `var` is admitted HERE, and deliberately not in the CryptoJS grammar,
/// because every rule in this module additionally requires the bound
/// identifier to occur exactly twice in the whole source: the declaration and
/// the single use inside the recovered expression
/// ([`identifier_occurrence_count`]). Two occurrences leave no room for a
/// reassignment, a second declaration, or a sibling scope, so `var`'s
/// function-scope hoisting cannot make the wrong binding win and a reassigned
/// binding fails closed on the count alone. CryptoJS resolves names through
/// real scope analysis instead of counting, where hoisting would matter, so it
/// stays at `const|let`.
const BINDING_KEYWORD: &str = r"(?:const|let|var)";

/// String-literal delimiter: single quote, double quote, or backtick.
///
/// Widening the delimiter is safe because [`unquote_static_string`] is the only
/// way a captured literal becomes bytes, and it requires the opening and
/// closing delimiter to match and refuses a backtick literal that carries
/// interpolation or an escape. The character classes inside each literal
/// exclude `$`, `{`, and `\` anyway, so an interpolated template cannot even
/// reach that check.
const QUOTE: &str = r#"["'`]"#;

/// A quoted keyword operand (encoding label, cipher algorithm) in any
/// delimiter and any ASCII case. Node accepts `'BASE64'`, `"Utf8"`, and
/// `AES-256-CBC` identically, so recognizing only the lowercase spelling is a
/// recall hole, not a safety boundary: the allowlist that follows is what
/// bounds the operation.
fn quoted_label(pattern: &str) -> String {
    format!(r#"(?:'(?i:{pattern})'|"(?i:{pattern})"|`(?i:{pattern})`)"#)
}

/// `Buffer.from(literal, encoding)` and its deprecated but still executable
/// twin `new Buffer(literal, encoding)`. The size constructor
/// (`new Buffer(1024)`) cannot match any call site built from this because
/// every one of them requires a quoted first argument.
const BUFFER_CONSTRUCTOR: &str = r"(?:Buffer\s*\.\s*from|new\s+Buffer)";

/// One static-operation allowance for one source.
///
/// `MAX_STATIC_EXPRESSIONS` used to be re-enforced from zero inside each
/// grammar loop, so a file carrying XOR, bound-AES, and inline-AES
/// expressions could evaluate up to three times the ceiling the limit
/// advertises. This makes the ceiling mean what it says: 64 attempts per
/// source, in a fixed grammar order, shared by every grammar that spends it.
///
/// The 64th attempt is granted, so a source sitting exactly on the boundary
/// still recovers its last plaintext; the 65th is refused and reports one
/// coverage reason, not one per grammar.
struct StaticOperationBudget {
    remaining: usize,
    exhaustion_reported: bool,
}

impl StaticOperationBudget {
    fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exhaustion_reported: false,
        }
    }

    /// Spend one operation. Returns `false` once the source is out of budget,
    /// recording the coverage reason exactly once.
    fn take(&mut self) -> bool {
        if self.remaining == 0 {
            if !self.exhaustion_reported {
                self.exhaustion_reported = true;
                record_static_limit("static operation ceiling");
            }
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RecoveredPlaintext {
    plaintext: String,
    source_start: usize,
    source_end: usize,
}

fn append_spliced_recoveries(
    sink: &mut dyn DecodeOutputSink,
    chunk: &Chunk,
    recovered: BTreeSet<RecoveredPlaintext>,
    decoder: &'static str,
) -> bool {
    record_static_recovery_supported(recovered.len());
    for recovery in recovered {
        let Some(original) = chunk.data.get(recovery.source_start..recovery.source_end) else {
            continue;
        };
        if !push_decoded_text_chunk_spliced_at(
            sink,
            chunk,
            Some((recovery.source_start, recovery.source_end)),
            original,
            recovery.plaintext,
            decoder,
        ) {
            return false;
        }
    }
    true
}

static LITERAL_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        &format!(
            r"(?m)\b{BINDING_KEYWORD}\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\[((?:[\x20\t\r\n]*(?:0[xX][0-9A-Fa-f]+|[0-9]+)[\x20\t\r\n]*,)*[\x20\t\r\n]*(?:0[xX][0-9A-Fa-f]+|[0-9]+)[\x20\t\r\n]*,?[\x20\t\r\n]*)\]"
        ),
        "literal byte-array assignment",
    )
});

static BASE64_JSON_ARRAY_RE: LazyLock<Regex> = LazyLock::new(|| {
    let base64 = quoted_label("base64");
    // Node's `toString()` defaults to UTF-8 and accepts `utf8`, `utf-8`, and
    // any casing of either, so all four spellings are the same program.
    let utf8 = quoted_label("utf-?8");
    compile_static_regex(
        &format!(
            r"(?m)\b{BINDING_KEYWORD}\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*JSON\s*\.\s*parse\s*\(\s*{BUFFER_CONSTRUCTOR}\s*\(\s*({QUOTE}[A-Za-z0-9+/=_-]+{QUOTE})\s*,\s*{base64}\s*\)\s*\.\s*toString\s*\(\s*(?:{utf8})?\s*\)\s*\)"
        ),
        "Base64 JSON byte-array assignment",
    )
});

// `fromCodePoint` is `fromCharCode` for every scalar this grammar can produce:
// the operands are XOR results of two byte arrays, so every code point is in
// 0..=255 and the two functions agree exactly. Recognizing only one spelling
// dropped the other program on the floor.
const FROM_CHAR_CODE: &str = r"from(?:CharCode|CodePoint)";

static XOR_MAP_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        &format!(
            r"String\s*\.\s*{FROM_CHAR_CODE}\s*\(\s*\.\.\.\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*map\s*\(\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*=>\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\[\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*%\s*(?:(?:([A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*length)|([0-9]+))\s*\]\s*\)\s*\)"
        ),
        "static XOR map expression",
    )
});

static XOR_CANDIDATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    let computed = quoted_label(FROM_CHAR_CODE);
    compile_static_regex(
        &format!(r"String\s*(?:\.\s*{FROM_CHAR_CODE}|\[\s*{computed}\s*\])\s*\("),
        "static XOR candidate",
    )
});

static XOR_DYNAMIC_PROPERTY_RE: LazyLock<Regex> = LazyLock::new(|| {
    let computed = quoted_label(FROM_CHAR_CODE);
    compile_static_regex(
        &format!(r"String\s*\[\s*{computed}\s*\]\s*\("),
        "computed static XOR property",
    )
});

pub(super) struct JavaScriptStaticDecoder;

#[derive(Clone, Copy)]
struct StaticExpressionKinds {
    xor: bool,
    node_aes: bool,
    cryptojs_aes: bool,
    reverse_base64: bool,
}

impl StaticExpressionKinds {
    fn any(self) -> bool {
        self.xor || self.node_aes || self.cryptojs_aes || self.reverse_base64
    }
}

fn static_expression_kinds(data: &str) -> StaticExpressionKinds {
    StaticExpressionKinds {
        xor: (data.contains("fromCharCode") || data.contains("fromCodePoint"))
            && data.contains('^'),
        // Node's cipher name is case-insensitive, so the admission gate has to
        // be too, or `AES-256-CBC` never reaches the grammar that would
        // accept it.
        node_aes: data.contains("createDecipheriv")
            && crate::ascii_ci::ci_find(data.as_bytes(), b"aes-256-cbc"),
        cryptojs_aes: data.contains("crypto-js")
            && data.contains(".AES")
            && data.contains(".decrypt")
            && data.contains(".enc")
            && data.contains(".Utf8"),
        reverse_base64: data.contains("atob")
            && data.contains("split")
            && data.contains("reverse")
            && data.contains("join"),
    }
}

impl Decoder for JavaScriptStaticDecoder {
    fn name(&self) -> &'static str {
        "javascript-static"
    }

    fn admission_sketch(&self, chunk: &Chunk) -> DecodeAdmissionSketch {
        if chunk.metadata.source_type.contains("/javascript-static") {
            return DecodeAdmissionSketch::NONE;
        }
        let kinds = static_expression_kinds(&chunk.data);
        let count = [
            kinds.xor,
            kinds.node_aes,
            kinds.cryptojs_aes,
            kinds.reverse_base64,
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if count == 0 {
            DecodeAdmissionSketch::NONE
        } else {
            DecodeAdmissionSketch::possible(
                DecodeAdmissionSketch::JAVASCRIPT_STATIC,
                count,
                chunk.data.len().saturating_mul(count),
            )
        }
    }

    fn decode_chunk_into(&self, chunk: &Chunk, sink: &mut dyn DecodeOutputSink) {
        if chunk.metadata.source_type.contains("/javascript-static") {
            return;
        }

        let kinds = static_expression_kinds(&chunk.data);
        if !kinds.any() {
            return;
        }
        if chunk.data.len() > MAX_STATIC_SOURCE_BYTES {
            record_static_limit("source byte ceiling");
            record_static_recovery_rejection(
                &chunk.metadata,
                chunk.metadata.base_offset,
                StaticRecoveryRejection::ResourceLimit,
            );
            return;
        }

        let base_offset = chunk.metadata.base_offset;
        // ONE budget for the whole source. The XOR, bound-AES, and inline-AES
        // grammars used to count independently, so a file mixing all three
        // could evaluate three times the advertised 64-operation ceiling.
        // Ordering is fixed (XOR, then bound AES, then inline AES, each in
        // regex-match order), so which operations the budget buys is
        // deterministic.
        let mut budget = StaticOperationBudget::new(MAX_STATIC_EXPRESSIONS);
        if kinds.xor {
            let mut recovered = BTreeSet::new();
            recover_xor_plaintexts(
                &chunk.data,
                &chunk.metadata,
                base_offset,
                &mut recovered,
                &mut budget,
            );
            if !append_spliced_recoveries(sink, chunk, recovered, self.name()) {
                return;
            }
        }
        if kinds.node_aes {
            let mut recovered = BTreeSet::new();
            aes::recover_plaintexts(
                &chunk.data,
                &chunk.metadata,
                base_offset,
                &mut recovered,
                &mut budget,
            );
            if !append_spliced_recoveries(sink, chunk, recovered, self.name()) {
                return;
            }
        }
        if kinds.cryptojs_aes {
            let mut recovered = BTreeSet::new();
            cryptojs::recover_plaintexts(&chunk.data, &chunk.metadata, base_offset, &mut recovered);
            if !append_spliced_recoveries(sink, chunk, recovered, self.name()) {
                return;
            }
        }
        if kinds.reverse_base64 {
            let mut recovered = BTreeSet::new();
            reverse_base64::recover_plaintexts(
                &chunk.data,
                &chunk.metadata,
                base_offset,
                &mut recovered,
            );
            append_spliced_recoveries(sink, chunk, recovered, self.name());
        }
    }
}

fn report_nonstandard_xor_candidates(source: &str, metadata: &ChunkMetadata, base_offset: usize) {
    let supported_starts: HashSet<usize> = XOR_MAP_RE
        .find_iter(source)
        .take(MAX_STATIC_EXPRESSIONS)
        .map(|matched| matched.start())
        .collect();
    for (candidate_index, candidate) in XOR_CANDIDATE_RE.find_iter(source).enumerate() {
        if candidate_index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("XOR candidate ceiling");
            if let Some(offset) = crate::engine::absolute_offset(base_offset, candidate.start()) {
                record_static_recovery_rejection(
                    metadata,
                    offset,
                    StaticRecoveryRejection::ResourceLimit,
                );
            }
            break;
        }
        if supported_starts.contains(&candidate.start()) {
            continue;
        }
        let Some(offset) = crate::engine::absolute_offset(base_offset, candidate.start()) else {
            record_static_limit("XOR candidate offset overflow");
            continue;
        };
        let reason = if XOR_DYNAMIC_PROPERTY_RE.is_match(candidate.as_str()) {
            StaticRecoveryRejection::DynamicPropertyAccess
        } else {
            StaticRecoveryRejection::MalformedExpression
        };
        record_static_recovery_rejection(metadata, offset, reason);
    }
}

fn recover_xor_plaintexts(
    source: &str,
    metadata: &ChunkMetadata,
    base_offset: usize,
    emitted: &mut BTreeSet<RecoveredPlaintext>,
    budget: &mut StaticOperationBudget,
) {
    report_nonstandard_xor_candidates(source, metadata, base_offset);
    let bindings = collect_byte_array_bindings(source);
    if bindings.len() < 2 {
        return;
    }
    for captures in XOR_MAP_RE.captures_iter(source) {
        if !budget.take() {
            break;
        }
        let Some((
            data_name,
            byte_parameter,
            index_parameter,
            byte_use,
            key_name,
            index_use,
            key_length_name,
            key_length_literal,
        )) = capture_xor_names(&captures)
        else {
            continue;
        };
        let Some(expression_offset) = crate::engine::absolute_offset(
            base_offset,
            captures.get(0).map_or(0, |matched| matched.start()),
        ) else {
            record_static_limit("XOR expression offset overflow");
            continue;
        };
        if byte_parameter != byte_use || index_parameter != index_use {
            continue;
        }
        let modulo_matches_key = match (key_length_name, key_length_literal) {
            (Some(length_name), None) => length_name == key_name,
            (None, Some(length_literal)) => length_literal
                .parse::<usize>()
                // LAW10: fail-closed; a malformed literal length rejects the recovery candidate, and no alternate key is tried.
                .ok()
                .is_some_and(|length| length > 0),
            _ => false,
        };
        if !modulo_matches_key || data_name == key_name {
            continue;
        }
        let key_occurrences = if key_length_name.is_some() { 3 } else { 2 };
        if identifier_occurrence_count(source, data_name) != 2
            || identifier_occurrence_count(source, key_name) != key_occurrences
        {
            continue;
        }
        let (Some(data), Some(key)) = (bindings.get(data_name), bindings.get(key_name)) else {
            continue;
        };
        let data = match data {
            Ok(data) => data,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, *reason);
                continue;
            }
        };
        let key = match key {
            Ok(key) => key,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, *reason);
                continue;
            }
        };
        if key_length_literal.is_some()
            // LAW10: fail-closed; a malformed or mismatched literal length rejects the recovery candidate, and no alternate decoder is selected.
            && key_length_literal.and_then(|literal| literal.parse::<usize>().ok())
                != Some(key.len())
        {
            continue;
        }
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
                record_static_recovery_rejection(
                    metadata,
                    expression_offset,
                    StaticRecoveryRejection::XorPlaintextUtf8,
                );
                continue;
            }
        };
        let Some(expression) = captures.get(0) else {
            continue;
        };
        emitted.insert(RecoveredPlaintext {
            plaintext,
            source_start: expression.start(),
            source_end: expression.end(),
        });
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
        let parsed = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map_or_else(|| value.parse::<u8>(), |hex| u8::from_str_radix(hex, 16));
        match parsed {
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

/// Strip one string literal's delimiters, or refuse.
///
/// Single quotes, double quotes, and backticks all denote the same value in
/// JavaScript as long as the backtick form carries no substitution and no
/// escape. `${` would make the value depend on evaluation and `\` would make
/// the written bytes differ from the runtime bytes, so both fail closed rather
/// than recovering a plaintext this grammar cannot prove.
fn unquote_static_string(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let quote = *bytes.first()?;
    if bytes.len() < 2
        || !matches!(quote, b'\'' | b'"' | b'`')
        || bytes.last().copied() != Some(quote)
    {
        return None;
    }
    let inner = value.get(1..value.len() - 1)?;
    if quote == b'`' && (inner.contains("${") || inner.contains('\\')) {
        return None;
    }
    Some(inner)
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
    Option<&'a str>,
    Option<&'a str>,
)> {
    Some((
        captures.get(1)?.as_str(),
        captures.get(2)?.as_str(),
        captures.get(3)?.as_str(),
        captures.get(4)?.as_str(),
        captures.get(5)?.as_str(),
        captures.get(6)?.as_str(),
        captures.get(7).map(|capture| capture.as_str()),
        captures.get(8).map(|capture| capture.as_str()),
    ))
}

#[cfg(test)]
#[path = "../../tests/unit/decode_javascript_static.rs"]
mod tests;
