//! Exact static recovery for the upstream reverse/Base64 wrapper dialect.

use super::{
    compile_static_regex, cryptojs::collect_inert_regex_bindings, record_static_limit,
    unquote_static_string, RecoveredPlaintext, MAX_BYTE_ARRAY_LEN, MAX_STATIC_EXPRESSIONS,
};
use keyhog_core::ChunkMetadata;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use crate::telemetry::{record_static_recovery_rejection, StaticRecoveryRejection};

const MAX_REVERSE_BASE64_LITERAL_BYTES: usize = MAX_BYTE_ARRAY_LEN.div_ceil(3) * 4;

static HELPER_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?s)\bfunction\s+(?P<function>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*(?P<param>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*\{\s*return\s+(?P<param_use>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*split\s*\(\s*(?:''|"")\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*(?:''|"")\s*\)\s*;?\s*\}"#,
        "reverse/Base64 helper",
    )
});

static INVOCATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?P<function>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*atob\s*\(\s*(?P<literal>["'][A-Za-z0-9+/=]+["'])\s*\.\s*split\s*\(\s*(?:''|"")\s*\)\s*\.\s*reverse\s*\(\s*\)\s*\.\s*join\s*\(\s*(?:''|"")\s*\)\s*\)\s*\)"#,
        "reverse/Base64 invocation",
    )
});

static ATOB_CANDIDATE_RE: LazyLock<Regex> =
    LazyLock::new(|| compile_static_regex(r"\batob\s*\(", "reverse/Base64 candidate"));

#[derive(Clone, Copy)]
struct Helper<'a> {
    name: &'a str,
    parameter: &'a str,
    start: usize,
}

#[derive(Clone, Copy)]
struct Invocation<'a> {
    function: &'a str,
    literal: &'a str,
    literal_start: usize,
    literal_end: usize,
    start: usize,
}

struct CodeFacts<'a> {
    identifier_counts: HashMap<&'a str, usize>,
    scopes: HashMap<usize, u32>,
}

impl CodeFacts<'_> {
    fn count(&self, identifier: &str) -> usize {
        match self.identifier_counts.get(identifier) {
            Some(count) => *count,
            None => 0,
        }
    }

    fn is_top_level(&self, start: usize) -> bool {
        self.scopes.get(&start) == Some(&0)
    }
}

pub(super) fn recover_plaintexts(
    source: &str,
    metadata: &ChunkMetadata,
    base_offset: usize,
    emitted: &mut BTreeSet<RecoveredPlaintext>,
) {
    let raw_helpers = collect_helpers(source);
    let raw_invocations = collect_invocations(source);
    if raw_invocations.is_empty() {
        record_loose_candidates(source, metadata, base_offset);
        return;
    }
    if raw_helpers.is_empty() {
        record_invocations(
            &raw_invocations,
            metadata,
            base_offset,
            StaticRecoveryRejection::MalformedExpression,
        );
        return;
    }

    let mut semantic_names: HashSet<&str> = raw_helpers
        .iter()
        .flat_map(|helper| [helper.name, helper.parameter])
        .chain(raw_invocations.iter().map(|invocation| invocation.function))
        .collect();
    semantic_names.extend(["atob", "split", "reverse", "join"]);
    let candidate_starts: HashSet<usize> = raw_helpers
        .iter()
        .map(|helper| helper.start)
        .chain(raw_invocations.iter().map(|invocation| invocation.start))
        .collect();
    let regex_bindings = collect_inert_regex_bindings(source);
    let facts = match analyze_code(source, &semantic_names, &candidate_starts, &regex_bindings) {
        Ok(facts) => facts,
        Err(reason) => {
            record_invocations(&raw_invocations, metadata, base_offset, reason);
            return;
        }
    };

    let helpers: Vec<_> = raw_helpers
        .into_iter()
        .filter(|helper| facts.is_top_level(helper.start))
        .collect();
    if helpers.len() != 1 {
        record_invocations(
            &raw_invocations,
            metadata,
            base_offset,
            StaticRecoveryRejection::MalformedExpression,
        );
        return;
    }
    let helper = helpers[0];
    let invocations: Vec<_> = raw_invocations
        .into_iter()
        .filter(|invocation| {
            invocation.function == helper.name && facts.is_top_level(invocation.start)
        })
        .take(MAX_STATIC_EXPRESSIONS + 1)
        .collect();
    if invocations.is_empty() {
        return;
    }
    if invocations.len() > MAX_STATIC_EXPRESSIONS {
        record_static_limit("reverse/Base64 expression ceiling");
        record_invocations(
            &invocations[MAX_STATIC_EXPRESSIONS..],
            metadata,
            base_offset,
            StaticRecoveryRejection::ResourceLimit,
        );
        return;
    }
    if facts.count(helper.parameter) != 2
        || facts.count(helper.name) != invocations.len().saturating_add(1)
        || facts.count("atob") != invocations.len()
        || ["split", "reverse", "join"]
            .into_iter()
            .any(|method| facts.count(method) != invocations.len().saturating_add(1))
    {
        record_invocations(
            &invocations,
            metadata,
            base_offset,
            StaticRecoveryRejection::MalformedExpression,
        );
        return;
    }

    for invocation in invocations {
        let Some(expression_offset) = crate::engine::absolute_offset(base_offset, invocation.start)
        else {
            record_static_limit("reverse/Base64 expression offset overflow");
            continue;
        };
        let plaintext = match recover_literal(invocation.literal) {
            Ok(plaintext) => plaintext,
            Err(reason) => {
                record_static_recovery_rejection(metadata, expression_offset, reason);
                continue;
            }
        };
        emitted.insert(RecoveredPlaintext {
            plaintext,
            source_start: invocation.literal_start,
            source_end: invocation.literal_end,
        });
    }
}

fn record_loose_candidates(source: &str, metadata: &ChunkMetadata, base_offset: usize) {
    for (index, candidate) in ATOB_CANDIDATE_RE.find_iter(source).enumerate() {
        let reason = if index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("reverse/Base64 candidate ceiling");
            StaticRecoveryRejection::ResourceLimit
        } else {
            StaticRecoveryRejection::MalformedExpression
        };
        if let Some(offset) = crate::engine::absolute_offset(base_offset, candidate.start()) {
            record_static_recovery_rejection(metadata, offset, reason);
        }
        if index >= MAX_STATIC_EXPRESSIONS {
            break;
        }
    }
}

fn record_invocations(
    invocations: &[Invocation<'_>],
    metadata: &ChunkMetadata,
    base_offset: usize,
    reason: StaticRecoveryRejection,
) {
    for invocation in invocations.iter().take(MAX_STATIC_EXPRESSIONS) {
        if let Some(offset) = crate::engine::absolute_offset(base_offset, invocation.start) {
            record_static_recovery_rejection(metadata, offset, reason);
        }
    }
}

fn collect_helpers(source: &str) -> Vec<Helper<'_>> {
    HELPER_RE
        .captures_iter(source)
        .filter_map(|captures| {
            let matched = captures.get(0)?;
            let name = captures.name("function")?.as_str();
            let parameter = captures.name("param")?.as_str();
            (parameter == captures.name("param_use")?.as_str()).then_some(Helper {
                name,
                parameter,
                start: matched.start(),
            })
        })
        .collect()
}

fn collect_invocations(source: &str) -> Vec<Invocation<'_>> {
    INVOCATION_RE
        .captures_iter(source)
        .filter_map(|captures| {
            let matched = captures.get(0)?;
            let literal_match = captures.name("literal")?;
            let literal = unquote_static_string(literal_match.as_str())?;
            Some(Invocation {
                function: captures.name("function")?.as_str(),
                literal,
                literal_start: literal_match.start() + 1,
                literal_end: literal_match.end() - 1,
                start: matched.start(),
            })
        })
        .collect()
}

fn recover_literal(encoded: &str) -> Result<String, StaticRecoveryRejection> {
    if encoded.len() > MAX_REVERSE_BASE64_LITERAL_BYTES {
        record_static_limit("reverse/Base64 literal byte ceiling");
        return Err(StaticRecoveryRejection::ResourceLimit);
    }
    let reversed: String = encoded.bytes().rev().map(char::from).collect();
    let decoded = super::super::base64_decode(&reversed)
        .map_err(|()| StaticRecoveryRejection::MalformedExpression)?;
    if decoded.len() > MAX_BYTE_ARRAY_LEN {
        return Err(StaticRecoveryRejection::ResourceLimit);
    }
    if !decoded.is_ascii() {
        return Err(StaticRecoveryRejection::MalformedExpression);
    }
    Ok(decoded.into_iter().rev().map(char::from).collect())
}

fn analyze_code<'a>(
    source: &'a str,
    semantic_names: &HashSet<&'a str>,
    candidate_starts: &HashSet<usize>,
    regex_bindings: &[(usize, usize)],
) -> Result<CodeFacts<'a>, StaticRecoveryRejection> {
    let malformed = StaticRecoveryRejection::MalformedExpression;
    let bytes = source.as_bytes();
    let mut identifier_counts: HashMap<&str, usize> = semantic_names
        .iter()
        .copied()
        .map(|name| (name, 0))
        .collect();
    let mut scopes = HashMap::new();
    let mut scope_stack = vec![0u32];
    let mut next_scope = 1u32;
    let mut index = 0usize;
    let mut regex_index = 0usize;

    while index < bytes.len() {
        while regex_bindings
            .get(regex_index)
            .is_some_and(|(_, end)| *end <= index)
        {
            regex_index += 1;
        }
        if let Some((start, end)) = regex_bindings.get(regex_index) {
            if index == *start {
                index = *end;
                regex_index += 1;
                continue;
            }
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            let mut closed = false;
            while index + 1 < bytes.len() {
                if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                    index += 2;
                    closed = true;
                    break;
                }
                index += 1;
            }
            if !closed {
                return Err(malformed);
            }
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"') {
            let literal_start = index;
            let quote = bytes[index];
            index += 1;
            let mut closed = false;
            let content_start = index;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = index.checked_add(2).ok_or(malformed)?;
                    continue;
                }
                if bytes[index] == quote {
                    let content = source.get(content_start..index).ok_or(malformed)?;
                    index += 1;
                    closed = true;
                    if semantic_names.contains(content)
                        && is_computed_property(source, literal_start, index)
                    {
                        return Err(StaticRecoveryRejection::DynamicPropertyAccess);
                    }
                    break;
                }
                if matches!(bytes[index], b'\n' | b'\r') {
                    return Err(malformed);
                }
                index += 1;
            }
            if !closed {
                return Err(malformed);
            }
            continue;
        }
        if matches!(bytes[index], b'`' | b'\\') {
            return Err(malformed);
        }
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let identifier = source.get(start..index).ok_or(malformed)?;
            if matches!(identifier, "eval" | "Function") {
                return Err(StaticRecoveryRejection::UnsupportedCall);
            }
            if let Some(count) = identifier_counts.get_mut(identifier) {
                *count = count.saturating_add(1);
            }
            if candidate_starts.contains(&start) {
                scopes.insert(
                    start,
                    *scope_stack
                        .last()
                        .ok_or(StaticRecoveryRejection::ResourceLimit)?,
                );
            }
            continue;
        }
        match bytes[index] {
            b'{' => {
                scope_stack.push(next_scope);
                next_scope = next_scope
                    .checked_add(1)
                    .ok_or(StaticRecoveryRejection::ResourceLimit)?;
            }
            b'}' => {
                if scope_stack.len() == 1 {
                    return Err(malformed);
                }
                scope_stack.pop();
            }
            _ => {}
        }
        index += 1;
    }

    if scope_stack.len() != 1 {
        return Err(malformed);
    }
    Ok(CodeFacts {
        identifier_counts,
        scopes,
    })
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$')
}

fn is_identifier_byte(byte: u8) -> bool {
    is_identifier_start(byte) || byte.is_ascii_digit()
}

fn is_computed_property(source: &str, literal_start: usize, literal_end: usize) -> bool {
    let before = source.as_bytes()[..literal_start]
        .iter()
        .rfind(|byte| !byte.is_ascii_whitespace());
    let after = source.as_bytes()[literal_end..]
        .iter()
        .find(|byte| !byte.is_ascii_whitespace());
    before == Some(&b'[') && after == Some(&b']')
}
