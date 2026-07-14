//! Bounded CryptoJS passphrase AES recovery for literal JavaScript programs.

use super::{
    aes::decrypt_aes_256_cbc, all_distinct, compile_static_regex, record_static_limit,
    unquote_static_string, RecoveredPlaintext, MAX_ARRAY_BINDINGS, MAX_BYTE_ARRAY_LEN,
    MAX_STATIC_EXPRESSIONS,
};
use keyhog_core::ChunkMetadata;
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use crate::telemetry::{record_static_recovery_rejection, StaticRecoveryRejection};

static REQUIRE_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?m)\bconst\s+(?P<alias>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*(?:'crypto-js'|"crypto-js")\s*\)\s*;"#,
        "CryptoJS require binding",
    )
});

static DECRYPT_FUNCTION_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r"(?s)\bfunction\s+(?P<function>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*(?P<cipher_param>[A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*(?P<key_param>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*\{\s*(?:const|let)\s+(?P<bytes>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?P<decrypt_alias>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*AES\s*\.\s*decrypt\s*\(\s*(?P<cipher_use>[A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*(?P<key_use>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*;\s*return\s+(?P<bytes_use>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*toString\s*\(\s*(?P<utf8_alias>[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*enc\s*\.\s*Utf8\s*\)\s*;?\s*\}",
        "CryptoJS passphrase decrypt function",
    )
});

static STRING_BINDING_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r#"(?m)\b(?:const|let)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?P<value>["'][A-Za-z0-9+/=_-]+["'])\s*;"#,
        "static ASCII string binding",
    )
});

static DECRYPT_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r"(?m)\b(?:const|let)\s+(?P<result>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?P<invocation>(?P<function>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(\s*(?P<cipher>[A-Za-z_$][A-Za-z0-9_$]*)\s*,\s*(?P<key>[A-Za-z_$][A-Za-z0-9_$]*)\s*\))\s*;",
        "CryptoJS passphrase decrypt call",
    )
});

static CONSOLE_LOG_RE: LazyLock<Regex> = LazyLock::new(|| {
    compile_static_regex(
        r"(?m)\bconsole\s*\.\s*log\s*\(\s*(?P<result>[A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*;",
        "CryptoJS result log",
    )
});

#[derive(Clone, Copy)]
struct RequireBinding<'a> {
    alias: &'a str,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct StaticStringBinding<'a> {
    name: &'a str,
    value: &'a str,
    start: usize,
    end: usize,
}

#[derive(Clone, Copy)]
struct DecryptFunction<'a> {
    start: usize,
    end: usize,
    alias: &'a str,
    name: &'a str,
    cipher_param: &'a str,
    key_param: &'a str,
    bytes_name: &'a str,
}

#[derive(Clone, Copy)]
struct DecryptCall<'a> {
    start: usize,
    end: usize,
    invocation_start: usize,
    invocation_end: usize,
    result: &'a str,
    function: &'a str,
    cipher: &'a str,
    key: &'a str,
}

#[derive(Clone, Copy)]
struct ResultLog<'a> {
    start: usize,
    end: usize,
    result: &'a str,
}

struct LexicalFacts<'a> {
    identifier_counts: HashMap<&'a str, usize>,
    scopes: HashMap<usize, u32>,
}

impl LexicalFacts<'_> {
    fn count(&self, identifier: &str) -> usize {
        self.identifier_counts.get(identifier).copied().unwrap_or(0)
    }

    fn scope(&self, start: usize) -> Option<u32> {
        self.scopes.get(&start).copied()
    }
}

pub(super) fn recover_plaintexts(
    source: &str,
    metadata: &ChunkMetadata,
    base_offset: usize,
    emitted: &mut BTreeSet<RecoveredPlaintext>,
) {
    let raw_requires = collect_require_bindings(source);
    let raw_strings = collect_string_bindings(source);
    let functions = collect_functions(source);
    let calls = collect_calls(source);
    let logs = collect_result_logs(source);
    let regex_bindings = collect_inert_regex_bindings(source);
    if raw_requires.is_empty() || raw_strings.len() < 2 || functions.is_empty() || calls.is_empty()
    {
        return;
    }

    let mut semantic_names = HashSet::new();
    let mut candidate_starts = HashSet::new();
    for binding in &raw_requires {
        semantic_names.insert(binding.alias);
        candidate_starts.insert(binding.start);
    }
    for binding in &raw_strings {
        semantic_names.insert(binding.name);
        candidate_starts.insert(binding.start);
    }
    for function in &functions {
        semantic_names.extend([
            function.alias,
            function.name,
            function.cipher_param,
            function.key_param,
            function.bytes_name,
        ]);
        candidate_starts.insert(function.start);
    }
    for call in &calls {
        semantic_names.extend([call.result, call.function, call.cipher, call.key]);
        candidate_starts.insert(call.start);
    }
    for log in &logs {
        semantic_names.insert(log.result);
        candidate_starts.insert(log.start);
    }
    let mut grammar_spans = Vec::with_capacity(
        raw_requires.len()
            + raw_strings.len()
            + functions.len()
            + calls.len()
            + logs.len()
            + regex_bindings.len(),
    );
    grammar_spans.extend(
        raw_requires
            .iter()
            .map(|binding| (binding.start, binding.end)),
    );
    grammar_spans.extend(
        raw_strings
            .iter()
            .map(|binding| (binding.start, binding.end)),
    );
    grammar_spans.extend(
        functions
            .iter()
            .map(|function| (function.start, function.end)),
    );
    grammar_spans.extend(calls.iter().map(|call| (call.start, call.end)));
    grammar_spans.extend(logs.iter().map(|log| (log.start, log.end)));
    grammar_spans.extend(regex_bindings.iter().copied());
    if !source_is_covered_by_static_grammar(source, &grammar_spans) {
        return;
    }

    let Some(facts) = analyze_source(source, &semantic_names, &candidate_starts, &regex_bindings)
    else {
        return;
    };

    let mut require_bindings: HashMap<&str, Option<&RequireBinding<'_>>> = HashMap::new();
    for binding in &raw_requires {
        if facts.scope(binding.start).is_none() {
            continue;
        }
        require_bindings
            .entry(binding.alias)
            .and_modify(|existing| *existing = None)
            .or_insert(Some(binding));
    }
    let mut string_bindings: HashMap<&str, Option<&StaticStringBinding<'_>>> = HashMap::new();
    for binding in &raw_strings {
        if facts.scope(binding.start).is_none() {
            continue;
        }
        string_bindings
            .entry(binding.name)
            .and_modify(|existing| *existing = None)
            .or_insert(Some(binding));
    }
    let mut calls_by_function: HashMap<&str, Option<&DecryptCall<'_>>> = HashMap::new();
    for call in &calls {
        if facts.scope(call.start).is_none() {
            continue;
        }
        calls_by_function
            .entry(call.function)
            .and_modify(|existing| *existing = None)
            .or_insert(Some(call));
    }

    let mut recoveries = Vec::new();
    let mut supported_calls = HashSet::new();
    let mut supported_logs = HashSet::new();
    for function in &functions {
        let Some(function_scope) = facts.scope(function.start) else {
            continue;
        };
        let Some(Some(require_binding)) = require_bindings.get(function.alias) else {
            continue;
        };
        let Some(Some(call)) = calls_by_function.get(function.name) else {
            continue;
        };
        let (Some(Some(ciphertext)), Some(Some(passphrase))) = (
            string_bindings.get(call.cipher),
            string_bindings.get(call.key),
        ) else {
            continue;
        };
        let Some(call_scope) = facts.scope(call.start) else {
            continue;
        };
        if facts.scope(require_binding.start) != Some(function_scope)
            || facts.scope(ciphertext.start) != Some(function_scope)
            || facts.scope(passphrase.start) != Some(function_scope)
            || call_scope != function_scope
        {
            continue;
        }
        if require_binding.start >= function.start
            || function.end >= call.start
            || ciphertext.start >= call.start
            || passphrase.start >= call.start
        {
            continue;
        }

        let identifiers = [
            function.alias,
            function.name,
            function.cipher_param,
            function.key_param,
            function.bytes_name,
            call.result,
            call.cipher,
            call.key,
        ];
        if !all_distinct(&identifiers) {
            continue;
        }

        let roles = [
            (function.alias, 3usize),
            (function.name, 2),
            (function.cipher_param, 2),
            (function.key_param, 2),
            (function.bytes_name, 2),
            (call.cipher, 2),
            (call.key, 2),
        ];
        if !identifiers_have_exact_role_counts(&facts, &roles)
            || !result_usage_is_supported(&facts, &logs, call, function_scope)
        {
            continue;
        }
        let Some(expression_offset) =
            crate::engine::absolute_offset(base_offset, call.invocation_start)
        else {
            record_static_limit("CryptoJS expression offset overflow");
            continue;
        };
        supported_calls.insert(call.start);
        supported_logs.extend(logs.iter().filter_map(|log| {
            (log.result == call.result
                && log.start > call.end
                && facts.scope(log.start) == Some(function_scope))
            .then_some(log.start)
        }));
        if let Some(plaintext) = decrypt_passphrase(
            &ciphertext.value,
            passphrase.value.as_bytes(),
            metadata,
            expression_offset,
        ) {
            recoveries.push(RecoveredPlaintext {
                plaintext,
                source_start: call.invocation_start,
                source_end: call.invocation_end,
            });
        }
    }

    // Reject the whole source when any executable call or log is outside the proven flow.
    let executable_call_count = calls
        .iter()
        .filter(|call| facts.scope(call.start).is_some())
        .count();
    let executable_log_count = logs
        .iter()
        .filter(|log| facts.scope(log.start).is_some())
        .count();
    if supported_calls.len() != executable_call_count
        || supported_logs.len() != executable_log_count
    {
        return;
    }
    emitted.extend(recoveries);
}

fn collect_functions(source: &str) -> Vec<DecryptFunction<'_>> {
    let mut functions = Vec::new();
    for (function_index, captures) in DECRYPT_FUNCTION_RE.captures_iter(source).enumerate() {
        if function_index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("CryptoJS function ceiling");
            break;
        }
        let Some(matched) = captures.get(0) else {
            continue;
        };
        let (Some(name), Some(cipher_param), Some(key_param), Some(bytes_name), Some(alias)) = (
            capture(&captures, "function"),
            capture(&captures, "cipher_param"),
            capture(&captures, "key_param"),
            capture(&captures, "bytes"),
            capture(&captures, "decrypt_alias"),
        ) else {
            continue;
        };
        if capture(&captures, "cipher_use") != Some(cipher_param)
            || capture(&captures, "key_use") != Some(key_param)
            || capture(&captures, "bytes_use") != Some(bytes_name)
            || capture(&captures, "utf8_alias") != Some(alias)
        {
            continue;
        }
        functions.push(DecryptFunction {
            start: matched.start(),
            end: matched.end(),
            alias,
            name,
            cipher_param,
            key_param,
            bytes_name,
        });
    }
    functions
}

fn collect_calls(source: &str) -> Vec<DecryptCall<'_>> {
    let mut calls = Vec::new();
    for (call_index, captures) in DECRYPT_CALL_RE.captures_iter(source).enumerate() {
        if call_index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("CryptoJS call ceiling");
            break;
        }
        let Some(matched) = captures.get(0) else {
            continue;
        };
        let (Some(result), Some(function), Some(cipher), Some(key), Some(invocation)) = (
            capture(&captures, "result"),
            capture(&captures, "function"),
            capture(&captures, "cipher"),
            capture(&captures, "key"),
            captures.name("invocation"),
        ) else {
            continue;
        };
        calls.push(DecryptCall {
            start: matched.start(),
            end: matched.end(),
            invocation_start: invocation.start(),
            invocation_end: invocation.end(),
            result,
            function,
            cipher,
            key,
        });
    }
    calls
}

fn collect_require_bindings(source: &str) -> Vec<RequireBinding<'_>> {
    let mut bindings = Vec::new();
    for (binding_index, captures) in REQUIRE_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS {
            record_static_limit("CryptoJS require binding ceiling");
            break;
        }
        let (Some(alias), Some(binding)) = (capture(&captures, "alias"), captures.get(0)) else {
            continue;
        };
        bindings.push(RequireBinding {
            alias,
            start: binding.start(),
            end: binding.end(),
        });
    }
    bindings
}

fn collect_string_bindings(source: &str) -> Vec<StaticStringBinding<'_>> {
    let mut bindings = Vec::new();
    for (binding_index, captures) in STRING_BINDING_RE.captures_iter(source).enumerate() {
        if binding_index >= MAX_ARRAY_BINDINGS {
            record_static_limit("static ASCII string binding ceiling");
            break;
        }
        let (Some(name), Some(value), Some(binding)) = (
            capture(&captures, "name"),
            capture(&captures, "value"),
            captures.get(0),
        ) else {
            continue;
        };
        let Some(value) = unquote_static_string(value) else {
            continue;
        };
        bindings.push(StaticStringBinding {
            name,
            value,
            start: binding.start(),
            end: binding.end(),
        });
    }
    bindings
}

fn collect_result_logs(source: &str) -> Vec<ResultLog<'_>> {
    let mut logs = Vec::new();
    for (log_index, captures) in CONSOLE_LOG_RE.captures_iter(source).enumerate() {
        if log_index >= MAX_STATIC_EXPRESSIONS {
            record_static_limit("CryptoJS result log ceiling");
            break;
        }
        let (Some(matched), Some(result)) = (captures.get(0), capture(&captures, "result")) else {
            continue;
        };
        logs.push(ResultLog {
            start: matched.start(),
            end: matched.end(),
            result,
        });
    }
    logs
}

fn capture<'a>(captures: &regex::Captures<'a>, name: &str) -> Option<&'a str> {
    captures.name(name).map(|matched| matched.as_str())
}

fn identifiers_have_exact_role_counts(facts: &LexicalFacts<'_>, roles: &[(&str, usize)]) -> bool {
    let mut expected = HashMap::<&str, usize>::new();
    for (identifier, count) in roles {
        *expected.entry(identifier).or_default() += count;
    }
    expected
        .into_iter()
        .all(|(identifier, count)| facts.count(identifier) == count)
}

fn result_usage_is_supported(
    facts: &LexicalFacts<'_>,
    logs: &[ResultLog<'_>],
    call: &DecryptCall<'_>,
    scope: u32,
) -> bool {
    match facts.count(call.result) {
        1 => true,
        2 => {
            logs.iter()
                .filter(|log| {
                    log.result == call.result
                        && log.start > call.end
                        && facts.scope(log.start) == Some(scope)
                })
                .count()
                == 1
        }
        _ => false,
    }
}

/// Collect inert regex declarations so their contents cannot change lexical facts.
pub(super) fn collect_inert_regex_bindings(source: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let Some(keyword_end) = parse_binding_keyword(source, index) else {
            index += 1;
            continue;
        };
        let start = index;
        let mut cursor = skip_ascii_whitespace(bytes, keyword_end);
        let Some(identifier_end) = parse_identifier_end(bytes, cursor) else {
            index = keyword_end;
            continue;
        };
        cursor = skip_ascii_whitespace(bytes, identifier_end);
        if bytes.get(cursor) != Some(&b'=') {
            index = keyword_end;
            continue;
        }
        cursor = skip_ascii_whitespace(bytes, cursor + 1);
        if bytes.get(cursor) != Some(&b'/')
            || matches!(bytes.get(cursor + 1), Some(b'/') | Some(b'*'))
        {
            index = keyword_end;
            continue;
        }
        let Some(regex_end) = parse_regex_literal_end(bytes, cursor) else {
            index = keyword_end;
            continue;
        };
        cursor = regex_end;
        let flags_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_alphabetic) {
            cursor += 1;
        }
        if !regex_flags_are_supported(&bytes[flags_start..cursor]) {
            index = keyword_end;
            continue;
        }
        cursor = skip_ascii_whitespace(bytes, cursor);
        if bytes.get(cursor) != Some(&b';') {
            index = keyword_end;
            continue;
        }
        spans.push((start, cursor + 1));
        index = cursor + 1;
    }
    spans
}

fn parse_binding_keyword(source: &str, start: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if start > 0 && is_identifier_byte(*bytes.get(start - 1)?) {
        return None;
    }
    for keyword in ["const", "let"] {
        let end = start.checked_add(keyword.len())?;
        if source.get(start..end) == Some(keyword)
            && bytes
                .get(end)
                .is_some_and(|byte| byte.is_ascii_whitespace())
        {
            return Some(end);
        }
    }
    None
}

fn parse_identifier_end(bytes: &[u8], start: usize) -> Option<usize> {
    if !bytes.get(start).copied().is_some_and(is_identifier_start) {
        return None;
    }
    let mut end = start + 1;
    while bytes.get(end).copied().is_some_and(is_identifier_byte) {
        end += 1;
    }
    Some(end)
}

fn parse_regex_literal_end(bytes: &[u8], slash: usize) -> Option<usize> {
    let mut index = slash.checked_add(1)?;
    let mut in_class = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' | b'\r' => return None,
            b'\\' => {
                let escaped = *bytes.get(index + 1)?;
                if !matches!(
                    escaped,
                    b'/' | b'\\'
                        | b'.'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'('
                        | b')'
                        | b'*'
                        | b'+'
                        | b'?'
                        | b'^'
                        | b'$'
                        | b'|'
                        | b'-'
                        | b'd'
                        | b'D'
                        | b's'
                        | b'S'
                        | b'w'
                        | b'W'
                        | b'b'
                        | b'B'
                        | b'f'
                        | b'n'
                        | b'r'
                        | b't'
                        | b'v'
                        | b'0'
                ) {
                    return None;
                }
                index = index.checked_add(2)?;
            }
            b'[' if !in_class => {
                in_class = true;
                index += 1;
            }
            b']' if in_class => {
                in_class = false;
                index += 1;
            }
            b'/' if !in_class => return Some(index + 1),
            b'-' if in_class => return None,
            b'(' | b')' | b'{' | b'}' | b'*' | b'+' | b'?' | b'|' if !in_class => {
                return None;
            }
            byte if !byte.is_ascii() || byte.is_ascii_control() => return None,
            _ => index += 1,
        }
    }
    None
}

fn regex_flags_are_supported(flags: &[u8]) -> bool {
    let mut seen = 0u16;
    for &flag in flags {
        let bit = match flag {
            b'd' => 1 << 0,
            b'g' => 1 << 1,
            b'i' => 1 << 2,
            b'm' => 1 << 3,
            b's' => 1 << 4,
            b'u' => 1 << 5,
            b'v' => 1 << 6,
            b'y' => 1 << 7,
            _ => return false,
        };
        if seen & bit != 0 {
            return false;
        }
        seen |= bit;
    }
    seen & (1 << 5) == 0 || seen & (1 << 6) == 0
}

fn skip_ascii_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes.get(index).is_some_and(u8::is_ascii_whitespace) {
        index += 1;
    }
    index
}

fn javascript_line_terminator_len(bytes: &[u8], index: usize) -> Option<usize> {
    match bytes.get(index..) {
        Some([b'\n' | b'\r', ..]) => Some(1),
        Some([0xe2, 0x80, 0xa8 | 0xa9, ..]) => Some(3),
        _ => None,
    }
}

fn source_is_covered_by_static_grammar(source: &str, spans: &[(usize, usize)]) -> bool {
    let mut spans = spans.to_vec();
    spans.sort_unstable();
    let mut merged = Vec::<(usize, usize)>::with_capacity(spans.len());
    for (start, end) in spans {
        if start >= end || end > source.len() {
            return false;
        }
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let mut cursor = 0usize;
    for (start, end) in merged {
        if !contains_only_static_trivia(source.as_bytes(), cursor, start) {
            return false;
        }
        cursor = end;
    }
    contains_only_static_trivia(source.as_bytes(), cursor, source.len())
}

fn contains_only_static_trivia(bytes: &[u8], mut index: usize, end: usize) -> bool {
    while index < end {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        if let Some(width) = javascript_line_terminator_len(bytes, index) {
            index += width;
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'/') {
            index += 2;
            while index < end && javascript_line_terminator_len(bytes, index).is_none() {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b'/' && bytes.get(index + 1) == Some(&b'*') {
            index += 2;
            let mut closed = false;
            while index + 1 < end {
                if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                    index += 2;
                    closed = true;
                    break;
                }
                index += 1;
            }
            if !closed {
                return false;
            }
            continue;
        }
        return false;
    }
    true
}

fn analyze_source<'a>(
    source: &'a str,
    semantic_names: &HashSet<&'a str>,
    candidate_starts: &HashSet<usize>,
    regex_bindings: &[(usize, usize)],
) -> Option<LexicalFacts<'a>> {
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
            while index < bytes.len() && javascript_line_terminator_len(bytes, index).is_none() {
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
                return None;
            }
            continue;
        }
        if matches!(bytes[index], b'\'' | b'"') {
            let quote = bytes[index];
            index += 1;
            let mut closed = false;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = index.checked_add(2)?;
                    continue;
                }
                if bytes[index] == quote {
                    index += 1;
                    closed = true;
                    break;
                }
                if matches!(bytes[index], b'\n' | b'\r') {
                    return None;
                }
                index += 1;
            }
            if !closed {
                return None;
            }
            continue;
        }
        // Template interpolation is executable syntax outside the supported
        // literal grammar. Reject the source rather than partially lexing it.
        if bytes[index] == b'`' {
            return None;
        }
        // Escaped identifiers can alias a semantic binding while evading the
        // ASCII identifier counts that prove this narrow static data flow.
        if bytes[index] == b'\\' {
            return None;
        }
        if is_identifier_start(bytes[index]) {
            let start = index;
            index += 1;
            while index < bytes.len() && is_identifier_byte(bytes[index]) {
                index += 1;
            }
            let identifier = source.get(start..index)?;
            if matches!(identifier, "eval" | "Function") {
                return None;
            }
            if let Some(count) = identifier_counts.get_mut(identifier) {
                *count = count.saturating_add(1);
            }
            if candidate_starts.contains(&start) {
                scopes.insert(start, *scope_stack.last()?);
            }
            continue;
        }
        match bytes[index] {
            b'{' => {
                scope_stack.push(next_scope);
                next_scope = next_scope.checked_add(1)?;
            }
            b'}' => {
                if scope_stack.len() == 1 {
                    return None;
                }
                scope_stack.pop();
            }
            _ => {}
        }
        index += 1;
    }

    (scope_stack.len() == 1).then_some(LexicalFacts {
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

fn decrypt_passphrase(
    encoded: &str,
    passphrase: &[u8],
    metadata: &ChunkMetadata,
    expression_offset: usize,
) -> Option<String> {
    if encoded.len() > MAX_BYTE_ARRAY_LEN.saturating_mul(2) || passphrase.len() > MAX_BYTE_ARRAY_LEN
    {
        record_static_limit("CryptoJS literal byte ceiling");
        return None;
    }
    // CryptoJS OpenSSL parsing uses standard Base64, while the shared decoder also accepts Base64URL.
    if encoded.bytes().any(|byte| matches!(byte, b'-' | b'_')) {
        record_static_recovery_rejection(
            metadata,
            expression_offset,
            StaticRecoveryRejection::BufferBase64,
        );
        return None;
    }
    let envelope = match crate::decode::base64_decode(encoded) {
        Ok(envelope) => envelope,
        Err(()) => {
            record_static_recovery_rejection(
                metadata,
                expression_offset,
                StaticRecoveryRejection::BufferBase64,
            );
            return None;
        }
    };
    if envelope.len() < 16 {
        return None;
    }
    let (header, encrypted) = envelope.split_at(16);
    if !header.starts_with(b"Salted__")
        || encrypted.is_empty()
        || !encrypted.len().is_multiple_of(16)
    {
        return None;
    }
    let salt: &[u8; 8] = header.get(8..16)?.try_into().ok()?;
    let (key, iv) = evp_bytes_to_key_md5(passphrase, salt);
    decrypt_aes_256_cbc(&key, &iv, encrypted, metadata, expression_offset)
}

fn evp_bytes_to_key_md5(passphrase: &[u8], salt: &[u8; 8]) -> ([u8; 32], [u8; 16]) {
    let mut derived = [0u8; 48];
    let mut written = 0usize;
    let mut previous: Option<[u8; 16]> = None;
    while written < derived.len() {
        let mut context = md5::Context::new();
        if let Some(previous) = previous {
            context.consume(previous);
        }
        context.consume(passphrase);
        context.consume(salt);
        let digest = context.compute().0;
        let copied = (derived.len() - written).min(digest.len());
        derived[written..written + copied].copy_from_slice(&digest[..copied]);
        written += copied;
        previous = Some(digest);
    }
    let mut key = [0u8; 32];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&derived[..32]);
    iv.copy_from_slice(&derived[32..]);
    (key, iv)
}

#[cfg(test)]
mod tests {
    use super::evp_bytes_to_key_md5;

    #[test]
    fn evp_bytes_to_key_matches_openssl_vector() {
        let salt: [u8; 8] = hex::decode("0011223344556677")
            .expect("valid fixed salt")
            .try_into()
            .expect("eight-byte fixed salt");
        let (key, iv) = evp_bytes_to_key_md5(b"mySecretKey123", &salt);
        assert_eq!(
            key.as_slice(),
            hex::decode("e25410b8ef51f7047637c5e4dd5921ae15f98bf04076fa178e96fad9d45ec984")
                .expect("valid fixed key")
        );
        assert_eq!(
            iv.as_slice(),
            hex::decode("317406af052f963ee40fba3f9bed5d72").expect("valid fixed IV")
        );
    }
}
