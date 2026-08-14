//! Candidate-bounded source-role evidence.
//!
//! This module classifies only the bounded source containing an emitted
//! candidate. It never walks a repository or parses a file before retrieval.

use keyhog_core::SemanticSourceRole;

pub(crate) const MAX_SEMANTIC_WINDOW_BYTES: usize = 64 * 1024;
const MAX_KEY_PATH_SEGMENTS: usize = 12;
const MAX_NESTING_DEPTH: usize = 32;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SemanticParserConfidence {
    Abstained,
    Parsed,
}

impl SemanticParserConfidence {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Abstained => "abstained",
            Self::Parsed => "parsed",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SourceSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

impl SourceSpan {
    const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StructuredSourceEvidence {
    pub(crate) role: SemanticSourceRole,
    pub(crate) confidence: SemanticParserConfidence,
    pub(crate) candidate_span: SourceSpan,
    pub(crate) value_span: SourceSpan,
    key_path: [SourceSpan; MAX_KEY_PATH_SEGMENTS],
    key_path_len: u8,
}

impl StructuredSourceEvidence {
    fn new(
        role: SemanticSourceRole,
        candidate_span: SourceSpan,
        value_span: SourceSpan,
        key_path: &KeyPath,
    ) -> Self {
        Self {
            role,
            confidence: SemanticParserConfidence::Parsed,
            candidate_span,
            value_span,
            key_path: key_path.segments,
            key_path_len: key_path.len,
        }
    }

    pub(crate) fn key_path(&self) -> impl Iterator<Item = SourceSpan> + '_ {
        self.key_path[..usize::from(self.key_path_len)]
            .iter()
            .copied()
    }
}

#[derive(Clone, Copy)]
struct KeyPath {
    segments: [SourceSpan; MAX_KEY_PATH_SEGMENTS],
    len: u8,
}

impl KeyPath {
    const fn new() -> Self {
        Self {
            segments: [SourceSpan::new(0, 0); MAX_KEY_PATH_SEGMENTS],
            len: 0,
        }
    }

    fn push(&mut self, span: SourceSpan) -> bool {
        let index = usize::from(self.len);
        if index == self.segments.len() {
            return false;
        }
        self.segments[index] = span;
        self.len += 1;
        true
    }

    fn pop(&mut self) {
        self.len = self.len.saturating_sub(1);
    }

    fn append(&mut self, other: &Self) -> bool {
        for span in other.segments[..usize::from(other.len)].iter().copied() {
            if !self.push(span) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Copy)]
enum StructuredSyntax {
    Json,
    JsonLines,
    Toml,
    Yaml,
    Dotenv,
    Ini,
}

pub(crate) fn classify_exact_structured_candidate(
    text: &str,
    path: Option<&str>,
    candidate_start: usize,
    candidate: &str,
) -> Option<StructuredSourceEvidence> {
    let candidate_end = candidate_start.checked_add(candidate.len())?;
    if text.get(candidate_start..candidate_end) != Some(candidate) {
        return None;
    }
    classify_structured_candidate(text, path, candidate_start, candidate_end)
}

/// Classify one exact source candidate. Unsupported syntax, an invalid local
/// parse, an out-of-bounds span, and oversized parser input all abstain.
pub(crate) fn classify_structured_candidate(
    text: &str,
    path: Option<&str>,
    candidate_start: usize,
    candidate_end: usize,
) -> Option<StructuredSourceEvidence> {
    if candidate_start >= candidate_end
        || candidate_end > text.len()
        || !text.is_char_boundary(candidate_start)
        || !text.is_char_boundary(candidate_end)
    {
        return None;
    }
    let target = SourceSpan::new(candidate_start, candidate_end);
    match syntax_for_path(path?)? {
        StructuredSyntax::Json => classify_json(text, 0, target),
        StructuredSyntax::JsonLines => {
            let (start, end) = line_bounds(text, candidate_start);
            classify_json(&text[start..end], start, target)
        }
        StructuredSyntax::Toml => classify_toml(text, target),
        StructuredSyntax::Yaml => classify_yaml(text, target),
        StructuredSyntax::Dotenv => classify_dotenv(text, target),
        StructuredSyntax::Ini => classify_ini(text, target),
    }
}

fn syntax_for_path(path: &str) -> Option<StructuredSyntax> {
    let name = path
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(path)
        .split('?')
        .next()
        .unwrap_or(path);
    if name.eq_ignore_ascii_case(".env")
        || name
            .strip_prefix(".env.")
            .is_some_and(|suffix| !suffix.is_empty())
        || name
            .strip_prefix(".env-")
            .is_some_and(|suffix| !suffix.is_empty())
    {
        return Some(StructuredSyntax::Dotenv);
    }
    let extension = name.rsplit_once('.')?.1;
    if extension.eq_ignore_ascii_case("json") {
        Some(StructuredSyntax::Json)
    } else if extension.eq_ignore_ascii_case("jsonl") || extension.eq_ignore_ascii_case("ndjson") {
        Some(StructuredSyntax::JsonLines)
    } else if extension.eq_ignore_ascii_case("toml") {
        Some(StructuredSyntax::Toml)
    } else if extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml") {
        Some(StructuredSyntax::Yaml)
    } else if extension.eq_ignore_ascii_case("ini") || extension.eq_ignore_ascii_case("cfg") {
        Some(StructuredSyntax::Ini)
    } else {
        None
    }
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    base: usize,
    cursor: usize,
    target: SourceSpan,
    path: KeyPath,
    found: Option<StructuredSourceEvidence>,
}

fn classify_json(text: &str, base: usize, target: SourceSpan) -> Option<StructuredSourceEvidence> {
    if text.len() > MAX_SEMANTIC_WINDOW_BYTES
        || target.start < base
        || target.end > base + text.len()
    {
        return None;
    }
    let mut parser = JsonParser {
        bytes: text.as_bytes(),
        base,
        cursor: 0,
        target,
        path: KeyPath::new(),
        found: None,
    };
    parser.parse_value(0).ok()?;
    parser.skip_ws();
    (parser.cursor == parser.bytes.len()).then_some(())?;
    parser.found
}

impl JsonParser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<(), ()> {
        if depth > MAX_NESTING_DEPTH {
            return Err(());
        }
        self.skip_ws();
        match self.bytes.get(self.cursor).copied() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => {
                let value = self.parse_string()?;
                self.record_if_target(value);
                Ok(())
            }
            Some(b't') => self.parse_literal(b"true"),
            Some(b'f') => self.parse_literal(b"false"),
            Some(b'n') => self.parse_literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(()),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), ()> {
        self.cursor += 1;
        self.skip_ws();
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            self.skip_ws();
            if self.bytes.get(self.cursor) != Some(&b'"') {
                return Err(());
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if !self.consume(b':') || !self.path.push(key) {
                return Err(());
            }
            let result = self.parse_value(depth);
            self.path.pop();
            result?;
            self.skip_ws();
            if self.consume(b'}') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(());
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), ()> {
        self.cursor += 1;
        self.skip_ws();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.parse_value(depth)?;
            self.skip_ws();
            if self.consume(b']') {
                return Ok(());
            }
            if !self.consume(b',') {
                return Err(());
            }
        }
    }

    fn parse_string(&mut self) -> Result<SourceSpan, ()> {
        if !self.consume(b'"') {
            return Err(());
        }
        let start = self.cursor;
        while let Some(byte) = self.bytes.get(self.cursor).copied() {
            match byte {
                b'"' => {
                    let end = self.cursor;
                    self.cursor += 1;
                    return Ok(SourceSpan::new(self.base + start, self.base + end));
                }
                b'\\' => {
                    self.cursor += 1;
                    match self.bytes.get(self.cursor).copied() {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                            self.cursor += 1;
                        }
                        Some(b'u') => {
                            let end = self.cursor.saturating_add(5);
                            let digits = self.bytes.get(self.cursor + 1..end).ok_or(())?;
                            if !digits.iter().all(u8::is_ascii_hexdigit) {
                                return Err(());
                            }
                            self.cursor = end;
                        }
                        _ => return Err(()),
                    }
                }
                0x00..=0x1f => return Err(()),
                _ => self.cursor += 1,
            }
        }
        Err(())
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Result<(), ()> {
        let start = self.cursor;
        if self.bytes.get(start..start + literal.len()) != Some(literal) {
            return Err(());
        }
        self.cursor += literal.len();
        self.record_if_target(SourceSpan::new(self.base + start, self.base + self.cursor));
        Ok(())
    }

    fn parse_number(&mut self) -> Result<(), ()> {
        let start = self.cursor;
        self.consume(b'-');
        match self.bytes.get(self.cursor).copied() {
            Some(b'0') => self.cursor += 1,
            Some(b'1'..=b'9') => {
                self.cursor += 1;
                while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                    self.cursor += 1;
                }
            }
            _ => return Err(()),
        }
        if self.consume(b'.') {
            let fraction_start = self.cursor;
            while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                self.cursor += 1;
            }
            if self.cursor == fraction_start {
                return Err(());
            }
        }
        if self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| matches!(byte, b'e' | b'E'))
        {
            self.cursor += 1;
            if self
                .bytes
                .get(self.cursor)
                .is_some_and(|byte| matches!(byte, b'+' | b'-'))
            {
                self.cursor += 1;
            }
            let exponent_start = self.cursor;
            while self.bytes.get(self.cursor).is_some_and(u8::is_ascii_digit) {
                self.cursor += 1;
            }
            if self.cursor == exponent_start {
                return Err(());
            }
        }
        self.record_if_target(SourceSpan::new(self.base + start, self.base + self.cursor));
        Ok(())
    }

    fn record_if_target(&mut self, value: SourceSpan) {
        if self.found.is_none() && value.contains(self.target) && self.path.len != 0 {
            self.found = Some(StructuredSourceEvidence::new(
                SemanticSourceRole::StructuredAssignmentValue,
                self.target,
                value,
                &self.path,
            ));
        }
    }

    fn skip_ws(&mut self) {
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.cursor += 1;
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.cursor) == Some(&byte) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }
}

fn classify_dotenv(text: &str, target: SourceSpan) -> Option<StructuredSourceEvidence> {
    let search_start = target.start.saturating_sub(MAX_SEMANTIC_WINDOW_BYTES);
    let mut current_line_start = line_start(text, target.start);
    loop {
        if current_line_start < search_start {
            return None;
        }
        if let Some((key, value)) = parse_dotenv_assignment(text, current_line_start) {
            if value.contains(target) {
                let mut path = KeyPath::new();
                path.push(key);
                return Some(StructuredSourceEvidence::new(
                    SemanticSourceRole::EnvironmentAssignmentValue,
                    target,
                    value,
                    &path,
                ));
            }
        }
        if current_line_start == 0 {
            return None;
        }
        current_line_start = line_start(text, current_line_start.saturating_sub(1));
    }
}

fn parse_dotenv_assignment(text: &str, start: usize) -> Option<(SourceSpan, SourceSpan)> {
    let bytes = text.as_bytes();
    let mut cursor = skip_ascii_ws(bytes, start);
    let line_end = line_end(text, cursor);
    if bytes.get(cursor..cursor + 6) == Some(b"export")
        && bytes.get(cursor + 6).is_some_and(u8::is_ascii_whitespace)
    {
        cursor = skip_ascii_ws(bytes, cursor + 6);
    }
    let key_start = cursor;
    if !bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
    {
        return None;
    }
    cursor += 1;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        cursor += 1;
    }
    let key = SourceSpan::new(key_start, cursor);
    cursor = skip_ascii_ws_until(bytes, cursor, line_end);
    if bytes.get(cursor) != Some(&b'=') {
        return None;
    }
    cursor = skip_ascii_ws_until(bytes, cursor + 1, line_end);
    let value = parse_line_or_quoted_value(text, cursor, b"#", true)?;
    Some((key, value))
}

fn classify_toml(text: &str, target: SourceSpan) -> Option<StructuredSourceEvidence> {
    let search_start = target.start.saturating_sub(MAX_SEMANTIC_WINDOW_BYTES);
    let mut assignment_start = line_start(text, target.start);
    loop {
        if assignment_start < search_start {
            return None;
        }
        if let Some((keys, value)) = parse_toml_assignment(text, assignment_start) {
            if value.contains(target) {
                let mut path = toml_section_path(text, assignment_start, search_start)?;
                if !path.append(&keys) {
                    return None;
                }
                return Some(StructuredSourceEvidence::new(
                    SemanticSourceRole::StructuredAssignmentValue,
                    target,
                    value,
                    &path,
                ));
            }
        }
        if assignment_start == 0 {
            return None;
        }
        assignment_start = line_start(text, assignment_start.saturating_sub(1));
    }
}

fn parse_toml_assignment(text: &str, start: usize) -> Option<(KeyPath, SourceSpan)> {
    let end = line_end(text, start);
    let delimiter = find_unquoted_delimiter(text.as_bytes(), start, end, b'=')?;
    let key_span = trim_ascii_span(text.as_bytes(), start, delimiter);
    if key_span.start == key_span.end || text.as_bytes().get(key_span.start) == Some(&b'#') {
        return None;
    }
    let keys = parse_dotted_key(text, key_span)?;
    let value_start = skip_ascii_ws_until(text.as_bytes(), delimiter + 1, end);
    let value = parse_toml_value(text, value_start)?;
    Some((keys, value))
}

fn parse_toml_value(text: &str, start: usize) -> Option<SourceSpan> {
    let bytes = text.as_bytes();
    let quote = *bytes.get(start)?;
    if matches!(quote, b'\'' | b'"')
        && bytes.get(start..start + 3) == Some([quote, quote, quote].as_slice())
    {
        let content_start = start + 3;
        let limit = content_start
            .saturating_add(MAX_SEMANTIC_WINDOW_BYTES)
            .min(bytes.len());
        let close = find_sequence(bytes, content_start, limit, &[quote, quote, quote])?;
        return Some(SourceSpan::new(content_start, close));
    }
    if matches!(quote, b'\'' | b'"') {
        let close = find_closing_quote(
            bytes,
            start + 1,
            quote,
            quote == b'"',
            line_end(text, start),
        )?;
        return Some(SourceSpan::new(start + 1, close));
    }
    let end = line_end(text, start);
    let mut value_end = end;
    if let Some(comment) = find_unquoted_delimiter(bytes, start, end, b'#') {
        value_end = comment;
    }
    let value = trim_ascii_span(bytes, start, value_end);
    (value.start < value.end).then_some(value)
}

fn toml_section_path(text: &str, before: usize, lower_bound: usize) -> Option<KeyPath> {
    let mut cursor = before;
    while cursor > lower_bound {
        cursor = line_start(text, cursor.saturating_sub(1));
        let end = line_end(text, cursor);
        let span = trim_ascii_span(text.as_bytes(), cursor, end);
        let line = text.as_bytes().get(span.start..span.end)?;
        if line.starts_with(b"[[") {
            if !line.ends_with(b"]]") {
                return None;
            }
            return parse_dotted_key(text, SourceSpan::new(span.start + 2, span.end - 2));
        }
        if line.starts_with(b"[") {
            if !line.ends_with(b"]") {
                return None;
            }
            return parse_dotted_key(text, SourceSpan::new(span.start + 1, span.end - 1));
        }
        if cursor == 0 {
            break;
        }
    }
    Some(KeyPath::new())
}

fn classify_ini(text: &str, target: SourceSpan) -> Option<StructuredSourceEvidence> {
    let start = line_start(text, target.start);
    let end = line_end(text, target.start);
    let delimiter = find_first_unquoted(text.as_bytes(), start, end, &[b'=', b':'])?;
    let key = trim_ascii_span(text.as_bytes(), start, delimiter);
    if key.start == key.end || matches!(text.as_bytes()[key.start], b'#' | b';' | b'[') {
        return None;
    }
    let value_start = skip_ascii_ws_until(text.as_bytes(), delimiter + 1, end);
    let value = parse_line_or_quoted_value(text, value_start, b";#", false)?;
    if !value.contains(target) {
        return None;
    }
    let mut path = ini_section_path(
        text,
        start,
        target.start.saturating_sub(MAX_SEMANTIC_WINDOW_BYTES),
    )?;
    if !path.push(key) {
        return None;
    }
    Some(StructuredSourceEvidence::new(
        SemanticSourceRole::StructuredAssignmentValue,
        target,
        value,
        &path,
    ))
}

fn ini_section_path(text: &str, before: usize, lower_bound: usize) -> Option<KeyPath> {
    let mut cursor = before;
    while cursor > lower_bound {
        cursor = line_start(text, cursor.saturating_sub(1));
        let end = line_end(text, cursor);
        let span = trim_ascii_span(text.as_bytes(), cursor, end);
        if text.as_bytes().get(span.start) == Some(&b'[') {
            if text.as_bytes().get(span.end.saturating_sub(1)) != Some(&b']') {
                return None;
            }
            let mut path = KeyPath::new();
            path.push(SourceSpan::new(span.start + 1, span.end - 1));
            return Some(path);
        }
        if cursor == 0 {
            break;
        }
    }
    Some(KeyPath::new())
}

fn classify_yaml(text: &str, target: SourceSpan) -> Option<StructuredSourceEvidence> {
    let lower_bound = target.start.saturating_sub(MAX_SEMANTIC_WINDOW_BYTES);
    let mut cursor = line_start(text, target.start);
    loop {
        if cursor < lower_bound {
            return None;
        }
        if let Some(mapping) = parse_yaml_mapping(text, cursor) {
            if mapping.value.contains(target) {
                let path = yaml_key_path(text, cursor, lower_bound, mapping.indent, mapping.key)?;
                return Some(StructuredSourceEvidence::new(
                    SemanticSourceRole::StructuredAssignmentValue,
                    target,
                    mapping.value,
                    &path,
                ));
            }
        }
        if cursor == 0 {
            return None;
        }
        cursor = line_start(text, cursor.saturating_sub(1));
    }
}

struct YamlMapping {
    indent: usize,
    key: SourceSpan,
    value: SourceSpan,
}

fn parse_yaml_mapping(text: &str, start: usize) -> Option<YamlMapping> {
    let bytes = text.as_bytes();
    let end = line_end(text, start);
    let mut cursor = start;
    while bytes.get(cursor) == Some(&b' ') {
        cursor += 1;
    }
    let indent = cursor - start;
    if bytes.get(cursor) == Some(&b'-')
        && bytes.get(cursor + 1).is_some_and(u8::is_ascii_whitespace)
    {
        cursor = skip_ascii_ws_until(bytes, cursor + 1, end);
    }
    if matches!(bytes.get(cursor), None | Some(b'#')) {
        return None;
    }
    let delimiter = find_unquoted_delimiter(bytes, cursor, end, b':')?;
    let key = trim_ascii_span(bytes, cursor, delimiter);
    if key.start == key.end {
        return None;
    }
    let mut value_start = skip_ascii_ws_until(bytes, delimiter + 1, end);
    while matches!(bytes.get(value_start), Some(b'!' | b'&')) {
        value_start += 1;
        while bytes
            .get(value_start)
            .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            value_start += 1;
        }
        value_start = skip_ascii_ws_until(bytes, value_start, end);
    }
    if value_start == end {
        return Some(YamlMapping {
            indent,
            key,
            value: SourceSpan::new(end, end),
        });
    }
    if matches!(bytes.get(value_start), Some(b'|' | b'>')) {
        let value = yaml_block_span(text, start, indent)?;
        return Some(YamlMapping { indent, key, value });
    }
    let value = parse_line_or_quoted_value(text, value_start, b"#", true)?;
    Some(YamlMapping { indent, key, value })
}

fn yaml_block_span(text: &str, header_start: usize, header_indent: usize) -> Option<SourceSpan> {
    let mut cursor = next_line_start(text, header_start)?;
    let content_start = cursor;
    let mut content_end = cursor;
    let limit = header_start
        .saturating_add(MAX_SEMANTIC_WINDOW_BYTES)
        .min(text.len());
    while cursor < limit {
        let end = line_end(text, cursor);
        let indent = text.as_bytes()[cursor..end]
            .iter()
            .take_while(|byte| **byte == b' ')
            .count();
        let blank = text.as_bytes()[cursor..end]
            .iter()
            .all(u8::is_ascii_whitespace);
        if !blank && indent <= header_indent {
            break;
        }
        content_end = end;
        let Some(next) = next_line_start(text, cursor) else {
            break;
        };
        cursor = next;
    }
    (content_start < content_end).then_some(SourceSpan::new(content_start, content_end))
}

fn yaml_key_path(
    text: &str,
    line: usize,
    lower_bound: usize,
    indent: usize,
    leaf: SourceSpan,
) -> Option<KeyPath> {
    let mut parents = [SourceSpan::new(0, 0); MAX_KEY_PATH_SEGMENTS];
    let mut parent_len = 0usize;
    let mut required_indent = indent;
    let mut cursor = line;
    while cursor > lower_bound && required_indent > 0 {
        cursor = line_start(text, cursor.saturating_sub(1));
        if let Some(mapping) = parse_yaml_mapping(text, cursor) {
            if mapping.indent < required_indent && mapping.value.start == mapping.value.end {
                if parent_len == parents.len().saturating_sub(1) {
                    return None;
                }
                parents[parent_len] = mapping.key;
                parent_len += 1;
                required_indent = mapping.indent;
            }
        }
        if cursor == 0 {
            break;
        }
    }
    let mut path = KeyPath::new();
    for parent in parents[..parent_len].iter().rev().copied() {
        path.push(parent);
    }
    path.push(leaf);
    Some(path)
}

fn parse_line_or_quoted_value(
    text: &str,
    start: usize,
    comments: &[u8],
    allow_multiline_quote: bool,
) -> Option<SourceSpan> {
    let bytes = text.as_bytes();
    let quote = *bytes.get(start)?;
    if matches!(quote, b'\'' | b'\"') {
        let limit = if allow_multiline_quote {
            start
                .saturating_add(MAX_SEMANTIC_WINDOW_BYTES)
                .min(text.len())
        } else {
            line_end(text, start)
        };
        let close = find_closing_quote(bytes, start + 1, quote, quote == b'\"', limit)?;
        let trailing_end = line_end(text, close + 1);
        let trailing = trim_ascii_span(bytes, close + 1, trailing_end);
        if trailing.start < trailing.end
            && !bytes
                .get(trailing.start)
                .is_some_and(|byte| comments.contains(byte))
        {
            return None;
        }
        return Some(SourceSpan::new(start + 1, close));
    }
    let end = line_end(text, start);
    let comment_start = find_first_unquoted(bytes, start, end, comments).unwrap_or(end);
    let value = trim_ascii_span(bytes, start, comment_start);
    (value.start < value.end).then_some(value)
}

fn parse_dotted_key(text: &str, span: SourceSpan) -> Option<KeyPath> {
    let bytes = text.as_bytes();
    let mut cursor = span.start;
    let mut path = KeyPath::new();
    while cursor < span.end {
        cursor = skip_ascii_ws_until(bytes, cursor, span.end);
        let segment = match bytes.get(cursor).copied()? {
            quote @ (b'\'' | b'"') => {
                let close = find_closing_quote(bytes, cursor + 1, quote, quote == b'"', span.end)?;
                let segment = SourceSpan::new(cursor + 1, close);
                cursor = close + 1;
                segment
            }
            _ => {
                let start = cursor;
                while cursor < span.end
                    && bytes.get(cursor).is_some_and(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
                    })
                {
                    cursor += 1;
                }
                if start == cursor {
                    return None;
                }
                SourceSpan::new(start, cursor)
            }
        };
        if !path.push(segment) {
            return None;
        }
        cursor = skip_ascii_ws_until(bytes, cursor, span.end);
        if cursor == span.end {
            break;
        }
        if bytes.get(cursor) != Some(&b'.') {
            return None;
        }
        cursor += 1;
    }
    (path.len != 0).then_some(path)
}

fn find_unquoted_delimiter(bytes: &[u8], start: usize, end: usize, delimiter: u8) -> Option<usize> {
    find_first_unquoted(bytes, start, end, &[delimiter])
}

fn find_first_unquoted(bytes: &[u8], start: usize, end: usize, delimiters: &[u8]) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for index in start..end {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some(b'"') && byte == b'\\' {
            escaped = true;
            continue;
        }
        if matches!(byte, b'\'' | b'"') {
            if quote == Some(byte) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(byte);
            }
            continue;
        }
        if quote.is_none() && delimiters.contains(&byte) {
            return Some(index);
        }
    }
    None
}

fn find_closing_quote(
    bytes: &[u8],
    mut cursor: usize,
    quote: u8,
    escapes: bool,
    limit: usize,
) -> Option<usize> {
    while cursor < limit {
        match bytes[cursor] {
            byte if byte == quote => return Some(cursor),
            b'\\' if escapes => cursor = cursor.saturating_add(2),
            _ => cursor += 1,
        }
    }
    None
}

fn find_sequence(bytes: &[u8], start: usize, end: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(start..end)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start + offset)
}

fn trim_ascii_span(bytes: &[u8], mut start: usize, mut end: usize) -> SourceSpan {
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    SourceSpan::new(start, end)
}

fn skip_ascii_ws(bytes: &[u8], mut cursor: usize) -> usize {
    while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    cursor
}

fn skip_ascii_ws_until(bytes: &[u8], mut cursor: usize, end: usize) -> usize {
    while cursor < end && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    cursor
}

fn line_start(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1)
}

fn line_end(text: &str, offset: usize) -> usize {
    text.as_bytes()[offset.min(text.len())..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map_or(text.len(), |index| offset.min(text.len()) + index)
}

fn line_bounds(text: &str, offset: usize) -> (usize, usize) {
    (line_start(text, offset), line_end(text, offset))
}

fn next_line_start(text: &str, start: usize) -> Option<usize> {
    let end = line_end(text, start);
    (end < text.len()).then_some(end + 1)
}
