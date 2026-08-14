//! Candidate-bounded source-role evidence.
//!
//! This module classifies only the bounded source containing an emitted
//! candidate. It never walks a repository or parses a file before retrieval.

use keyhog_core::SemanticSourceRole;

pub(crate) const MAX_SEMANTIC_WINDOW_BYTES: usize = 64 * 1024;
const MAX_KEY_PATH_SEGMENTS: usize = 12;

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
    pub(crate) const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub(crate) const fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceSemanticEvidence {
    pub(crate) role: SemanticSourceRole,
    pub(crate) confidence: SemanticParserConfidence,
    pub(crate) candidate_span: SourceSpan,
    pub(crate) value_span: SourceSpan,
    key_path: [SourceSpan; MAX_KEY_PATH_SEGMENTS],
    key_path_len: u8,
}

impl SourceSemanticEvidence {
    pub(crate) const fn parsed(
        role: SemanticSourceRole,
        candidate_span: SourceSpan,
        value_span: SourceSpan,
    ) -> Self {
        Self {
            role,
            confidence: SemanticParserConfidence::Parsed,
            candidate_span,
            value_span,
            key_path: [SourceSpan::new(0, 0); MAX_KEY_PATH_SEGMENTS],
            key_path_len: 0,
        }
    }

    pub(crate) fn key_path(&self) -> impl Iterator<Item = SourceSpan> + '_ {
        self.key_path[..usize::from(self.key_path_len)]
            .iter()
            .copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StructuredValueEvidence {
    role: SemanticSourceRole,
    value_span: SourceSpan,
    key_path: [SourceSpan; MAX_KEY_PATH_SEGMENTS],
    key_path_len: u8,
}

impl StructuredValueEvidence {
    fn new(role: SemanticSourceRole, value_span: SourceSpan, key_path: &KeyPath) -> Self {
        Self {
            role,
            value_span,
            key_path: key_path.segments,
            key_path_len: key_path.len,
        }
    }

    fn for_candidate(self, candidate_span: SourceSpan) -> Option<SourceSemanticEvidence> {
        self.value_span
            .contains(candidate_span)
            .then_some(SourceSemanticEvidence {
                role: self.role,
                confidence: SemanticParserConfidence::Parsed,
                candidate_span,
                value_span: self.value_span,
                key_path: self.key_path,
                key_path_len: self.key_path_len,
            })
    }
}

#[derive(Debug, Default)]
pub(crate) struct StructuredSourceIndex {
    values: Vec<StructuredValueEvidence>,
}

impl StructuredSourceIndex {
    fn push(&mut self, role: SemanticSourceRole, value_span: SourceSpan, key_path: &KeyPath) {
        if value_span.start < value_span.end {
            self.values
                .push(StructuredValueEvidence::new(role, value_span, key_path));
        }
    }

    pub(crate) fn classify(&self, candidate_span: SourceSpan) -> Option<SourceSemanticEvidence> {
        self.values
            .iter()
            .copied()
            .find_map(|value| value.for_candidate(candidate_span))
    }
}

#[derive(Debug)]
pub(crate) enum CandidateSourceIndex {
    Structured(StructuredSourceIndex),
    Code(crate::code_semantics::CodeSourceIndex),
}

impl CandidateSourceIndex {
    pub(crate) fn classify(&self, candidate_span: SourceSpan) -> Option<SourceSemanticEvidence> {
        match self {
            Self::Structured(index) => index.classify(candidate_span),
            Self::Code(index) => index.classify(candidate_span),
        }
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
) -> Option<SourceSemanticEvidence> {
    let candidate_end = candidate_start.checked_add(candidate.len())?;
    if text.get(candidate_start..candidate_end) != Some(candidate) {
        return None;
    }
    classify_structured_candidate(text, path, candidate_start, candidate_end)
}

/// Classify one exact source candidate. Unsupported syntax, an invalid parse,
/// an out-of-bounds span, and oversized parser input all abstain.
pub(crate) fn classify_structured_candidate(
    text: &str,
    path: Option<&str>,
    candidate_start: usize,
    candidate_end: usize,
) -> Option<SourceSemanticEvidence> {
    let target = checked_candidate_span(text, candidate_start, candidate_end)?;
    build_structured_source_index(text, path)?.classify(target)
}

fn checked_candidate_span(
    text: &str,
    candidate_start: usize,
    candidate_end: usize,
) -> Option<SourceSpan> {
    (candidate_start < candidate_end
        && candidate_end <= text.len()
        && text.is_char_boundary(candidate_start)
        && text.is_char_boundary(candidate_end))
    .then_some(SourceSpan::new(candidate_start, candidate_end))
}

pub(crate) fn build_structured_source_index(
    text: &str,
    path: Option<&str>,
) -> Option<StructuredSourceIndex> {
    if text.len() > MAX_SEMANTIC_WINDOW_BYTES {
        return None;
    }
    match syntax_for_path(path?)? {
        StructuredSyntax::Json => index_json(text, 0),
        StructuredSyntax::JsonLines => index_json_lines(text),
        StructuredSyntax::Toml => index_toml(text),
        StructuredSyntax::Yaml => index_yaml(text),
        StructuredSyntax::Dotenv => index_dotenv(text),
        StructuredSyntax::Ini => index_ini(text),
    }
}

pub(crate) fn build_candidate_source_index(
    text: &str,
    path: Option<&str>,
) -> Option<CandidateSourceIndex> {
    let path = path?;
    if syntax_for_path(path).is_some() {
        build_structured_source_index(text, Some(path)).map(CandidateSourceIndex::Structured)
    } else {
        crate::code_semantics::build_code_source_index(text, path).map(CandidateSourceIndex::Code)
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
    path: KeyPath,
    index: StructuredSourceIndex,
}

fn index_json(text: &str, base: usize) -> Option<StructuredSourceIndex> {
    let mut parser = JsonParser {
        bytes: text.as_bytes(),
        base,
        cursor: 0,
        path: KeyPath::new(),
        index: StructuredSourceIndex::default(),
    };
    parser.parse_value(0).ok()?;
    parser.skip_ws();
    (parser.cursor == parser.bytes.len()).then_some(parser.index)
}

fn index_json_lines(text: &str) -> Option<StructuredSourceIndex> {
    let mut index = StructuredSourceIndex::default();
    let mut start = 0;
    loop {
        let end = line_end(text, start);
        if !text[start..end].trim().is_empty() {
            index
                .values
                .extend(index_json(&text[start..end], start)?.values);
        }
        let Some(next) = next_line_start(text, start) else {
            return Some(index);
        };
        start = next;
    }
}

impl JsonParser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<(), ()> {
        if depth > crate::structured::parsers::MAX_STRUCTURED_TRAVERSAL_DEPTH {
            return Err(());
        }
        self.skip_ws();
        match self.bytes.get(self.cursor).copied() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => {
                let value = self.parse_string()?;
                self.record_value(value);
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
        self.record_value(SourceSpan::new(self.base + start, self.base + self.cursor));
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
        self.record_value(SourceSpan::new(self.base + start, self.base + self.cursor));
        Ok(())
    }

    fn record_value(&mut self, value: SourceSpan) {
        if self.path.len != 0 {
            self.index.push(
                SemanticSourceRole::StructuredAssignmentValue,
                value,
                &self.path,
            );
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

fn index_dotenv(text: &str) -> Option<StructuredSourceIndex> {
    let mut index = StructuredSourceIndex::default();
    let mut current_line_start = 0;
    loop {
        let mut consumed_through = current_line_start;
        match parse_dotenv_assignment(text, current_line_start) {
            Some((key, value)) => {
                let mut path = KeyPath::new();
                if !path.push(key) {
                    return None;
                }
                index.push(SemanticSourceRole::EnvironmentAssignmentValue, value, &path);
                consumed_through = line_start(text, value.end);
            }
            None if line_starts_quoted_assignment(text, current_line_start) => return None,
            None => {}
        }
        let Some(next) = next_line_start(text, consumed_through) else {
            return Some(index);
        };
        current_line_start = next;
    }
}

fn parse_dotenv_assignment(text: &str, start: usize) -> Option<(SourceSpan, SourceSpan)> {
    let bytes = text.as_bytes();
    let line_end = line_end(text, start);
    let mut cursor = skip_ascii_ws_until(bytes, start, line_end);
    if bytes.get(cursor..cursor + 6) == Some(b"export")
        && bytes.get(cursor + 6).is_some_and(u8::is_ascii_whitespace)
    {
        cursor = skip_ascii_ws_until(bytes, cursor + 6, line_end);
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
    let value = parse_line_or_quoted_value(text, cursor, b"#", true, false)?;
    Some((key, value))
}

fn line_starts_quoted_assignment(text: &str, start: usize) -> bool {
    let bytes = text.as_bytes();
    let end = line_end(text, start);
    let Some(delimiter) = find_unquoted_delimiter(bytes, start, end, b'=') else {
        return false;
    };
    let value_start = skip_ascii_ws_until(bytes, delimiter + 1, end);
    matches!(bytes.get(value_start), Some(b'\'' | b'"'))
}

fn index_toml(text: &str) -> Option<StructuredSourceIndex> {
    let mut index = StructuredSourceIndex::default();
    let mut assignment_start = 0;
    loop {
        let line_span = trim_ascii_span(
            text.as_bytes(),
            assignment_start,
            line_end(text, assignment_start),
        );
        let line = text.as_bytes().get(line_span.start..line_span.end)?;
        if line.starts_with(b"[") {
            let valid_section = if line.starts_with(b"[[") {
                line.ends_with(b"]]")
                    && parse_dotted_key(
                        text,
                        SourceSpan::new(line_span.start + 2, line_span.end - 2),
                    )
                    .is_some()
            } else {
                line.ends_with(b"]")
                    && parse_dotted_key(
                        text,
                        SourceSpan::new(line_span.start + 1, line_span.end - 1),
                    )
                    .is_some()
            };
            if !valid_section {
                return None;
            }
        }

        let mut consumed_through = assignment_start;
        match parse_toml_assignment(text, assignment_start) {
            Some((keys, value)) => {
                let mut path = toml_section_path(text, assignment_start, 0)?;
                if !path.append(&keys) {
                    return None;
                }
                index.push(SemanticSourceRole::StructuredAssignmentValue, value, &path);
                consumed_through = line_start(text, value.end);
            }
            None if line_starts_quoted_assignment(text, assignment_start) => return None,
            None => {}
        }
        let Some(next) = next_line_start(text, consumed_through) else {
            return Some(index);
        };
        assignment_start = next;
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

fn index_ini(text: &str) -> Option<StructuredSourceIndex> {
    let mut index = StructuredSourceIndex::default();
    let mut section = KeyPath::new();
    let mut start = 0;
    loop {
        let end = line_end(text, start);
        let line = trim_ascii_span(text.as_bytes(), start, end);
        if line.start < line.end {
            match text.as_bytes()[line.start] {
                b'#' | b';' => {}
                b'[' => {
                    if text.as_bytes().get(line.end.saturating_sub(1)) != Some(&b']') {
                        return None;
                    }
                    section = KeyPath::new();
                    if !section.push(SourceSpan::new(line.start + 1, line.end - 1)) {
                        return None;
                    }
                }
                _ => {
                    if let Some(delimiter) =
                        find_first_unquoted(text.as_bytes(), start, end, &[b'=', b':'])
                    {
                        let key = trim_ascii_span(text.as_bytes(), start, delimiter);
                        let value_start = skip_ascii_ws_until(text.as_bytes(), delimiter + 1, end);
                        let value =
                            parse_line_or_quoted_value(text, value_start, b";#", false, false)?;
                        let mut path = section;
                        if key.start == key.end || !path.push(key) {
                            return None;
                        }
                        index.push(SemanticSourceRole::StructuredAssignmentValue, value, &path);
                    }
                }
            }
        }
        let Some(next) = next_line_start(text, start) else {
            return Some(index);
        };
        start = next;
    }
}

fn index_yaml(text: &str) -> Option<StructuredSourceIndex> {
    let mut index = StructuredSourceIndex::default();
    let mut cursor = 0;
    loop {
        let mut consumed_through = cursor;
        if let Some(mapping) = parse_yaml_mapping(text, cursor) {
            let path = yaml_key_path(text, cursor, 0, mapping.indent, mapping.key)?;
            index.push(
                SemanticSourceRole::StructuredAssignmentValue,
                mapping.value,
                &path,
            );
            consumed_through = line_start(text, mapping.value.end);
        } else if line_starts_quoted_mapping(text, cursor) {
            return None;
        }
        let Some(next) = next_line_start(text, consumed_through) else {
            return Some(index);
        };
        cursor = next;
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
    let value = parse_line_or_quoted_value(text, value_start, b"#", true, true)?;
    Some(YamlMapping { indent, key, value })
}

fn line_starts_quoted_mapping(text: &str, start: usize) -> bool {
    let bytes = text.as_bytes();
    let end = line_end(text, start);
    let Some(delimiter) = find_unquoted_delimiter(bytes, start, end, b':') else {
        return false;
    };
    let value_start = skip_ascii_ws_until(bytes, delimiter + 1, end);
    matches!(bytes.get(value_start), Some(b'\'' | b'"'))
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
    quote_aware_comments: bool,
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
    let comment_start = if quote_aware_comments {
        find_first_unquoted(bytes, start, end, comments).unwrap_or(end)
    } else {
        bytes[start..end]
            .iter()
            .position(|byte| comments.contains(byte))
            .map_or(end, |offset| start + offset)
    };
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
