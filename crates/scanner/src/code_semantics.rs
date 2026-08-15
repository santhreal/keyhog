//! Candidate-bounded source roles for Rust, JavaScript/TypeScript, and Python.

use std::sync::LazyLock;

use keyhog_core::SemanticSourceRole;

use crate::source_semantics::{SourceSemanticEvidence, SourceSpan};

pub(crate) const MAX_CODE_SOURCE_BYTES: usize = 64 * 1024;

const CODE_ROLE_MARKERS_TOML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/rules/code-source-role-markers.toml"
));

#[derive(serde::Deserialize)]
struct CodeRoleMarkerFile {
    schema_version: u32,
    markers: CodeRoleMarkers,
}

#[derive(serde::Deserialize)]
struct CodeRoleMarkers {
    option_declarations: Vec<String>,
    command_invocations: Vec<String>,
    regex_constructors: Vec<String>,
}

static CODE_ROLE_MARKERS: LazyLock<CodeRoleMarkers> = LazyLock::new(|| {
    let parsed: CodeRoleMarkerFile = match toml::from_str(CODE_ROLE_MARKERS_TOML) {
        Ok(parsed) => parsed,
        Err(error) => panic!(
            "invalid rules/code-source-role-markers.toml: {error}. Fix the bundled role markers; refusing to classify source roles without them."
        ),
    };
    if parsed.schema_version != 1 {
        panic!(
            "unsupported rules/code-source-role-markers.toml schema {}; expected 1",
            parsed.schema_version
        );
    }
    let marker_sets = [
        &parsed.markers.option_declarations,
        &parsed.markers.command_invocations,
        &parsed.markers.regex_constructors,
    ];
    if marker_sets
        .iter()
        .any(|markers| markers.is_empty() || markers.iter().any(String::is_empty))
    {
        panic!("rules/code-source-role-markers.toml requires non-empty marker sets and spellings");
    }
    parsed.markers
});

#[derive(Clone, Copy, PartialEq, Eq)]
enum CodeLanguage {
    Rust,
    JavaScript,
    Python,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LexemeKind {
    String,
    Regex,
    Identifier,
}

#[derive(Clone, Copy)]
struct CodeLexeme {
    span: SourceSpan,
    kind: LexemeKind,
    role: SemanticSourceRole,
}

#[derive(Debug)]
pub(crate) struct CodeSourceIndex {
    lexemes: Vec<CodeLexeme>,
    test_scopes: Vec<SourceSpan>,
}

impl std::fmt::Debug for CodeLexeme {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CodeLexeme")
            .field("span", &self.span)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl CodeSourceIndex {
    pub(crate) fn classify(&self, target: SourceSpan) -> Option<SourceSemanticEvidence> {
        let lexeme = self
            .lexemes
            .iter()
            .filter(|lexeme| lexeme.span.contains(target))
            .min_by_key(|lexeme| lexeme.span.end.saturating_sub(lexeme.span.start))?;
        let role = if self.test_scopes.iter().any(|scope| scope.contains(target)) {
            SemanticSourceRole::TestFixture
        } else {
            lexeme.role
        };
        Some(SourceSemanticEvidence::parsed(role, target, lexeme.span))
    }
}

pub(crate) fn build_code_source_index(text: &str, path: &str) -> Option<CodeSourceIndex> {
    if text.len() > MAX_CODE_SOURCE_BYTES {
        return None;
    }
    let language = language_for_path(path)?;
    let mut lexer = CodeLexer::new(text, language);
    lexer.parse()?;
    lexer.assign_context_roles();
    let mut test_scopes = if crate::context::is_test_file(path) {
        vec![SourceSpan::new(0, text.len())]
    } else {
        match language {
            CodeLanguage::Rust => rust_test_scopes(&lexer.mask),
            CodeLanguage::JavaScript => javascript_test_scopes(&lexer.mask),
            CodeLanguage::Python => python_test_scopes(text),
        }
    };
    test_scopes.sort_by_key(|span| (span.start, span.end));
    Some(CodeSourceIndex {
        lexemes: lexer.lexemes,
        test_scopes,
    })
}

fn language_for_path(path: &str) -> Option<CodeLanguage> {
    let name = path
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(path)
        .split('?')
        .next()
        .unwrap_or(path);
    let extension = name.rsplit_once('.')?.1;
    if extension.eq_ignore_ascii_case("rs") {
        Some(CodeLanguage::Rust)
    } else if ["js", "jsx", "ts", "tsx", "mjs", "cjs"]
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    {
        Some(CodeLanguage::JavaScript)
    } else if extension.eq_ignore_ascii_case("py") || extension.eq_ignore_ascii_case("pyi") {
        Some(CodeLanguage::Python)
    } else {
        None
    }
}

struct CodeLexer<'a> {
    text: &'a str,
    bytes: &'a [u8],
    language: CodeLanguage,
    cursor: usize,
    mask: Vec<u8>,
    lexemes: Vec<CodeLexeme>,
}

impl<'a> CodeLexer<'a> {
    fn javascript_template_expression_end(bytes: &[u8], start: usize) -> Option<usize> {
        let mut cursor = start;
        let mut depth = 1usize;
        let mut quote = None;
        while cursor < bytes.len() {
            if let Some(active_quote) = quote {
                if bytes[cursor] == b'\\' {
                    cursor = cursor.saturating_add(2);
                } else if bytes[cursor] == active_quote {
                    quote = None;
                    cursor += 1;
                } else if matches!(bytes[cursor], b'\r' | b'\n') {
                    return None;
                } else {
                    cursor += 1;
                }
                continue;
            }
            if bytes.get(cursor..cursor + 2) == Some(b"//") {
                cursor += 2;
                while cursor < bytes.len() && !matches!(bytes[cursor], b'\r' | b'\n') {
                    cursor += 1;
                }
            } else if bytes.get(cursor..cursor + 2) == Some(b"/*") {
                let relative = memchr::memmem::find(&bytes[cursor + 2..], b"*/")?;
                cursor += 2 + relative + 2;
            } else {
                match bytes[cursor] {
                    b'"' | b'\'' => {
                        quote = Some(bytes[cursor]);
                        cursor += 1;
                    }
                    b'`' | b'/' => return None,
                    b'{' => {
                        depth = depth.checked_add(1)?;
                        if depth > crate::structured::parsers::MAX_STRUCTURED_TRAVERSAL_DEPTH {
                            return None;
                        }
                        cursor += 1;
                    }
                    b'}' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(cursor);
                        }
                        cursor += 1;
                    }
                    _ => cursor += 1,
                }
            }
        }
        None
    }
    fn new(text: &'a str, language: CodeLanguage) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            language,
            cursor: 0,
            mask: text.as_bytes().to_vec(),
            lexemes: Vec::new(),
        }
    }

    fn parse(&mut self) -> Option<()> {
        while self.cursor < self.bytes.len() {
            if self.starts_line_comment() {
                self.blank_line_comment();
            } else if self.starts_block_comment() {
                self.blank_block_comment()?;
            } else if self.language == CodeLanguage::Rust && self.parse_rust_raw_string()? {
            } else if self.language == CodeLanguage::JavaScript && self.bytes[self.cursor] == b'`' {
                self.parse_javascript_template()?;
            } else if self.starts_string() {
                self.parse_quoted_string()?;
            } else if self.language == CodeLanguage::JavaScript
                && self.bytes[self.cursor] == b'/'
                && self.javascript_regex_can_start()
            {
                self.parse_javascript_regex()?;
            } else if is_identifier_start(self.bytes[self.cursor]) {
                self.parse_identifier();
            } else {
                self.cursor += 1;
            }
        }
        if !balanced_delimiters(&self.mask) {
            return None;
        }
        Some(())
    }

    fn starts_line_comment(&self) -> bool {
        match self.language {
            CodeLanguage::Rust | CodeLanguage::JavaScript => {
                self.bytes.get(self.cursor..self.cursor + 2) == Some(b"//")
            }
            CodeLanguage::Python => self.bytes.get(self.cursor) == Some(&b'#'),
        }
    }

    fn starts_block_comment(&self) -> bool {
        matches!(self.language, CodeLanguage::Rust | CodeLanguage::JavaScript)
            && self.bytes.get(self.cursor..self.cursor + 2) == Some(b"/*")
    }

    fn blank_line_comment(&mut self) {
        let start = self.cursor;
        while self.cursor < self.bytes.len() && !matches!(self.bytes[self.cursor], b'\r' | b'\n') {
            self.cursor += 1;
        }
        self.mask[start..self.cursor].fill(b' ');
    }

    fn blank_block_comment(&mut self) -> Option<()> {
        let start = self.cursor;
        self.cursor += 2;
        let mut depth = 1usize;
        while self.cursor < self.bytes.len() {
            if self.language == CodeLanguage::Rust
                && self.bytes.get(self.cursor..self.cursor + 2) == Some(b"/*")
            {
                depth = depth.checked_add(1)?;
                self.cursor += 2;
            } else if self.bytes.get(self.cursor..self.cursor + 2) == Some(b"*/") {
                self.cursor += 2;
                depth -= 1;
                if depth == 0 {
                    self.mask[start..self.cursor].fill(b' ');
                    return Some(());
                }
            } else {
                self.cursor += 1;
            }
        }
        None
    }

    fn starts_string(&self) -> bool {
        let byte = self.bytes[self.cursor];
        match self.language {
            CodeLanguage::Rust => byte == b'"' || (byte == b'\'' && self.rust_char_has_close()),
            CodeLanguage::JavaScript => matches!(byte, b'"' | b'\''),
            CodeLanguage::Python => matches!(byte, b'"' | b'\''),
        }
    }

    fn rust_char_has_close(&self) -> bool {
        let end = self.cursor.saturating_add(8).min(self.bytes.len());
        self.bytes[self.cursor + 1..end].contains(&b'\'')
    }

    fn parse_quoted_string(&mut self) -> Option<()> {
        let quote = self.bytes[self.cursor];
        let delimiter_len = if self.language == CodeLanguage::Python
            && self.bytes.get(self.cursor..self.cursor + 3)
                == Some([quote, quote, quote].as_slice())
        {
            3
        } else {
            1
        };
        let start = self.cursor;
        self.cursor += delimiter_len;
        let content_start = self.cursor;
        while self.cursor < self.bytes.len() {
            let closes = if delimiter_len == 1 {
                self.bytes.get(self.cursor) == Some(&quote)
            } else {
                self.bytes.get(self.cursor..self.cursor + 3)
                    == Some([quote, quote, quote].as_slice())
            };
            if closes {
                let content_end = self.cursor;
                self.cursor += delimiter_len;
                self.mask[start..self.cursor].fill(b' ');
                if quote != b'\''
                    || self.language != CodeLanguage::Rust
                    || content_end - content_start > 1
                {
                    self.push_string_lexeme(content_start, content_end);
                }
                return Some(());
            }
            if self.bytes[self.cursor] == b'\\' && quote != b'`' {
                self.cursor = self.cursor.saturating_add(2);
            } else if delimiter_len == 1
                && quote != b'`'
                && matches!(self.bytes[self.cursor], b'\r' | b'\n')
            {
                return None;
            } else {
                self.cursor += 1;
            }
        }
        None
    }

    fn parse_javascript_template(&mut self) -> Option<()> {
        let start = self.cursor;
        self.cursor += 1;
        let mut segment_start = self.cursor;
        while self.cursor < self.bytes.len() {
            if self.bytes[self.cursor] == b'\\' {
                self.cursor = self.cursor.saturating_add(2);
            } else if self.bytes.get(self.cursor..self.cursor + 2) == Some(b"${") {
                self.push_string_lexeme(segment_start, self.cursor);
                self.cursor =
                    Self::javascript_template_expression_end(self.bytes, self.cursor + 2)? + 1;
                segment_start = self.cursor;
            } else if self.bytes[self.cursor] == b'`' {
                self.push_string_lexeme(segment_start, self.cursor);
                self.cursor += 1;
                self.mask[start..self.cursor].fill(b' ');
                return Some(());
            } else {
                self.cursor += 1;
            }
        }
        None
    }

    fn push_string_lexeme(&mut self, start: usize, end: usize) {
        if start < end {
            self.lexemes.push(CodeLexeme {
                span: SourceSpan::new(start, end),
                kind: LexemeKind::String,
                role: SemanticSourceRole::StringLiteral,
            });
        }
    }

    fn parse_rust_raw_string(&mut self) -> Option<bool> {
        let start = self.cursor;
        let mut prefix_end = start;
        if self.bytes.get(prefix_end) == Some(&b'b') {
            prefix_end += 1;
        }
        if self.bytes.get(prefix_end) != Some(&b'r') {
            return Some(false);
        }
        prefix_end += 1;
        let hashes_start = prefix_end;
        while self.bytes.get(prefix_end) == Some(&b'#') {
            prefix_end += 1;
        }
        if self.bytes.get(prefix_end) != Some(&b'"') {
            return Some(false);
        }
        let hashes = prefix_end - hashes_start;
        let content_start = prefix_end + 1;
        let mut search = content_start;
        while let Some(relative) = memchr::memchr(b'"', &self.bytes[search..]) {
            let quote = search + relative;
            let close = quote + 1 + hashes;
            if close <= self.bytes.len()
                && self.bytes[quote + 1..close]
                    .iter()
                    .all(|byte| *byte == b'#')
            {
                self.cursor = close;
                self.mask[start..self.cursor].fill(b' ');
                self.lexemes.push(CodeLexeme {
                    span: SourceSpan::new(content_start, quote),
                    kind: LexemeKind::String,
                    role: SemanticSourceRole::StringLiteral,
                });
                return Some(true);
            }
            search = quote + 1;
        }
        None
    }

    fn javascript_regex_can_start(&self) -> bool {
        let previous = self.mask[..self.cursor]
            .iter()
            .rposition(|byte| !byte.is_ascii_whitespace())
            .and_then(|index| self.mask.get(index).copied());
        previous.is_none_or(|byte| {
            matches!(
                byte,
                b'=' | b'(' | b'[' | b'{' | b',' | b':' | b';' | b'!' | b'?'
            )
        })
    }

    fn parse_javascript_regex(&mut self) -> Option<()> {
        let start = self.cursor;
        self.cursor += 1;
        let content_start = self.cursor;
        let mut in_class = false;
        while self.cursor < self.bytes.len() {
            match self.bytes[self.cursor] {
                b'\\' => self.cursor = self.cursor.saturating_add(2),
                b'[' => {
                    in_class = true;
                    self.cursor += 1;
                }
                b']' => {
                    in_class = false;
                    self.cursor += 1;
                }
                b'/' if !in_class => {
                    let content_end = self.cursor;
                    self.cursor += 1;
                    while self
                        .bytes
                        .get(self.cursor)
                        .is_some_and(u8::is_ascii_alphabetic)
                    {
                        self.cursor += 1;
                    }
                    self.mask[start..self.cursor].fill(b' ');
                    self.lexemes.push(CodeLexeme {
                        span: SourceSpan::new(content_start, content_end),
                        kind: LexemeKind::Regex,
                        role: SemanticSourceRole::RegexRuleDefinition,
                    });
                    return Some(());
                }
                b'\r' | b'\n' => return None,

                _ => self.cursor += 1,
            }
        }
        None
    }

    fn parse_identifier(&mut self) {
        let start = self.cursor;
        self.cursor += 1;
        while self
            .bytes
            .get(self.cursor)
            .is_some_and(|byte| is_identifier_continue(*byte))
        {
            self.cursor += 1;
        }
        self.lexemes.push(CodeLexeme {
            span: SourceSpan::new(start, self.cursor),
            kind: LexemeKind::Identifier,
            role: SemanticSourceRole::IdentifierTypeMemberName,
        });
    }

    fn assign_context_roles(&mut self) {
        for lexeme in &mut self.lexemes {
            if lexeme.kind != LexemeKind::String {
                continue;
            }
            let content = &self.text[lexeme.span.start..lexeme.span.end];
            let context_start = lexeme.span.start.saturating_sub(192);
            let context = &self.mask[context_start..lexeme.span.start];
            if content.trim_start().starts_with('-')
                && marker_matches(context, &CODE_ROLE_MARKERS.option_declarations)
            {
                lexeme.role = SemanticSourceRole::CommandOptionDeclaration;
            } else if marker_matches(context, &CODE_ROLE_MARKERS.regex_constructors) {
                lexeme.role = SemanticSourceRole::RegexRuleDefinition;
            } else if marker_matches(context, &CODE_ROLE_MARKERS.command_invocations) {
                lexeme.role = SemanticSourceRole::CommandArgumentValue;
            }
        }
    }
}

fn marker_matches(context: &[u8], markers: &[String]) -> bool {
    markers.iter().any(|marker| {
        let marker = marker.as_bytes();
        let mut search = 0usize;
        let mut latest = None;
        while let Some(relative) = memchr::memmem::find(&context[search..], marker) {
            latest = Some(search + relative + marker.len());
            search += relative + marker.len();
        }
        let Some(latest) = latest else {
            return false;
        };
        let mut depth = 1usize;
        for &byte in &context[latest..] {
            if byte == b'(' {
                depth += 1;
            } else if byte == b')' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return false;
                }
            }
        }
        true
    })
}

fn is_identifier_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$')
}

fn is_identifier_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

fn balanced_delimiters(mask: &[u8]) -> bool {
    let mut stack = [0u8; crate::structured::parsers::MAX_STRUCTURED_TRAVERSAL_DEPTH];
    let mut len = 0usize;
    for &byte in mask {
        match byte {
            b'(' | b'[' | b'{' => {
                if len == stack.len() {
                    return false;
                }
                stack[len] = byte;
                len += 1;
            }
            b')' | b']' | b'}' => {
                let expected = if byte == b')' {
                    b'('
                } else if byte == b']' {
                    b'['
                } else {
                    b'{'
                };
                if len == 0 || stack[len - 1] != expected {
                    return false;
                }
                len -= 1;
            }
            _ => {}
        }
    }
    len == 0
}

fn rust_test_scopes(mask: &[u8]) -> Vec<SourceSpan> {
    let mut scopes = Vec::new();
    for marker in [b"#[test]".as_slice(), b"#[cfg(test)]".as_slice()] {
        let mut search = 0;
        while let Some(relative) = memchr::memmem::find(&mask[search..], marker) {
            let start = search + relative;
            if let Some(open) = mask[start + marker.len()..]
                .iter()
                .position(|byte| *byte == b'{')
                .map(|relative| start + marker.len() + relative)
            {
                if let Some(close) = matching_brace(mask, open) {
                    scopes.push(SourceSpan::new(start, close + 1));
                }
            }
            search = start + marker.len();
        }
    }
    scopes
}

fn javascript_test_scopes(mask: &[u8]) -> Vec<SourceSpan> {
    let mut scopes = Vec::new();
    for marker in [b"describe".as_slice(), b"test".as_slice(), b"it".as_slice()] {
        let mut search = 0;
        while let Some(relative) = memchr::memmem::find(&mask[search..], marker) {
            let start = search + relative;
            let before_ok = start == 0 || !is_identifier_continue(mask[start - 1]);
            let after = start + marker.len();
            let after_ok = mask
                .get(after)
                .is_none_or(|byte| !is_identifier_continue(*byte));
            if before_ok && after_ok {
                let limit = after.saturating_add(512).min(mask.len());
                if let Some(open) = mask[after..limit]
                    .iter()
                    .position(|byte| *byte == b'{')
                    .map(|relative| after + relative)
                {
                    if let Some(close) = matching_brace(mask, open) {
                        scopes.push(SourceSpan::new(start, close + 1));
                    }
                }
            }
            search = after;
        }
    }
    scopes
}

fn python_test_scopes(text: &str) -> Vec<SourceSpan> {
    let mut scopes = Vec::new();
    let mut lines = Vec::new();
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let end = start + line.len();
        lines.push((start, end, line));
        start = end;
    }
    if start < text.len() || lines.is_empty() {
        lines.push((start, text.len(), &text[start..]));
    }
    for (index, (line_start, _, line)) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("def test_") || trimmed.starts_with("class Test")) {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let mut end = text.len();
        for (next_start, _, next_line) in lines.iter().skip(index + 1) {
            let next_trimmed = next_line.trim_start();
            if next_trimmed.trim().is_empty() || next_trimmed.starts_with('#') {
                continue;
            }
            let next_indent = next_line.len() - next_trimmed.len();
            if next_indent <= indent {
                end = *next_start;
                break;
            }
        }
        scopes.push(SourceSpan::new(*line_start, end));
    }
    scopes
}

fn matching_brace(mask: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, &byte) in mask[open..].iter().enumerate() {
        if byte == b'{' {
            depth = depth.checked_add(1)?;
        } else if byte == b'}' {
            depth = depth.checked_sub(1)?;
            if depth == 0 {
                return Some(open + offset);
            }
        }
    }
    None
}
