//! C11 preprocessor passes.

use crate::parsing::c::lex::tokens::{
    TOK_PP_DEFINE, TOK_PP_ELIF, TOK_PP_ELSE, TOK_PP_ENDIF, TOK_PP_ERROR, TOK_PP_IDENT, TOK_PP_IF,
    TOK_PP_IFDEF, TOK_PP_IFNDEF, TOK_PP_INCLUDE, TOK_PP_INCLUDE_NEXT, TOK_PP_LINE, TOK_PP_NULL,
    TOK_PP_PRAGMA, TOK_PP_SCCS, TOK_PP_UNDEF, TOK_PP_WARNING, TOK_PREPROC,
};

/// Preprocessor side-effect metadata.
pub mod effects;
/// Macro-expansion kernel.
pub mod expansion;
/// Macro-expansion source-byte materialization helpers.
pub mod materialization;
/// Include source-manager ABI.
pub mod source;
/// Token synthesis helpers for macro stringification and token paste.
pub mod synthesis;

/// Source bytes after C translation phase 2 line splicing.
///
/// `bytes` contains the source with every backslash-newline pair deleted.
/// `original_offsets` maps each output byte boundary back to the input byte
/// boundary at the same logical position. Its length is always
/// `bytes.len() + 1`, with the final entry pointing at `source.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CLineSplicedSource {
    /// Phase-2 source bytes with line-splice pairs removed.
    pub bytes: Vec<u8>,
    /// Output byte-boundary to original byte-boundary map.
    pub original_offsets: Vec<usize>,
}

impl CLineSplicedSource {
    /// Map a logical byte boundary in `bytes` back to an original source offset.
    #[must_use]
    pub fn original_offset(&self, logical_offset: usize) -> usize {
        self.original_offsets
            .get(logical_offset)
            .copied()
            .or_else(|| self.original_offsets.last().copied())
            .unwrap_or(0)
    }
}

/// Delete C translation phase 2 backslash-newline pairs.
///
/// This is intentionally global and independent of directive parsing: every C
/// tokenization path must see the same phase-2 byte stream before directives,
/// macro names, and ordinary tokens are interpreted.
#[must_use]
pub fn c_translation_phase_line_splice(source: &[u8]) -> CLineSplicedSource {
    let mut bytes = Vec::with_capacity(source.len());
    let mut original_offsets = Vec::with_capacity(source.len() + 1);
    let mut index = 0usize;

    while index < source.len() {
        if source[index] == b'\\' {
            match source.get(index + 1).copied() {
                Some(b'\n') => {
                    index += 2;
                    continue;
                }
                Some(b'\r') => {
                    index += 2;
                    if source.get(index).copied() == Some(b'\n') {
                        index += 1;
                    }
                    continue;
                }
                _ => {}
            }
        }

        original_offsets.push(index);
        bytes.push(source[index]);
        index += 1;
    }

    original_offsets.push(source.len());
    CLineSplicedSource {
        bytes,
        original_offsets,
    }
}

/// Stable directive kind identifiers carried by host-side preprocessor analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CPreprocessorDirectiveKind {
    /// Empty `#` directive.
    Null,
    /// `#define`.
    Define,
    /// `#undef`.
    Undef,
    /// `#include`.
    Include,
    /// GNU `#include_next`.
    IncludeNext,
    /// `#if`.
    If,
    /// `#ifdef`.
    Ifdef,
    /// `#ifndef`.
    Ifndef,
    /// `#elif`.
    Elif,
    /// `#else`.
    Else,
    /// `#endif`.
    Endif,
    /// `#pragma`.
    Pragma,
    /// `#line`.
    Line,
    /// `#error`.
    Error,
    /// GNU `#warning`.
    Warning,
    /// System `#ident`.
    Ident,
    /// System `#sccs`.
    Sccs,
}

impl CPreprocessorDirectiveKind {
    /// Return the stable directive metadata token ID.
    #[must_use]
    pub const fn token_id(self) -> u32 {
        match self {
            Self::Null => TOK_PP_NULL,
            Self::Define => TOK_PP_DEFINE,
            Self::Undef => TOK_PP_UNDEF,
            Self::Include => TOK_PP_INCLUDE,
            Self::IncludeNext => TOK_PP_INCLUDE_NEXT,
            Self::If => TOK_PP_IF,
            Self::Ifdef => TOK_PP_IFDEF,
            Self::Ifndef => TOK_PP_IFNDEF,
            Self::Elif => TOK_PP_ELIF,
            Self::Else => TOK_PP_ELSE,
            Self::Endif => TOK_PP_ENDIF,
            Self::Pragma => TOK_PP_PRAGMA,
            Self::Line => TOK_PP_LINE,
            Self::Error => TOK_PP_ERROR,
            Self::Warning => TOK_PP_WARNING,
            Self::Ident => TOK_PP_IDENT,
            Self::Sccs => TOK_PP_SCCS,
        }
    }
}

/// Parsed metadata for one compact `TOK_PREPROC` source row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CPreprocessorDirective {
    /// Recognized directive kind.
    pub kind: CPreprocessorDirectiveKind,
    /// Byte offset of the directive keyword within the phase-2 logical row.
    pub keyword_start: usize,
    /// Byte length of the directive keyword. Null directives use zero.
    pub keyword_len: usize,
    /// Byte offset where directive payload starts after horizontal whitespace.
    pub payload_start: usize,
    /// Byte offset where the phase-2 logical directive row ends.
    pub logical_end: usize,
}

/// Fail-loud preprocessor row classification error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CPreprocessorError {
    /// Byte offset where classification failed.
    pub offset: usize,
    /// Actionable diagnostic.
    pub message: &'static str,
}

impl core::fmt::Display for CPreprocessorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for CPreprocessorError {}

/// Return the physical byte length of one logical preprocessing directive row.
///
/// C translation phase 2 deletes backslash-newline pairs before directive
/// parsing. The returned span therefore continues across `\\\n` and `\\\r\n`
/// pairs and stops before the first non-spliced line terminator.
#[must_use]
pub fn c_logical_directive_len(source: &[u8], offset: usize) -> usize {
    if offset >= source.len() {
        return 0;
    }

    let mut index = offset;
    while index < source.len() {
        match source[index] {
            b'\n' => {
                if index > offset && source[index - 1] == b'\\' {
                    index += 1;
                    continue;
                }
                break;
            }
            b'\r' => {
                let has_lf = source.get(index + 1).copied() == Some(b'\n');
                if index > offset && source[index - 1] == b'\\' {
                    index += usize::from(has_lf) + 1;
                    continue;
                }
                break;
            }
            _ => index += 1,
        }
    }

    index - offset
}

/// Classify a compact preprocessor row without expanding macros.
///
/// This function validates the directive name, treats horizontal whitespace
/// after `#` the same way C does, and leaves payload bytes untouched so macro
/// definitions, includes, pragmas, and `#error` diagnostics share one phase-2
/// view with downstream directive and macro handling.
///
/// # Errors
///
/// Returns a diagnostic when the row is not a directive row or uses an
/// unsupported directive spelling.
pub fn try_classify_preprocessor_directive(
    row: &[u8],
) -> Result<CPreprocessorDirective, CPreprocessorError> {
    let logical_end = c_logical_directive_len(row, 0);
    let physical_line = row.get(..logical_end).unwrap_or(row);
    let spliced = c_translation_phase_line_splice(physical_line);
    classify_phase2_preprocessor_directive(&spliced.bytes).map_err(|mut err| {
        err.offset = spliced.original_offset(err.offset);
        err
    })
}

fn classify_phase2_preprocessor_directive(
    line: &[u8],
) -> Result<CPreprocessorDirective, CPreprocessorError> {
    let mut index = skip_horizontal_ws(line, 0);
    if line.get(index).copied() != Some(b'#') {
        return Err(CPreprocessorError {
            offset: index,
            message: "Fix: preprocessor row must begin with # after horizontal whitespace",
        });
    }

    index += 1;
    index = skip_horizontal_ws(line, index);
    if index >= line.len() {
        return Ok(CPreprocessorDirective {
            kind: CPreprocessorDirectiveKind::Null,
            keyword_start: index,
            keyword_len: 0,
            payload_start: index,
            logical_end: line.len(),
        });
    }

    let keyword_start = index;
    while index < line.len() && is_directive_ident_continue(line[index]) {
        index += 1;
    }
    let keyword = &line[keyword_start..index];
    let kind = match keyword {
        b"define" => CPreprocessorDirectiveKind::Define,
        b"undef" => CPreprocessorDirectiveKind::Undef,
        b"include" => CPreprocessorDirectiveKind::Include,
        b"include_next" => CPreprocessorDirectiveKind::IncludeNext,
        b"if" => CPreprocessorDirectiveKind::If,
        b"ifdef" => CPreprocessorDirectiveKind::Ifdef,
        b"ifndef" => CPreprocessorDirectiveKind::Ifndef,
        b"elif" => CPreprocessorDirectiveKind::Elif,
        b"else" => CPreprocessorDirectiveKind::Else,
        b"endif" => CPreprocessorDirectiveKind::Endif,
        b"pragma" => CPreprocessorDirectiveKind::Pragma,
        b"line" => CPreprocessorDirectiveKind::Line,
        b"error" => CPreprocessorDirectiveKind::Error,
        b"warning" => CPreprocessorDirectiveKind::Warning,
        b"ident" => CPreprocessorDirectiveKind::Ident,
        b"sccs" => CPreprocessorDirectiveKind::Sccs,
        _ => {
            return Err(CPreprocessorError {
                offset: keyword_start,
                message: "Fix: implement or reject this C preprocessor directive explicitly",
            });
        }
    };

    Ok(CPreprocessorDirective {
        kind,
        keyword_start,
        keyword_len: keyword.len(),
        payload_start: skip_horizontal_ws(line, index),
        logical_end: line.len(),
    })
}

/// Build directive-kind and conditional-value metadata for compact C tokens.
///
/// `TOK_PREPROC` rows are classified from original source spans. Conditional
/// rows get an evaluated truth value; all other rows get `0`.
///
/// # Errors
///
/// Returns a diagnostic when token streams are inconsistent, a directive span
/// is outside `source`, or the current payload evaluator cannot parse a
/// conditional expression.
pub fn reference_c_preprocessor_directive_metadata(
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
    source: &[u8],
    defined_macros: &[&[u8]],
) -> Result<(Vec<u32>, Vec<u32>), CPreprocessorError> {
    if tok_types.len() != tok_starts.len() || tok_types.len() != tok_lens.len() {
        return Err(CPreprocessorError {
            offset: tok_types.len().min(tok_starts.len()).min(tok_lens.len()),
            message: "Fix: token type/start/length streams must have identical lengths",
        });
    }

    let mut directive_kinds = vec![0; tok_types.len()];
    let mut directive_values = vec![0; tok_types.len()];
    for (idx, ((tok_type, start), len)) in
        tok_types.iter().zip(tok_starts).zip(tok_lens).enumerate()
    {
        if *tok_type != TOK_PREPROC {
            continue;
        }
        let start = usize::try_from(*start).map_err(|_| CPreprocessorError {
            offset: idx,
            message: "Fix: token start does not fit host usize",
        })?;
        let len = usize::try_from(*len).map_err(|_| CPreprocessorError {
            offset: idx,
            message: "Fix: token length does not fit host usize",
        })?;
        let token_end = start.checked_add(len).ok_or(CPreprocessorError {
            offset: start,
            message: "Fix: token span overflows source address space",
        })?;
        let physical_logical_len = c_logical_directive_len(source, start);
        if physical_logical_len > len {
            return Err(CPreprocessorError {
                offset: start + len,
                message:
                    "Fix: TOK_PREPROC span must include the full phase-2 spliced directive row",
            });
        }
        let logical_end = start
            .checked_add(physical_logical_len)
            .ok_or(CPreprocessorError {
                offset: start,
                message: "Fix: directive logical span overflows source address space",
            })?;
        if token_end > source.len() {
            return Err(CPreprocessorError {
                offset: start,
                message: "Fix: preprocessor token span must be inside the source buffer",
            });
        }
        let row = source.get(start..logical_end).ok_or(CPreprocessorError {
            offset: start,
            message: "Fix: preprocessor token span must be inside the source buffer",
        })?;
        let spliced = c_translation_phase_line_splice(row);
        let directive =
            classify_phase2_preprocessor_directive(&spliced.bytes).map_err(|mut err| {
                err.offset = start + spliced.original_offset(err.offset);
                err
            })?;
        directive_kinds[idx] = directive.kind.token_id();
        directive_values[idx] =
            conditional_directive_value(&spliced.bytes, directive, defined_macros)
                .map_err(|mut err| {
                    err.offset = start + spliced.original_offset(err.offset);
                    err
                })?
                .unwrap_or(0);
    }
    Ok((directive_kinds, directive_values))
}

fn conditional_directive_value(
    row: &[u8],
    directive: CPreprocessorDirective,
    defined_macros: &[&[u8]],
) -> Result<Option<u32>, CPreprocessorError> {
    let payload = row
        .get(directive.payload_start..directive.logical_end)
        .unwrap_or_default();
    match directive.kind {
        CPreprocessorDirectiveKind::If | CPreprocessorDirectiveKind::Elif => Ok(Some(u32::from(
            PreprocessorExprParser {
                bytes: payload,
                index: 0,
                base_offset: directive.payload_start,
                defined_macros,
            }
            .parse()?,
        ))),
        CPreprocessorDirectiveKind::Ifdef => Ok(Some(u32::from(
            first_payload_ident(payload).is_some_and(|name| macro_is_defined(defined_macros, name)),
        ))),
        CPreprocessorDirectiveKind::Ifndef => Ok(Some(u32::from(
            first_payload_ident(payload)
                .is_some_and(|name| !macro_is_defined(defined_macros, name)),
        ))),
        _ => Ok(None),
    }
}

struct PreprocessorExprParser<'src, 'defs, 'name> {
    bytes: &'src [u8],
    index: usize,
    base_offset: usize,
    defined_macros: &'defs [&'name [u8]],
}

impl PreprocessorExprParser<'_, '_, '_> {
    fn parse(&mut self) -> Result<bool, CPreprocessorError> {
        let value = self.parse_conditional()?;
        self.skip_ws_and_splices();
        if self.index != self.bytes.len() {
            return Err(self.error("Fix: unsupported tokens remain in #if expression"));
        }
        Ok(value != 0)
    }

    fn parse_conditional(&mut self) -> Result<u64, CPreprocessorError> {
        let condition = self.parse_logical_or()?;
        self.skip_ws_and_splices();
        if !self.consume_byte(b'?') {
            return Ok(condition);
        }

        let then_value = self.parse_conditional()?;
        self.skip_ws_and_splices();
        if !self.consume_byte(b':') {
            return Err(self.error("Fix: close #if conditional operator with ':'"));
        }
        let else_value = self.parse_conditional()?;
        Ok(if condition != 0 {
            then_value
        } else {
            else_value
        })
    }

    fn parse_logical_or(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_logical_and()?;
        loop {
            self.skip_ws_and_splices();
            if !self.consume_pair(b'|', b'|') {
                return Ok(value);
            }
            let rhs = self.parse_logical_and()?;
            value = u64::from(value != 0 || rhs != 0);
        }
    }

    fn parse_logical_and(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_bitwise_or()?;
        loop {
            self.skip_ws_and_splices();
            if !self.consume_pair(b'&', b'&') {
                return Ok(value);
            }
            let rhs = self.parse_bitwise_or()?;
            value = u64::from(value != 0 && rhs != 0);
        }
    }

    fn parse_bitwise_or(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_bitwise_xor()?;
        loop {
            self.skip_ws_and_splices();
            if self.consume_pair(b'|', b'|') {
                self.index = self.index.saturating_sub(2);
                return Ok(value);
            }
            if !self.consume_byte(b'|') {
                return Ok(value);
            }
            value |= self.parse_bitwise_xor()?;
        }
    }

    fn parse_bitwise_xor(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_bitwise_and()?;
        loop {
            self.skip_ws_and_splices();
            if !self.consume_byte(b'^') {
                return Ok(value);
            }
            value ^= self.parse_bitwise_and()?;
        }
    }

    fn parse_bitwise_and(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_equality()?;
        loop {
            self.skip_ws_and_splices();
            if self.consume_pair(b'&', b'&') {
                self.index = self.index.saturating_sub(2);
                return Ok(value);
            }
            if !self.consume_byte(b'&') {
                return Ok(value);
            }
            value &= self.parse_equality()?;
        }
    }

    fn parse_equality(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_relational()?;
        loop {
            self.skip_ws_and_splices();
            if self.consume_pair(b'=', b'=') {
                value = u64::from(value == self.parse_relational()?);
            } else if self.consume_pair(b'!', b'=') {
                value = u64::from(value != self.parse_relational()?);
            } else {
                return Ok(value);
            }
        }
    }

    fn parse_relational(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_shift()?;
        loop {
            self.skip_ws_and_splices();
            if self.consume_pair(b'<', b'=') {
                value = u64::from(value <= self.parse_shift()?);
            } else if self.consume_pair(b'>', b'=') {
                value = u64::from(value >= self.parse_shift()?);
            } else if self.consume_byte(b'<') {
                value = u64::from(value < self.parse_shift()?);
            } else if self.consume_byte(b'>') {
                value = u64::from(value > self.parse_shift()?);
            } else {
                return Ok(value);
            }
        }
    }

    fn parse_shift(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_additive()?;
        loop {
            self.skip_ws_and_splices();
            if self.consume_pair(b'<', b'<') {
                let rhs = self.parse_additive()?;
                value = value.checked_shl(rhs.min(127) as u32).unwrap_or(0);
            } else if self.consume_pair(b'>', b'>') {
                let rhs = self.parse_additive()?;
                value = value.checked_shr(rhs.min(127) as u32).unwrap_or(0);
            } else {
                return Ok(value);
            }
        }
    }

    fn parse_additive(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_multiplicative()?;
        loop {
            self.skip_ws_and_splices();
            if self.consume_byte(b'+') {
                value = value.wrapping_add(self.parse_multiplicative()?);
            } else if self.consume_byte(b'-') {
                value = value.wrapping_sub(self.parse_multiplicative()?);
            } else {
                return Ok(value);
            }
        }
    }

    fn parse_multiplicative(&mut self) -> Result<u64, CPreprocessorError> {
        let mut value = self.parse_unary()?;
        loop {
            self.skip_ws_and_splices();
            if self.consume_byte(b'*') {
                value = value.wrapping_mul(self.parse_unary()?);
            } else if self.consume_byte(b'/') {
                let rhs = self.parse_unary()?;
                if rhs == 0 {
                    return Err(self.error("Fix: #if expression divides by zero"));
                }
                value /= rhs;
            } else if self.consume_byte(b'%') {
                let rhs = self.parse_unary()?;
                if rhs == 0 {
                    return Err(self.error("Fix: #if expression takes modulo by zero"));
                }
                value %= rhs;
            } else {
                return Ok(value);
            }
        }
    }

    fn parse_unary(&mut self) -> Result<u64, CPreprocessorError> {
        self.skip_ws_and_splices();
        if self.consume_byte(b'!') {
            return Ok(u64::from(self.parse_unary()? == 0));
        }
        if self.consume_byte(b'~') {
            return Ok(!self.parse_unary()?);
        }
        if self.consume_byte(b'+') {
            return self.parse_unary();
        }
        if self.consume_byte(b'-') {
            return Ok(self.parse_unary()?.wrapping_neg());
        }
        if self.consume_byte(b'(') {
            let value = self.parse_conditional()?;
            self.skip_ws_and_splices();
            if !self.consume_byte(b')') {
                return Err(self.error("Fix: close parenthesized #if expression with ')'"));
            }
            return Ok(value);
        }
        if self.consume_ident(b"defined") {
            return self.parse_defined_operator();
        }
        if let Some(value) = self.consume_char_constant()? {
            return Ok(value);
        }
        if let Some(value) = self.consume_integer() {
            return Ok(value);
        }
        if let Some((start, end)) = self.consume_identifier_span() {
            return Ok(u64::from(macro_is_defined(
                self.defined_macros,
                &self.bytes[start..end],
            )));
        }
        Err(self.error("Fix: expected #if operand, integer literal, identifier, or defined()"))
    }

    fn parse_defined_operator(&mut self) -> Result<u64, CPreprocessorError> {
        self.skip_ws_and_splices();
        let parenthesized = self.consume_byte(b'(');
        self.skip_ws_and_splices();
        let Some((start, end)) = self.consume_identifier_span() else {
            return Err(self.error("Fix: defined operator requires a macro identifier"));
        };
        self.skip_ws_and_splices();
        if parenthesized && !self.consume_byte(b')') {
            return Err(self.error("Fix: close defined(identifier) with ')'"));
        }
        Ok(u64::from(macro_is_defined(
            self.defined_macros,
            &self.bytes[start..end],
        )))
    }

    fn consume_integer(&mut self) -> Option<u64> {
        self.skip_ws_and_splices();
        let start = self.index;
        let radix = if self.bytes.get(self.index..self.index + 2) == Some(b"0x")
            || self.bytes.get(self.index..self.index + 2) == Some(b"0X")
        {
            self.index += 2;
            16
        } else if self.bytes.get(self.index..self.index + 2) == Some(b"0b")
            || self.bytes.get(self.index..self.index + 2) == Some(b"0B")
        {
            self.index += 2;
            2
        } else if self.bytes.get(self.index).copied() == Some(b'0') {
            8
        } else {
            10
        };
        let digits_start = self.index;
        let mut value = 0u64;
        while let Some(byte) = self.bytes.get(self.index).copied() {
            let digit = match byte {
                b'0'..=b'9' => u64::from(byte - b'0'),
                b'a'..=b'f' if radix == 16 => u64::from(byte - b'a' + 10),
                b'A'..=b'F' if radix == 16 => u64::from(byte - b'A' + 10),
                _ => break,
            };
            if digit >= radix {
                break;
            }
            value = value.saturating_mul(radix).saturating_add(digit);
            self.index += 1;
        }
        if self.index == digits_start {
            self.index = start;
            return None;
        }
        while matches!(self.bytes.get(self.index), Some(b'u' | b'U' | b'l' | b'L')) {
            self.index += 1;
        }
        Some(value)
    }

    fn consume_char_constant(&mut self) -> Result<Option<u64>, CPreprocessorError> {
        self.skip_ws_and_splices();
        let prefix_start = self.index;
        if self.bytes.get(self.index..self.index + 2) == Some(b"u8") {
            self.index += 2;
        } else if matches!(self.bytes.get(self.index), Some(b'L' | b'u' | b'U')) {
            self.index += 1;
        }
        if !self.consume_byte(b'\'') {
            self.index = prefix_start;
            return Ok(None);
        }

        let mut value = 0u64;
        let mut saw_character = false;
        loop {
            let Some(byte) = self.bytes.get(self.index).copied() else {
                return Err(self.error("Fix: terminate #if character constant"));
            };
            if byte == b'\'' {
                break;
            }
            if matches!(byte, b'\n' | b'\r') {
                return Err(self.error("Fix: close #if character constant before newline"));
            }
            let next_value = if self.consume_byte(b'\\') {
                self.consume_escape_value()?
            } else {
                self.index += 1;
                u64::from(byte)
            };
            value = value.wrapping_shl(8) | (next_value & 0xff);
            saw_character = true;
        }

        if !saw_character {
            return Err(
                self.error("Fix: #if character constant must contain at least one character")
            );
        }

        if !self.consume_byte(b'\'') {
            return Err(self.error("Fix: close #if character constant with single quote"));
        }
        Ok(Some(value))
    }

    fn consume_escape_value(&mut self) -> Result<u64, CPreprocessorError> {
        let Some(byte) = self.bytes.get(self.index).copied() else {
            return Err(self.error("Fix: complete #if character escape"));
        };
        self.index += 1;
        let value = match byte {
            b'\'' => b'\'',
            b'"' => b'"',
            b'?' => b'?',
            b'\\' => b'\\',
            b'a' => 7,
            b'b' => 8,
            b'f' => 12,
            b'n' => b'\n',
            b'r' => b'\r',
            b't' => b'\t',
            b'v' => 11,
            b'0'..=b'7' => {
                let mut value = u64::from(byte - b'0');
                let mut digits = 1u8;
                while digits < 3 {
                    let Some(next @ b'0'..=b'7') = self.bytes.get(self.index).copied() else {
                        break;
                    };
                    value = value * 8 + u64::from(next - b'0');
                    self.index += 1;
                    digits += 1;
                }
                return Ok(value);
            }
            b'x' => return self.consume_hex_escape(),
            b'u' => return self.consume_fixed_hex_escape(4),
            b'U' => return self.consume_fixed_hex_escape(8),
            other => other,
        };
        Ok(u64::from(value))
    }

    fn consume_fixed_hex_escape(&mut self, digits: usize) -> Result<u64, CPreprocessorError> {
        let mut value = 0u64;
        for _ in 0..digits {
            let Some(byte) = self.bytes.get(self.index).copied() else {
                return Err(self.error("Fix: universal character escape is truncated"));
            };
            let digit = match byte {
                b'0'..=b'9' => u64::from(byte - b'0'),
                b'a'..=b'f' => u64::from(byte - b'a' + 10),
                b'A'..=b'F' => u64::from(byte - b'A' + 10),
                _ => return Err(self.error("Fix: universal character escape needs hex digits")),
            };
            value = value.saturating_mul(16).saturating_add(digit);
            self.index += 1;
        }
        Ok(value)
    }

    fn consume_hex_escape(&mut self) -> Result<u64, CPreprocessorError> {
        let start = self.index;
        let mut value = 0u64;
        while let Some(byte) = self.bytes.get(self.index).copied() {
            let digit = match byte {
                b'0'..=b'9' => u64::from(byte - b'0'),
                b'a'..=b'f' => u64::from(byte - b'a' + 10),
                b'A'..=b'F' => u64::from(byte - b'A' + 10),
                _ => break,
            };
            value = value.saturating_mul(16).saturating_add(digit);
            self.index += 1;
        }
        if self.index == start {
            return Err(self.error("Fix: hex character escape needs at least one digit"));
        }
        Ok(value)
    }

    fn consume_identifier_span(&mut self) -> Option<(usize, usize)> {
        self.skip_ws_and_splices();
        let start = self.index;
        let first = self.bytes.get(self.index).copied()?;
        if !is_c_ident_start(first) {
            return None;
        }
        self.index += 1;
        while self
            .bytes
            .get(self.index)
            .copied()
            .is_some_and(is_directive_ident_continue)
        {
            self.index += 1;
        }
        Some((start, self.index))
    }

    fn consume_ident(&mut self, ident: &[u8]) -> bool {
        self.skip_ws_and_splices();
        let end = self.index.saturating_add(ident.len());
        if self.bytes.get(self.index..end) != Some(ident) {
            return false;
        }
        if self
            .bytes
            .get(end)
            .copied()
            .is_some_and(is_directive_ident_continue)
        {
            return false;
        }
        self.index = end;
        true
    }

    fn consume_pair(&mut self, first: u8, second: u8) -> bool {
        if self.bytes.get(self.index..self.index + 2) == Some(&[first, second]) {
            self.index += 2;
            true
        } else {
            false
        }
    }

    fn consume_byte(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.index).copied() == Some(byte) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn skip_ws_and_splices(&mut self) {
        loop {
            match self.bytes.get(self.index).copied() {
                Some(b' ' | b'\t' | b'\x0b' | b'\x0c' | b'\n' | b'\r') => self.index += 1,
                Some(b'\\') if self.bytes.get(self.index + 1).copied() == Some(b'\n') => {
                    self.index += 2;
                }
                Some(b'\\') if self.bytes.get(self.index + 1).copied() == Some(b'\r') => {
                    self.index += 2;
                    if self.bytes.get(self.index).copied() == Some(b'\n') {
                        self.index += 1;
                    }
                }
                Some(b'/') if self.bytes.get(self.index + 1).copied() == Some(b'/') => {
                    self.index += 2;
                    while !matches!(self.bytes.get(self.index), None | Some(b'\n' | b'\r')) {
                        self.index += 1;
                    }
                }
                Some(b'/') if self.bytes.get(self.index + 1).copied() == Some(b'*') => {
                    self.index += 2;
                    while self.index + 1 < self.bytes.len()
                        && self.bytes.get(self.index..self.index + 2) != Some(b"*/")
                    {
                        self.index += 1;
                    }
                    if self.index + 1 < self.bytes.len() {
                        self.index += 2;
                    }
                }
                _ => return,
            }
        }
    }

    fn error(&self, message: &'static str) -> CPreprocessorError {
        CPreprocessorError {
            offset: self.base_offset + self.index,
            message,
        }
    }
}

fn first_payload_ident(payload: &[u8]) -> Option<&[u8]> {
    let mut index = skip_horizontal_ws(payload, 0);
    let start = index;
    if !payload.get(index).copied().is_some_and(is_c_ident_start) {
        return None;
    }
    index += 1;
    while payload
        .get(index)
        .copied()
        .is_some_and(is_directive_ident_continue)
    {
        index += 1;
    }
    payload.get(start..index)
}

#[inline]
fn macro_is_defined(defined_macros: &[&[u8]], name: &[u8]) -> bool {
    defined_macros.iter().any(|candidate| *candidate == name)
}

#[inline]
fn skip_horizontal_ws(bytes: &[u8], mut index: usize) -> usize {
    loop {
        match bytes.get(index).copied() {
            Some(b' ' | b'\t' | b'\x0b' | b'\x0c') => index += 1,
            Some(b'/') if bytes.get(index + 1).copied() == Some(b'/') => {
                return bytes.len();
            }
            Some(b'/') if bytes.get(index + 1).copied() == Some(b'*') => {
                index += 2;
                while index + 1 < bytes.len() && bytes.get(index..index + 2) != Some(b"*/") {
                    index += 1;
                }
                if index + 1 >= bytes.len() {
                    return bytes.len();
                }
                index += 2;
            }
            _ => return index,
        }
    }
}

#[inline]
fn is_directive_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[inline]
fn is_c_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}
