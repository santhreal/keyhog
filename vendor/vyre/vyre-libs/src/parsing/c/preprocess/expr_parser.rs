//! C preprocessor `#if` / `#elif` expression parser, extracted from
//! `mod.rs` so the file stays under the 500-LOC source cap.

use super::{is_c_ident_start, is_directive_ident_continue, macro_is_defined, CPreprocessorError};

pub(super) struct PreprocessorExprParser<'src, 'defs, 'name> {
    pub(super) bytes: &'src [u8],
    pub(super) index: usize,
    pub(super) base_offset: usize,
    pub(super) defined_macros: &'defs [&'name [u8]],
}

impl PreprocessorExprParser<'_, '_, '_> {
    pub(super) fn parse(&mut self) -> Result<bool, CPreprocessorError> {
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
