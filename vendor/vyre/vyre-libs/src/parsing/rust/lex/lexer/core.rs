//! CPU reference lexer for the Rust nano-subset.

use crate::parsing::rust::lex::keyword::promote;
use crate::parsing::rust::lex::tokens::*;

/// A token with a source span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// Token kind id.
    pub kind: u16,
    /// Start byte offset in source.
    pub start: u32,
    /// Length in bytes.
    pub len: u16,
}

impl Token {
    /// Return the token's text as a `&str` from the source buffer.
    pub fn text<'a>(&self, source: &'a [u8]) -> &'a str {
        std::str::from_utf8(&source[self.start as usize..(self.start + self.len as u32) as usize])
            .expect("Fix: lexer must reject invalid UTF-8 spans; return Lex error instead of panicking - lexer only produces valid UTF-8 spans")
    }
}

/// Lex a byte slice into a vector of tokens.
pub fn lex(source: &[u8]) -> Result<Vec<Token>, usize> {
    let _ = std::str::from_utf8(source).map_err(|e| e.valid_up_to())?;

    let mut tokens = Vec::new();
    let mut i = 0usize;

    while i < source.len() {
        let b = source[i];

        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        if b == b'/' && i + 1 < source.len() && source[i + 1] == b'/' {
            while i < source.len() && source[i] != b'\n' {
                i += 1;
            }
            continue;
        }

        if b == b'/' && i + 1 < source.len() && source[i + 1] == b'*' {
            i += 2;
            while i + 1 < source.len() {
                if source[i] == b'*' && source[i + 1] == b'/' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }

        let start = i;

        if b == b'_' || b.is_ascii_alphabetic() {
            while i < source.len()
                && (source[i].is_ascii_alphanumeric() || source[i] == b'_')
            {
                i += 1;
            }
            let text = std::str::from_utf8(&source[start..i]).unwrap();
            let kind = promote(text).unwrap_or(IDENT);
            tokens.push(Token { kind, start: start as u32, len: (i - start) as u16 });
            continue;
        }

        if b.is_ascii_digit() {
            while i < source.len() && source[i].is_ascii_digit() {
                i += 1;
            }
            tokens.push(Token { kind: LITERAL_INT, start: start as u32, len: (i - start) as u16 });
            continue;
        }

        if i + 1 < source.len() {
            let pair = [b, source[i + 1]];
            let (kind, advance) = match &pair {
                b"==" => (EQ, 2),
                b"->" => (ARROW, 2),
                b"&m" if i + 4 <= source.len() && &source[i + 1..i + 4] == b"mut" => {
                    (AMP_MUT, 4)
                }
                _ => (0, 0),
            };
            if advance > 0 {
                i += advance;
                tokens.push(Token { kind, start: start as u32, len: advance as u16 });
                continue;
            }
        }

        let kind = match b {
            b'+' => PLUS,
            b'-' => MINUS,
            b'*' => STAR,
            b'/' => SLASH,
            b'=' => ASSIGN,
            b'<' => LT,
            b';' => SEMI,
            b':' => COLON,
            b',' => COMMA,
            b'&' => AMP,
            b'!' => BANG,
            b'(' => LPAREN,
            b')' => RPAREN,
            b'{' => LBRACE,
            b'}' => RBRACE,
            _ => return Err(start),
        };
        i += 1;
        tokens.push(Token { kind, start: start as u32, len: 1 });
    }

    tokens.push(Token { kind: EOF, start: source.len() as u32, len: 0 });
    Ok(tokens)
}
