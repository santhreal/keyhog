//! Packed binary wire format for grammar table blobs.
//!
//! `vyre-libs::parsing::{lexer,lr_table}` loads these blobs as ReadOnly
//! storage buffers on the GPU. Layout:
//!
//! ```text
//! bytes 0..4   : magic b"SGGC"
//! bytes 4..6   : version = 0 (LE u16)
//! bytes 6..8   : kind (LE u16, 0 = lexer DFA, 1 = LR)
//! bytes 8..12  : num_states (LE u32)
//! bytes 12..16 : num_classes (for lexer) or num_tokens (for LR)
//! bytes 16..20 : extra (nonterminal count for LR, token-id count for lexer)
//! bytes 20..24 : payload_len
//! bytes 24..   : payload (packed u32 transitions + aux arrays)
//! ```

use crate::dfa::DfaTable;
use crate::lr::{LrTable, Production};

/// Magic bytes at the head of every blob: `SGGC` = "Surgec Grammar-Gen C".
pub const MAGIC: [u8; 4] = *b"SGGC";
/// Wire format version.
pub const VERSION: u16 = 0;

/// Which kind of grammar table the blob carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum BlobKind {
    /// Lexer DFA.
    LexerDfa = 0,
    /// LR(1) action + goto tables.
    LrTables = 1,
}

/// Failure to decode an `SGGC` blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Buffer shorter than the 24-byte header.
    TooShort {
        /// Minimum bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },
    /// Magic bytes do not spell `SGGC`.
    BadMagic([u8; 4]),
    /// Wire [`VERSION`] mismatch.
    UnsupportedVersion(u16),
    /// Unknown [`BlobKind`] discriminant.
    UnsupportedKind(u16),
    /// Declared payload does not fit in `bytes`.
    PayloadTruncated {
        /// Total bytes implied by header + payload.
        expected: usize,
        /// Actual byte length.
        got: usize,
    },
    /// Lexer payload word count does not match header dimensions.
    LexerPayloadWordCount {
        /// `(num_states * num_classes) + token_id_words` expected.
        expected: usize,
        /// Words in payload.
        got: usize,
    },
    /// LR payload cannot be split into action, goto, and productions.
    LrPayloadSize,
}

/// A packed grammar blob.
#[derive(Debug, Clone)]
pub struct PackedBlob {
    /// Which kind of table this blob carries.
    pub kind: BlobKind,
    /// Raw bytes ready for upload.
    pub bytes: Vec<u8>,
}

impl PackedBlob {
    /// Pack a lexer DFA into a blob.
    #[must_use]
    pub fn from_dfa(dfa: &DfaTable) -> Self {
        let mut payload = Vec::new();
        for &word in &dfa.transitions {
            payload.extend_from_slice(&word.to_le_bytes());
        }
        for &word in &dfa.token_ids {
            payload.extend_from_slice(&word.to_le_bytes());
        }

        let bytes = write_header(
            BlobKind::LexerDfa,
            dfa.num_states,
            dfa.num_classes,
            u32::try_from(dfa.token_ids.len()).expect("token_ids count fits u32"),
            &payload,
        );

        Self {
            kind: BlobKind::LexerDfa,
            bytes,
        }
    }

    /// Pack an LR table into a blob.
    #[must_use]
    pub fn from_lr(lr: &LrTable) -> Self {
        let mut payload = Vec::new();
        for &word in &lr.action {
            payload.extend_from_slice(&word.to_le_bytes());
        }
        for &word in &lr.goto {
            payload.extend_from_slice(&word.to_le_bytes());
        }
        for prod in &lr.productions {
            payload.extend_from_slice(&prod.lhs.to_le_bytes());
            payload.extend_from_slice(&prod.rhs_len.to_le_bytes());
        }

        let bytes = write_header(
            BlobKind::LrTables,
            lr.num_states,
            lr.num_tokens,
            lr.num_nonterminals,
            &payload,
        );

        Self {
            kind: BlobKind::LrTables,
            bytes,
        }
    }

    /// Decode a lexer DFA from this blob’s bytes.
    pub fn try_as_dfa(&self) -> Result<DfaTable, WireError> {
        decode_dfa_from_bytes(&self.bytes)
    }

    /// Decode LR tables from this blob’s bytes.
    pub fn try_as_lr(&self) -> Result<LrTable, WireError> {
        decode_lr_from_bytes(&self.bytes)
    }
}

/// Decode a lexer DFA from raw `SGGC` bytes (host round-trip / tests).
pub fn decode_dfa_from_bytes(bytes: &[u8]) -> Result<DfaTable, WireError> {
    let header = parse_header(bytes)?;
    if header.kind != BlobKind::LexerDfa as u16 {
        return Err(WireError::UnsupportedKind(header.kind));
    }
    let num_states = header.num_states;
    let num_classes = header.num_classes;
    let token_words = header.extra as usize;
    let trans_words = (num_states as usize).saturating_mul(num_classes as usize);
    let expected_words = trans_words.saturating_add(token_words);
    let got_words = header.payload.len() / 4;
    if got_words != expected_words || header.payload.len() % 4 != 0 {
        return Err(WireError::LexerPayloadWordCount {
            expected: expected_words,
            got: got_words,
        });
    }
    let mut words = read_u32_words(header.payload);
    let transitions = words.drain(..trans_words).collect();
    let token_ids = words;
    Ok(DfaTable {
        num_states,
        num_classes,
        transitions,
        token_ids,
    })
}

/// Decode LR tables from raw `SGGC` bytes.
pub fn decode_lr_from_bytes(bytes: &[u8]) -> Result<LrTable, WireError> {
    let header = parse_header(bytes)?;
    if header.kind != BlobKind::LrTables as u16 {
        return Err(WireError::UnsupportedKind(header.kind));
    }
    let num_states = header.num_states;
    let num_tokens = header.num_classes;
    let num_nonterminals = header.extra;
    let action_words = (num_states as usize).saturating_mul(num_tokens as usize);
    let goto_words = (num_states as usize).saturating_mul(num_nonterminals as usize);
    let words: Vec<u32> = read_u32_words(header.payload);
    let min = action_words.saturating_add(goto_words);
    if words.len() < min || (words.len() - min) % 2 != 0 {
        return Err(WireError::LrPayloadSize);
    }
    let mut w = words.into_iter();
    let action: Vec<u32> = w.by_ref().take(action_words).collect();
    let goto: Vec<u32> = w.by_ref().take(goto_words).collect();
    let mut productions = Vec::new();
    while let (Some(lhs), Some(rhs_len)) = (w.next(), w.next()) {
        productions.push(Production { lhs, rhs_len });
    }
    Ok(LrTable {
        num_states,
        num_tokens,
        num_nonterminals,
        action,
        goto,
        productions,
    })
}

struct HeaderParts<'a> {
    kind: u16,
    num_states: u32,
    num_classes: u32,
    extra: u32,
    payload: &'a [u8],
}

fn parse_header(bytes: &[u8]) -> Result<HeaderParts<'_>, WireError> {
    if bytes.len() < 24 {
        return Err(WireError::TooShort {
            need: 24,
            got: bytes.len(),
        });
    }
    if bytes[0..4] != MAGIC {
        return Err(WireError::BadMagic(
            bytes[0..4].try_into().expect("4 bytes"),
        ));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let kind = u16::from_le_bytes([bytes[6], bytes[7]]);
    let num_states = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let num_classes = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let extra = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let payload_len = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
    let total = 24usize.saturating_add(payload_len);
    if bytes.len() < total {
        return Err(WireError::PayloadTruncated {
            expected: total,
            got: bytes.len(),
        });
    }
    Ok(HeaderParts {
        kind,
        num_states,
        num_classes,
        extra,
        payload: &bytes[24..total],
    })
}

fn read_u32_words(payload: &[u8]) -> Vec<u32> {
    payload
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn write_header(kind: BlobKind, states: u32, classes: u32, extra: u32, payload: &[u8]) -> Vec<u8> {
    let payload_len = u32::try_from(payload.len()).expect("payload fits u32");
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&(kind as u16).to_le_bytes());
    out.extend_from_slice(&states.to_le_bytes());
    out.extend_from_slice(&classes.to_le_bytes());
    out.extend_from_slice(&extra.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dfa::DfaBuilder;
    use crate::lr::smoke_grammar;

    #[test]
    fn lexer_blob_starts_with_magic_and_kind() {
        let dfa = DfaBuilder::new(4, 8).build();
        let blob = PackedBlob::from_dfa(&dfa);
        assert_eq!(&blob.bytes[0..4], &MAGIC);
        let version = u16::from_le_bytes([blob.bytes[4], blob.bytes[5]]);
        assert_eq!(version, VERSION);
        let kind = u16::from_le_bytes([blob.bytes[6], blob.bytes[7]]);
        assert_eq!(kind, BlobKind::LexerDfa as u16);
    }

    #[test]
    fn lr_blob_starts_with_magic_and_kind() {
        let lr = smoke_grammar();
        let blob = PackedBlob::from_lr(&lr);
        assert_eq!(&blob.bytes[0..4], &MAGIC);
        let kind = u16::from_le_bytes([blob.bytes[6], blob.bytes[7]]);
        assert_eq!(kind, BlobKind::LrTables as u16);
    }

    #[test]
    fn lexer_blob_payload_length_matches_header() {
        let dfa = DfaBuilder::new(4, 8).build();
        let blob = PackedBlob::from_dfa(&dfa);
        let payload_len = u32::from_le_bytes([
            blob.bytes[20],
            blob.bytes[21],
            blob.bytes[22],
            blob.bytes[23],
        ]) as usize;
        assert_eq!(blob.bytes.len(), 24 + payload_len);
    }

    #[test]
    fn lexer_dfa_roundtrips_through_wire() {
        let dfa = DfaBuilder::new(4, 8).build();
        let blob = PackedBlob::from_dfa(&dfa);
        let got = blob.try_as_dfa().expect("decode lexer blob");
        assert_eq!(got, dfa);
    }

    #[test]
    fn lr_table_roundtrips_through_wire() {
        let lr = smoke_grammar();
        let blob = PackedBlob::from_lr(&lr);
        let got = blob.try_as_lr().expect("decode LR blob");
        assert_eq!(got, lr);
    }
}
