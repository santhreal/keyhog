// Stable binary IR wire format for serialized IR programs.

use crate::ir::{BufferDecl, DataType, Expr, Node, Program};

/// The `decode` module.
pub mod decode;
/// The `encode` module.
pub mod encode;
/// The `framing` module.
pub mod framing;
/// The `tags` module.
pub mod tags;

/// Maximum buffers accepted from one IR wire-format program.
///
/// I10 requires bounded allocation before validating semantics. This limit
/// rejects hostile wire blobs before allocating the buffer table.
pub const MAX_BUFFERS: usize = 16_384;

/// Maximum statement nodes accepted from any single wire-format node list.
///
/// I10 requires node vectors to be bounded before allocation; nested lists are
/// each checked against this budget as they are decoded.
pub const MAX_NODES: usize = 1_000_000;

/// Maximum call arguments accepted from one wire-format call expression.
///
/// I10 requires expression argument vectors to be bounded before allocation.
pub const MAX_ARGS: usize = 4_096;

/// Maximum UTF-8 string length accepted from the IR wire format.
///
/// I10 bounds allocation for names and operation identifiers carried by
/// attacker-controlled wire bytes.
pub const MAX_STRING_LEN: usize = 1 << 20;

/// Maximum recursive decode depth for the IR wire format.
///
/// The limit is applied to the **shared** recursion counter in `Reader`
/// that `Reader::node` and `Reader::expr` both increment on entry and
/// decrement on exit. A hostile blob cannot evade the cap by alternating
/// statement and expression nesting — every nested decode call, whether it
/// descends into a `Node::If`/`Loop`/`Block` body or into a nested
/// [`Expr`] argument tree, counts against the same budget. Depth ≥
/// `MAX_DECODE_DEPTH` is rejected with a `Fix:`-prefixed error before any
/// stack frame is pushed, preventing stack-overflow DoS from a blob that
/// nests `Block(Block(... Block(...) ...))` a million times deep.
///
/// Covers audit L.1.35 (HIGH).
pub const MAX_DECODE_DEPTH: u32 = 256;

/// Hard ceiling on the size of a single wire-encoded Program in bytes.
///
/// The framing layer rejects larger blobs before any decode allocation so
/// attacker-controlled input cannot force unbounded memory growth.
pub const MAX_PROGRAM_BYTES: usize = 64 * 1024 * 1024;

pub(crate) struct Reader<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
    /// Current recursion depth on the decode call stack. Incremented by
    /// every `node()` and `expr()` call and compared against
    /// [`MAX_DECODE_DEPTH`] before any nested decode proceeds.
    pub depth: u32,
}

impl Program {
    /// Serialize this IR program into the stable `VIR0` IR wire format.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::WireFormatValidation`] when a count
    /// cannot be represented in the versioned wire format or when a public
    /// enum variant has no registered stable wire tag. The `message` field
    /// carries the actionable diagnostic prose including a `Fix:` hint.
    #[inline]
    #[must_use]
    pub fn to_wire(&self) -> Result<Vec<u8>, crate::error::Error> {
        encode::to_wire(self).map_err(wire_err)
    }

    /// Serialize this IR program into the stable `VIR0` IR wire format,
    /// appending to an existing buffer.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::WireFormatValidation`] when a count
    /// cannot be represented in the versioned wire format or when a public
    /// enum variant has no registered stable wire tag. The `message` field
    /// carries the actionable diagnostic prose including a `Fix:` hint.
    #[inline]
    pub fn to_wire_into(&self, dst: &mut Vec<u8>) -> Result<(), crate::error::Error> {
        encode::to_wire_into(self, dst).map_err(wire_err)
    }

    /// Serialize this IR program into bytes.
    ///
    /// This compatibility wrapper preserves the pre-`to_wire` API name.
    ///
    /// On an encoding error, an empty vector is returned after logging the
    /// failure. Use [`Program::to_wire`] when the caller needs to handle the
    /// error explicitly.
    #[must_use]
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.to_wire() {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Program::to_bytes: wire encoding failed; returning empty bytes. \
                     This indicates a malformed Program; callers requiring strict \
                     encoding must use Program::to_wire directly."
                );
                Vec::new()
            }
        }
    }

    /// Deserialize an IR program from the stable `VYRE` IR wire format.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::VersionMismatch`] when the
    /// payload advertises a schema version this runtime does not
    /// understand. Returns [`crate::error::Error::WireFormatValidation`]
    /// for any other decode failure — truncated bytes, unknown enum
    /// tag, integrity digest mismatch, or malformed structural
    /// section.
    #[inline]
    #[must_use]
    pub fn from_wire(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        if bytes.len() > MAX_PROGRAM_BYTES {
            return Err(wire_err(format!(
                "Fix: wire blob is {} bytes, exceeding the {}-byte IR framing cap. Reject this input or split the Program before serialization.",
                bytes.len(),
                MAX_PROGRAM_BYTES
            )));
        }
        // The version field is validated before the string-based
        // decoder so that an out-of-range version surfaces as the
        // typed `VersionMismatch` variant instead of being absorbed
        // into the generic `WireFormatValidation` bucket. Tooling
        // that hangs off the diagnostic code `E-WIRE-VERSION` relies
        // on this distinction.
        if bytes.len() >= framing::MAGIC.len() + 2
            && &bytes[..framing::MAGIC.len()] == framing::MAGIC
        {
            let version = u16::from_le_bytes([bytes[4], bytes[5]]);
            if version != framing::WIRE_FORMAT_VERSION {
                return Err(crate::error::Error::VersionMismatch {
                    expected: u32::from(framing::WIRE_FORMAT_VERSION),
                    found: u32::from(version),
                });
            }
        }
        decode::from_wire(bytes).map_err(wire_err)
    }

    /// Deserialize an IR program from bytes.
    ///
    /// This compatibility wrapper preserves the pre-`from_wire` API name.
    ///
    /// # Errors
    ///
    /// Returns the same actionable decode errors as [`Program::from_wire`].
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        Self::from_wire(bytes)
    }

    /// Stable content hash of this Program, used as a cache identity.
    ///
    /// Computed as BLAKE3 of the canonical wire-format encoding. Two
    /// programs with the same wire bytes produce the same hash; two
    /// programs that compile to different wire bytes produce different
    /// hashes. This is the lego-correct identity for any persistent-
    /// cache consumer that wants a deterministic key per Program
    /// without re-implementing the hash itself.
    ///
    /// On wire-encoding failure (extremely rare — only when the
    /// Program is structurally malformed) returns the all-zero hash.
    /// Consumers that need to discriminate that case should call
    /// [`Self::to_wire`] explicitly first.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        let bytes = self.to_bytes();
        if bytes.is_empty() {
            return [0u8; 32];
        }
        blake3::hash(&bytes).into()
    }
}

/// Wrap an internal wire-format error string in the typed [`crate::error::Error`]
/// so every public boundary of this module returns a structured variant
/// callers can match on.
fn wire_err(message: String) -> crate::error::Error {
    crate::error::Error::WireFormatValidation { message }
}

/// Append stable VIR0 wire bytes for a [`DataType`] (tag + any payload) into
/// `buf`. Used by disk-cache fingerprinting where `Debug` output would be
/// the wrong contract.
pub fn append_data_type_fingerprint(buf: &mut Vec<u8>, value: &DataType) -> Result<(), String> {
    tags::data_type_tag::put_data_type(buf, value)
}

/// Append stable VIR0 wire bytes for a `Node` statement list (count + each
/// node). Matches the statement encoding used in full program wire (`to_wire`)
/// (without the file envelope, metadata, or buffer table).
pub fn append_node_list_fingerprint(buf: &mut Vec<u8>, nodes: &[Node]) -> Result<(), String> {
    encode::put_nodes(buf, nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferAccess, BufferDecl, DataType, Node, Program};

    #[test]
    #[inline]
    pub(crate) fn to_bytes_returns_empty_on_wire_error() {
        let long_name = "x".repeat(MAX_STRING_LEN + 1);
        let program = Program::wrapped(
            vec![BufferDecl::storage(
                &long_name,
                0,
                BufferAccess::ReadOnly,
                DataType::U32,
            )],
            [1, 1, 1],
            vec![],
        );
        assert!(program.to_wire().is_err());
        assert!(program.to_bytes().is_empty());
    }

    /// EDGE-001 regression: `MAX_DECODE_DEPTH` covers **both** Node and Expr
    /// recursion through the same counter. A blob that nests statement
    /// bodies past the depth limit must be rejected at decode time,
    /// preventing stack-overflow DoS on untrusted input.
    ///
    /// The test runs on a dedicated thread with an 8 MiB stack because
    /// the encode/decode walk down a `MAX_DECODE_DEPTH + 1`-deep Block
    /// tree uses ~3–4× the native frames the default 2 MiB test stack
    /// allocates. Without the explicit stack, the test itself
    /// stack-overflows before the decode guard ever fires — masking
    /// the real assertion.
    #[test]
    pub(crate) fn decode_depth_cap_rejects_deeply_nested_blocks() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(run_decode_depth_cap)
            .expect("Fix: spawn test worker")
            .join()
            .expect("Fix: decode-depth-cap worker panicked");
    }

    fn run_decode_depth_cap() {
        // Build the nested program iteratively so the test thread's
        // stack only owns the tree, not a recursion chain the depth
        // of the tree.
        let mut inner = Node::Block(vec![]);
        for _ in 0..MAX_DECODE_DEPTH {
            inner = Node::Block(vec![inner]);
        }
        let program = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![inner],
        );
        let bytes = program
            .to_wire()
            .expect("Fix: building a (MAX_DEPTH+1)-nested program must still encode");
        let decoded = Program::from_wire(&bytes);
        assert!(
            decoded.is_err(),
            "decoding a program deeper than MAX_DECODE_DEPTH must fail; got Ok"
        );
        let err = decoded.unwrap_err().to_string();
        assert!(
            err.contains("Fix:"),
            "depth-exceed error must carry a `Fix:` hint, got: {err}"
        );
    }
}
