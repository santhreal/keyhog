//! Core type definitions for the vyre IR.
//!
//! These public types are defined by `vyre-spec` so that backend
//! conformance can be proved without depending on `vyre`.
//!
//! # Examples
//!
//! ```
//! use vyre::ir::{DataType, BufferAccess, BinOp};
//!
//! // Element type for a U32 buffer
//! let elem = DataType::U32;
//!
//! // Read-write access for an output buffer
//! let access = BufferAccess::ReadWrite;
//!
//! // The arithmetic operator used inside an Expr::BinOp
//! let op = BinOp::Add;
//! ```
//!
//! # Wire Contract
//!
//! `DataType::Bool` values occupy exactly one byte (`u8`) in every stable
//! wire-facing payload. `0` means false and `1` means true; producers must
//! not pack multiple booleans into bitsets under the `Bool` type. Packed-bit
//! encodings belong in explicit integer buffers such as `Vec<u32>`.

/// Re-export of frozen IR types from `vyre-spec`.
///
/// These types are the vocabulary of every vyre program: data types,
/// buffer access modes, binary and unary operators, function calling
/// conventions, and operation signatures. Because they live in the spec
/// crate, frontends and backends can depend on them without pulling in
/// the full compiler.
pub use vyre_spec::{AtomicOp, BinOp, BufferAccess, Convention, DataType, OpSignature, UnOp};
