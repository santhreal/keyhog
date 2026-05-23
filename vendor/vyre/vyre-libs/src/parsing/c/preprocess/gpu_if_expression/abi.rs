/// Canonical op id.
pub const OP_ID: &str = "vyre-libs::parsing::c::preprocess::gpu_if_expression";

/// Canonical binding indices.
pub const BINDING_TOK_STARTS: u32 = 0;
/// Canonical binding for the input per-token byte-length buffer.
pub const BINDING_TOK_LENS: u32 = 1;
/// Canonical binding for the input directive-kinds buffer.
pub const BINDING_DIRECTIVE_KINDS: u32 = 2;
/// Canonical binding for the input source bytes.
pub const BINDING_SOURCE: u32 = 3;
/// Canonical binding for the input packed defined-macro names.
pub const BINDING_MACRO_NAMES_PACKED: u32 = 4;
/// Canonical binding for the input macro-offset table.
pub const BINDING_MACRO_OFFSETS: u32 = 5;
/// Canonical binding for object-like macro integer values.
pub const BINDING_MACRO_VALUES: u32 = 6;
/// Canonical binding for the output `directive_values` buffer.
pub const BINDING_DIRECTIVE_VALUES: u32 = 7;

/// Per-thread stack depth (value and operator stacks).
pub const STACK_DEPTH: u32 = 16;

/// Legacy payload scan cap kept as a stable ABI constant for callers
/// that size external fixtures. The evaluator now scans to the
/// directive row end instead of truncating at this value.
pub const MAX_PAYLOAD_BYTES: u32 = 512;

/// Legacy identifier scan cap kept as a stable ABI constant for callers
/// that size external fixtures. The evaluator now scans identifiers to
/// the directive row end instead of truncating at this value.
pub const MAX_IDENT_LEN: u32 = 64;
