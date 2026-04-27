use crate::parsing::c::parse::vast_kinds::{
    C_AST_KIND_BUILTIN_CHOOSE_EXPR, C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR,
    C_AST_KIND_BUILTIN_CONSTANT_P_EXPR, C_AST_KIND_BUILTIN_EXPECT_EXPR,
    C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR, C_AST_KIND_BUILTIN_OFFSETOF_EXPR,
    C_AST_KIND_BUILTIN_OVERFLOW_EXPR, C_AST_KIND_BUILTIN_PREFETCH_EXPR,
    C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR, C_AST_KIND_BUILTIN_UNREACHABLE_STMT,
};
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Compatibility opcode for front-end streams that tag `__builtin_expect`.
pub const GNU_BUILTIN_EXPECT_OPCODE: u32 = 0x4558_5043;
/// Compatibility opcode for front-end streams that tag `__builtin_offsetof`.
pub const GNU_BUILTIN_OFFSETOF_OPCODE: u32 = 0x4F46_5354;
/// Compatibility opcode for front-end streams that tag `__builtin_object_size`.
pub const GNU_BUILTIN_OBJECT_SIZE_OPCODE: u32 = 0x4F42_4A53;
/// Compatibility opcode for front-end streams that tag `__builtin_prefetch`.
pub const GNU_BUILTIN_PREFETCH_OPCODE: u32 = 0x5052_4546;
/// Compatibility opcode for front-end streams that tag `__builtin_unreachable`.
pub const GNU_BUILTIN_UNREACHABLE_OPCODE: u32 = 0x554E_5243;
/// Reserved opcode prefix for unsupported GNU builtin front-end tags.
pub const GNU_BUILTIN_RESERVED_PREFIX: u32 = 0x474E_5500;

/// Fail-loud GNU builtin classifier error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuBuiltinError {
    /// Identifier byte length at the failure site.
    pub len: usize,
    /// Actionable diagnostic.
    pub message: &'static str,
}

impl core::fmt::Display for GnuBuiltinError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} for {} bytes", self.message, self.len)
    }
}

impl std::error::Error for GnuBuiltinError {}

/// Classify GNU builtin identifier bytes into parser-local VAST kinds.
///
/// Ordinary identifiers return `Ok(None)`. Unknown `__builtin_*` names return
/// an error because silently treating compiler intrinsics as ordinary calls
/// loses semantics needed by the C frontend.
///
/// # Errors
///
/// Returns an actionable error for unsupported GNU builtin names.
pub fn try_classify_gnu_builtin_name(name: &[u8]) -> Result<Option<u32>, GnuBuiltinError> {
    let kind = match name {
        b"__builtin_constant_p" => C_AST_KIND_BUILTIN_CONSTANT_P_EXPR,
        b"__builtin_choose_expr" => C_AST_KIND_BUILTIN_CHOOSE_EXPR,
        b"__builtin_types_compatible_p" => C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR,
        b"__builtin_expect" => C_AST_KIND_BUILTIN_EXPECT_EXPR,
        b"__builtin_offsetof" => C_AST_KIND_BUILTIN_OFFSETOF_EXPR,
        b"__builtin_object_size" => C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR,
        b"__builtin_prefetch" => C_AST_KIND_BUILTIN_PREFETCH_EXPR,
        b"__builtin_unreachable" => C_AST_KIND_BUILTIN_UNREACHABLE_STMT,
        b"__builtin_add_overflow" | b"__builtin_sub_overflow" | b"__builtin_mul_overflow" => {
            C_AST_KIND_BUILTIN_OVERFLOW_EXPR
        }
        b"__builtin_classify_type" => C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR,
        _ if name.starts_with(b"__builtin_") => {
            return Err(GnuBuiltinError {
                len: name.len(),
                message: "Fix: add explicit GNU builtin semantics before accepting this intrinsic",
            });
        }
        _ => return Ok(None),
    };

    Ok(Some(kind))
}

/// GNU builtin front-end normalization pass.
///
/// The pass preserves already-classified VAST builtin kinds and maps legacy
/// front-end builtin opcodes onto the same stable kind IDs. Reserved GNU
/// builtin opcodes trap instead of passing through as ordinary calls.
#[must_use]
pub fn c11_gnu_builtins_pass(
    ast_opcodes: &str,
    out_ast_opcodes: &str,
    num_ast_nodes: Expr,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let loop_body = vec![
        Node::let_bind("opcode", Expr::load(ast_opcodes, t.clone())),
        Node::let_bind("normalized", Expr::var("opcode")),
        Node::if_then(
            Expr::eq(Expr::var("opcode"), Expr::u32(GNU_BUILTIN_EXPECT_OPCODE)),
            vec![Node::assign(
                "normalized",
                Expr::u32(C_AST_KIND_BUILTIN_EXPECT_EXPR),
            )],
        ),
        Node::if_then(
            Expr::eq(Expr::var("opcode"), Expr::u32(GNU_BUILTIN_OFFSETOF_OPCODE)),
            vec![Node::assign(
                "normalized",
                Expr::u32(C_AST_KIND_BUILTIN_OFFSETOF_EXPR),
            )],
        ),
        Node::if_then(
            Expr::eq(
                Expr::var("opcode"),
                Expr::u32(GNU_BUILTIN_OBJECT_SIZE_OPCODE),
            ),
            vec![Node::assign(
                "normalized",
                Expr::u32(C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR),
            )],
        ),
        Node::if_then(
            Expr::eq(Expr::var("opcode"), Expr::u32(GNU_BUILTIN_PREFETCH_OPCODE)),
            vec![Node::assign(
                "normalized",
                Expr::u32(C_AST_KIND_BUILTIN_PREFETCH_EXPR),
            )],
        ),
        Node::if_then(
            Expr::eq(
                Expr::var("opcode"),
                Expr::u32(GNU_BUILTIN_UNREACHABLE_OPCODE),
            ),
            vec![Node::assign(
                "normalized",
                Expr::u32(C_AST_KIND_BUILTIN_UNREACHABLE_STMT),
            )],
        ),
        Node::if_then(
            Expr::eq(
                Expr::bitand(Expr::var("opcode"), Expr::u32(0xFFFF_FF00)),
                Expr::u32(GNU_BUILTIN_RESERVED_PREFIX),
            ),
            vec![Node::trap(
                Expr::var("opcode"),
                "unsupported-gnu-builtin-opcode",
            )],
        ),
        Node::store(out_ast_opcodes, t.clone(), Expr::var("normalized")),
    ];

    let ast_count = match &num_ast_nodes {
        Expr::LitU32(n) => *n,
        _ => 1,
    };
    Program::wrapped(
        vec![
            BufferDecl::storage(ast_opcodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(ast_count),
            BufferDecl::storage(out_ast_opcodes, 1, BufferAccess::ReadWrite, DataType::U32)
                .with_count(ast_count),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::c11_gnu_builtins_pass",
            vec![Node::if_then(Expr::lt(t.clone(), num_ast_nodes), loop_body)],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::c11_gnu_builtins_pass")
    .with_non_composable_with_self(true)
}

inventory::submit! {
    crate::harness::OpEntry {
        id: "vyre-libs::parsing::c11_gnu_builtins_pass",
        build: || c11_gnu_builtins_pass("ast", "out_ast", Expr::u32(4)),
        test_inputs: Some(|| {
            let ast = [
                0x11u32,
                GNU_BUILTIN_EXPECT_OPCODE,
                GNU_BUILTIN_OBJECT_SIZE_OPCODE,
                C_AST_KIND_BUILTIN_CHOOSE_EXPR,
            ];
            let ast_bytes = ast
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![ast_bytes, vec![0u8; 4 * 4]]]
        }),
        expected_output: Some(|| {
            let out = [
                0x11u32,
                C_AST_KIND_BUILTIN_EXPECT_EXPR,
                C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR,
                C_AST_KIND_BUILTIN_CHOOSE_EXPR,
            ];
            let out_bytes = out
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect::<Vec<u8>>();
            vec![vec![out_bytes]]
        }),
    }
}
