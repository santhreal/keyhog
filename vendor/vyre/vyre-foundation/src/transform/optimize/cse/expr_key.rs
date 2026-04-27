use super::TypeKey;
use smallvec::SmallVec;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ExprId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum ExprKey {
    LitU32(u32),
    LitI32(i32),
    /// Stores the IEEE 754 bits so `Eq`/`Hash`/`Ord` work correctly.
    LitF32(u32),
    LitBool(bool),
    Var(Arc<str>),
    Load(Arc<str>, ExprId),
    BufLen(Arc<str>),
    InvocationId(u8),
    WorkgroupId(u8),
    LocalId(u8),
    BinOp(u8, ExprId, ExprId),
    UnOp(u8, ExprId),
    /// CSE key for `BinOp::Opaque(id)` — stores the extension u32 id so
    /// two extensions with distinct ids hash to distinct keys. Without
    /// this, every `BinOp::Opaque(_)` collapsed onto a single key via
    /// `bin_op_key`'s wildcard fallback — silently merging unrelated
    /// extensions in CSE. (§1 injectivity contract.)
    BinOpOpaque(u32, ExprId, ExprId),
    /// CSE key for `UnOp::Opaque(id)` — same rationale as `BinOpOpaque`.
    UnOpOpaque(u32, ExprId),
    Call(Arc<str>, SmallVec<[ExprId; 4]>),
    Fma(ExprId, ExprId, ExprId),
    Select(ExprId, ExprId, ExprId),
    Cast(TypeKey, ExprId),
    Atomic,
    /// Subgroup intrinsics are effectful + lane-correlated; CSE must not
    /// merge them, so every instance gets a unique counter-keyed identity.
    Subgroup(u32),
    SubgroupLocalId,
    SubgroupSize,
    Opaque(Arc<str>, [u8; 32]),
}
