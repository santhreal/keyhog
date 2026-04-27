//! Compiler Extension Bridge: Binds lock-free aliasing to vyre_foundation.
//!
//! Provides the generic `OpId` interception mechanism mapping the SURGE AST
//! directly onto the `union_find` registry payload.

use std::collections::HashMap;
use vyre_foundation::ir::DataType;

/// Stable Operation UUID identifying the Lock-Free Alias Union subkernel.
pub const ALIAS_UNION_OP_ID: &str = "vyre.graph.union_find.v1";

/// Descriptor for an alias-analysis extension op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasOpDescriptor {
    /// Operand types accepted by the op.
    pub inputs: Vec<DataType>,
    /// Result type produced by the op.
    pub output: DataType,
    /// Human-readable operation contract.
    pub description: &'static str,
    /// True when argument order does not affect the result.
    pub commutative: bool,
    /// True when the op updates the alias data structure.
    pub side_effects: bool,
}

impl AliasOpDescriptor {
    /// Build the lock-free alias-union descriptor.
    #[must_use]
    pub fn alias_union() -> Self {
        Self {
            inputs: vec![DataType::U32, DataType::U32],
            output: DataType::U32,
            description: "Lock-free warp-accelerated union-find alias join",
            commutative: true,
            side_effects: true,
        }
    }
}

/// Registry of alias-analysis extension operations keyed by stable op id.
#[derive(Debug, Default, Clone)]
pub struct AliasRegistry {
    ops: HashMap<&'static str, AliasOpDescriptor>,
}

impl AliasRegistry {
    /// Register a descriptor under a stable op id.
    pub fn register(&mut self, op_id: &'static str, descriptor: AliasOpDescriptor) {
        self.ops.insert(op_id, descriptor);
    }

    /// Look up a descriptor by stable op id.
    #[must_use]
    pub fn get(&self, op_id: &str) -> Option<&AliasOpDescriptor> {
        self.ops.get(op_id)
    }

    /// Number of registered alias operations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// True when no alias operations are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

/// Registers the lock-free alias solver dynamically onto the compiler engine.
/// When the surgec compiler encounters `x == y` under aliased semantic boundaries,
/// the lowering phase will map the AST into this Extern execution route.
pub fn register_alias_ops(registry: &mut AliasRegistry) {
    registry.register(ALIAS_UNION_OP_ID, AliasOpDescriptor::alias_union());
}
