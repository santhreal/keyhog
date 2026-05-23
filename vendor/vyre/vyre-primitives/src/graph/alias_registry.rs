//! Compiler Extension Bridge: Binds lock-free aliasing to vyre_foundation.
//!
//! Provides the generic `OpId` interception mechanism mapping the source-query dialect AST
//! directly onto the `union_find` registry payload.

use std::collections::HashMap;
use vyre_foundation::ir::DataType;

/// Stable Operation UUID identifying the Lock-Free Alias Union subkernel.
pub const ALIAS_UNION_OP_ID: &str = "vyre-primitives::graph::alias_union";

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

    /// True when a descriptor is registered for `op_id`.
    #[must_use]
    pub fn contains(&self, op_id: &str) -> bool {
        self.ops.contains_key(op_id)
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
/// When the downstream analyzer compiler encounters `x == y` under aliased semantic boundaries,
/// the lowering phase will map the AST into this Extern execution route.
pub fn register_alias_ops(registry: &mut AliasRegistry) {
    registry.register(ALIAS_UNION_OP_ID, AliasOpDescriptor::alias_union());
}

/// Build the primitive-default alias operation registry.
#[must_use]
pub fn default_alias_registry() -> AliasRegistry {
    let mut registry = AliasRegistry::default();
    register_alias_ops(&mut registry);
    registry
}

/// True when the well-known alias-union operation is registered.
#[must_use]
pub fn alias_union_registered(registry: &AliasRegistry) -> bool {
    registry.contains(ALIAS_UNION_OP_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_contains_alias_union_only() {
        let registry = default_alias_registry();
        assert_eq!(registry.len(), 1);
        assert!(alias_union_registered(&registry));
    }

    #[test]
    fn empty_registry_has_no_implicit_alias_union() {
        let registry = AliasRegistry::default();
        assert!(registry.is_empty());
        assert!(!alias_union_registered(&registry));
        assert!(!registry.contains(ALIAS_UNION_OP_ID));
    }

    #[test]
    fn alias_union_descriptor_contract_is_pinned() {
        let registry = default_alias_registry();
        let desc = registry
            .get(ALIAS_UNION_OP_ID)
            .expect("default registry must contain alias-union descriptor");
        assert_eq!(desc.inputs, vec![DataType::U32, DataType::U32]);
        assert_eq!(desc.output, DataType::U32);
        assert!(desc.commutative, "alias-union must be commutative");
        assert!(desc.side_effects, "alias-union mutates union-find state");
    }
}
