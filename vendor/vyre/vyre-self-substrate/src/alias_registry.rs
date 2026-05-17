//! Alias-registry substrate consumer.
//!
//! Wires `vyre_primitives::graph::alias_registry::register_alias_ops`
//! into the dispatch path so the optimizer can stand up the
//! lock-free alias-union descriptor table at startup. Registry
//! lookups (a hot path during alias-analysis) bump the substrate
//! counter so observability dashboards see the consumption rate.

use vyre_primitives::graph::alias_registry::{
    register_alias_ops as primitive_register, AliasOpDescriptor, AliasRegistry, ALIAS_UNION_OP_ID,
};

/// Build a registry pre-populated with vyre's default alias-analysis
/// op descriptors. Bumps the dataflow-fixpoint substrate counter so
/// observability can track how many registries the dispatch path
/// instantiates.
#[must_use]
pub fn build_default_registry() -> AliasRegistry {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    let mut registry = AliasRegistry::default();
    primitive_register(&mut registry);
    registry
}

/// Look up an alias op descriptor in `registry`. Bumps the
/// substrate counter so per-query observability is visible.
#[must_use]
pub fn lookup_alias_op<'a>(
    registry: &'a AliasRegistry,
    op_id: &str,
) -> Option<&'a AliasOpDescriptor> {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    registry.get(op_id)
}

/// Convenience: returns whether the well-known alias-union op is
/// registered. The dispatch-time alias analyzer consults this
/// before emitting alias-union nodes.
#[must_use]
pub fn alias_union_registered(registry: &AliasRegistry) -> bool {
    lookup_alias_op(registry, ALIAS_UNION_OP_ID).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_registry_has_alias_union() {
        let registry = build_default_registry();
        assert!(alias_union_registered(&registry));
    }

    #[test]
    fn empty_registry_has_no_ops() {
        let registry = AliasRegistry::default();
        assert!(registry.is_empty());
        assert!(!alias_union_registered(&registry));
    }

    #[test]
    fn lookup_unknown_op_returns_none() {
        let registry = build_default_registry();
        assert!(lookup_alias_op(&registry, "vyre.graph.does_not_exist").is_none());
    }

    /// Closure-bar: substrate path produces the same registry as
    /// calling the primitive register function directly.
    #[test]
    fn matches_primitive_directly() {
        let via_substrate = build_default_registry();
        let mut via_primitive = AliasRegistry::default();
        primitive_register(&mut via_primitive);
        assert_eq!(via_substrate.len(), via_primitive.len());
        assert!(via_substrate.get(ALIAS_UNION_OP_ID).is_some());
        assert!(via_primitive.get(ALIAS_UNION_OP_ID).is_some());
    }

    /// Adversarial: looking up the alias-union op id on an empty
    /// registry must return None — no implicit defaults.
    #[test]
    fn empty_registry_does_not_self_populate() {
        let registry = AliasRegistry::default();
        assert!(lookup_alias_op(&registry, ALIAS_UNION_OP_ID).is_none());
    }

    /// The default alias-union op is commutative + side-effecting
    /// (the CSE / dispatch optimizer reads these flags on every
    /// query). If the descriptor flips, downstream passes may
    /// silently drop union calls — test pins the contract.
    #[test]
    fn alias_union_descriptor_contract() {
        let registry = build_default_registry();
        let desc = lookup_alias_op(&registry, ALIAS_UNION_OP_ID).unwrap();
        assert!(desc.commutative, "alias-union must be commutative");
        assert!(desc.side_effects, "alias-union must declare side effects");
    }
}
