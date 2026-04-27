#![allow(clippy::panic)]
//! Open-IR extension surface — traits and inventory registration for
//! third-party Expr / Node / DataType / BinOp / UnOp / AtomicOp /
//! RuleCondition variants.
//!
//! vyre-spec defines the per-kind extension ids and trait contracts
//! (`ExtensionDataType`, `ExtensionBinOp`, `ExtensionUnOp`,
//! `ExtensionAtomicOp`). This module provides the link-time registration
//! types that downstream crates submit via `inventory::submit!`, plus
//! frozen-after-init resolvers that materialize `&'static dyn Trait`
//! pointers.
//!
//! # Runtime cost
//!
//! Every resolver is a `LazyLock<FxHashMap<ExtensionXxxId, &'static dyn
//! ExtensionXxx>>`. First call walks the inventory once. Every subsequent
//! call is one hash + one table probe — sub-ns, no allocation, no lock.
//! The prior implementation called `inventory::iter` per lookup which
//! scaled linearly with the registration count and violated the
//! hot-path invariant documented in `docs/inventory-contract.md`.

use std::fmt::Debug;
use std::hash::Hash;
use std::sync::LazyLock;

use rustc_hash::FxHashMap;
use vyre_spec::extension::{
    ExtensionAtomicOp, ExtensionAtomicOpId, ExtensionBinOp, ExtensionBinOpId, ExtensionDataType,
    ExtensionDataTypeId, ExtensionRuleConditionId, ExtensionUnOp, ExtensionUnOpId,
};

/// Generic extension id used by the `Expr::Opaque` and `Node::Opaque`
/// surfaces (introduced in the 0.5.x cycle before the per-kind ids in
/// vyre-spec were finalized). New extensions should prefer the per-kind
/// ids — this generic id stays for the existing `ExprExtensionNode` /
/// `NodeNode` traits until their migration to per-kind surfaces lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtensionId(pub u32);

impl ExtensionId {
    /// Construct an extension id from a stable name hash (blake3 first 4 bytes).
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let digest = blake3::hash(name.as_bytes());
        let bytes = digest.as_bytes();
        let id = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Self(id | 0x8000_0000)
    }
}

/// Opaque Expr extension. Downstream crates implement this to add new
/// expression kinds.
pub trait ExprExtensionNode: Debug + Send + Sync + 'static {
    /// Stable extension id.
    fn extension_id(&self) -> ExtensionId;
    /// Encode to wire bytes.
    fn encode(&self) -> Vec<u8>;
    /// Human-readable display.
    fn display(&self) -> String;
}

/// Opaque Node extension.
pub trait NodeNode: Debug + Send + Sync + 'static {
    /// Stable extension id.
    fn extension_id(&self) -> ExtensionId;
    /// Encode to wire bytes.
    fn encode(&self) -> Vec<u8>;
    /// Human-readable display.
    fn display(&self) -> String;
}

/// Opaque rule condition extension — lets third-party rule-engine crates
/// compose bespoke predicates without editing vyre-core's RuleCondition.
pub trait RuleConditionExt: Debug + Send + Sync + 'static {
    /// Stable extension id.
    fn extension_id(&self) -> ExtensionRuleConditionId;
    /// Evaluate against an opaque rule context (crate-specific payload).
    fn evaluate_opaque(&self, ctx: &dyn std::any::Any) -> bool;
    /// Canonical fingerprint for cache invalidation.
    fn stable_fingerprint(&self) -> [u8; 32];
    /// Buffer declarations the rule builder must add when this condition
    /// appears in a program. Extensions that need private scratch
    /// buffers for their evaluator return them here; frozen conditions
    /// return an empty `Vec`. The rule builder merges these into the
    /// canonical six-buffer set before construction.
    fn required_buffers(&self) -> Vec<crate::ir::BufferDecl> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------
// Registration types (one per extendable IR kind).
// ---------------------------------------------------------------------

/// Link-time registration for an extension-declared `DataType`.
///
/// The `vtable` pointer is what `resolve_data_type` returns — it bypasses
/// any further registry lookup on subsequent accesses.
pub struct ExtensionDataTypeRegistration {
    /// Stable id this registration serves.
    pub id: ExtensionDataTypeId,
    /// Implementation pointer. Must outlive the process (`'static`).
    pub vtable: &'static dyn ExtensionDataType,
}

/// Link-time registration for an extension-declared binary operator.
pub struct ExtensionBinOpRegistration {
    /// Stable id this registration serves.
    pub id: ExtensionBinOpId,
    /// Implementation pointer.
    pub vtable: &'static dyn ExtensionBinOp,
}

/// Link-time registration for an extension-declared unary operator.
pub struct ExtensionUnOpRegistration {
    /// Stable id this registration serves.
    pub id: ExtensionUnOpId,
    /// Implementation pointer.
    pub vtable: &'static dyn ExtensionUnOp,
}

/// Link-time registration for an extension-declared atomic operator.
pub struct ExtensionAtomicOpRegistration {
    /// Stable id this registration serves.
    pub id: ExtensionAtomicOpId,
    /// Implementation pointer.
    pub vtable: &'static dyn ExtensionAtomicOp,
}

/// Legacy `Expr`/`Node`/`RuleCondition` registration (generic ExtensionId).
///
/// Retained while the wire decoder and visitor migration still consume
/// the generic id; will be split into per-kind registrations when those
/// sites migrate.
pub struct ExtensionRegistration {
    /// Stable id this extension owns.
    pub id: ExtensionId,
    /// Extension-crate name for diagnostics.
    pub name: &'static str,
    /// Extension kind tag.
    pub kind: ExtensionKind,
    /// Decoder for this extension's wire bytes.
    pub decode: fn(&[u8]) -> Result<(), String>,
}

/// Which IR surface an extension extends (legacy generic registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtensionKind {
    /// Extends [`Expr`](crate::ir::Expr).
    Expr,
    /// Extends [`Node`](crate::ir::Node).
    Node,
    /// Extends [`DataType`](crate::ir::DataType).
    DataType,
    /// Extends rule conditions.
    RuleCondition,
}

inventory::collect!(ExtensionRegistration);
inventory::collect!(ExtensionDataTypeRegistration);
inventory::collect!(ExtensionBinOpRegistration);
inventory::collect!(ExtensionUnOpRegistration);
inventory::collect!(ExtensionAtomicOpRegistration);

/// Deserializer function matched to the bytes produced by
/// [`crate::ir::ExprNode::wire_payload`] for `Expr::Opaque` round-trip.
pub type ExprExtensionDeserializer =
    fn(&[u8]) -> Result<std::sync::Arc<dyn crate::ir::ExprNode>, String>;

/// Deserializer function matched to the bytes produced by
/// [`crate::ir::NodeExtension::wire_payload`] for `Node::Opaque` round-trip.
pub type NodeExtensionDeserializer =
    fn(&[u8]) -> Result<std::sync::Arc<dyn crate::ir::NodeExtension>, String>;

/// Inventory record pairing an `ExprNode` extension kind to its wire-format
/// deserializer. Wire tag `0x80` on an `Expr` discriminant triggers a
/// kind-keyed lookup against these records.
pub struct OpaqueExprResolver {
    /// Stable extension kind — must match [`crate::ir::ExprNode::extension_kind`].
    pub kind: &'static str,
    /// Deserializer for the extension's `wire_payload` bytes.
    pub deserialize: ExprExtensionDeserializer,
}

/// Inventory record pairing a `NodeExtension` extension kind to its decoder.
pub struct OpaqueNodeResolver {
    /// Stable extension kind — must match [`crate::ir::NodeExtension::extension_kind`].
    pub kind: &'static str,
    /// Deserializer for the extension's `wire_payload` bytes.
    pub deserialize: NodeExtensionDeserializer,
}

inventory::collect!(OpaqueExprResolver);
inventory::collect!(OpaqueNodeResolver);

fn collect_unique_by<K, V, I>(registrations: I, registry_name: &str) -> FxHashMap<K, V>
where
    K: Eq + Hash + Copy + std::fmt::Debug,
    I: IntoIterator<Item = (K, V, &'static str)>,
{
    let mut map = FxHashMap::default();
    let mut owners: FxHashMap<K, &'static str> = FxHashMap::default();
    for (key, value, owner) in registrations {
        if let Some(previous_owner) = owners.insert(key, owner) {
            panic!(
                "{registry_name} duplicate registration for {key:?}: first registrant `{previous_owner}`, second registrant `{owner}`. Fix: pick one stable tag/kind owner."
            );
        }
        map.insert(key, value);
    }
    map
}

fn frozen_opaque_expr_registry() -> &'static FxHashMap<&'static str, ExprExtensionDeserializer> {
    static FROZEN: LazyLock<FxHashMap<&'static str, ExprExtensionDeserializer>> =
        LazyLock::new(|| {
            collect_unique_by(
                inventory::iter::<OpaqueExprResolver>
                    .into_iter()
                    .map(|reg| (reg.kind, reg.deserialize, reg.kind)),
                "OpaqueExprResolver",
            )
        });
    &FROZEN
}

fn frozen_opaque_node_registry() -> &'static FxHashMap<&'static str, NodeExtensionDeserializer> {
    static FROZEN: LazyLock<FxHashMap<&'static str, NodeExtensionDeserializer>> =
        LazyLock::new(|| {
            collect_unique_by(
                inventory::iter::<OpaqueNodeResolver>
                    .into_iter()
                    .map(|reg| (reg.kind, reg.deserialize, reg.kind)),
                "OpaqueNodeResolver",
            )
        });
    &FROZEN
}

/// Decode an opaque expression extension payload into an `Expr::Opaque` value.
pub fn decode_opaque_expr(kind: &str, payload: &[u8]) -> Result<crate::ir::Expr, String> {
    if let Some(deserialize) = frozen_opaque_expr_registry().get(kind) {
        let node = deserialize(payload)?;
        Ok(crate::ir::Expr::Opaque(node))
    } else {
        Err(format!(
            "Fix: no OpaqueExprResolver registered for extension kind `{kind}`. Link the crate that owns this extension and ensure it submits `inventory::submit! {{ OpaqueExprResolver {{ kind, deserialize }} }}`."
        ))
    }
}

/// Decode an opaque statement extension payload into a `Node::Opaque` value.
pub fn decode_opaque_node(kind: &str, payload: &[u8]) -> Result<crate::ir::Node, String> {
    if let Some(deserialize) = frozen_opaque_node_registry().get(kind) {
        let extension = deserialize(payload)?;
        Ok(crate::ir::Node::Opaque(extension))
    } else {
        Err(format!(
            "Fix: no OpaqueNodeResolver registered for extension kind `{kind}`. Link the crate that owns this extension and ensure it submits `inventory::submit! {{ OpaqueNodeResolver {{ kind, deserialize }} }}`."
        ))
    }
}

// ---------------------------------------------------------------------
// Frozen resolvers. First call walks the inventory; every subsequent
// call is hash + probe. No locks on the hot path.
// ---------------------------------------------------------------------

fn frozen_generic_registry() -> &'static FxHashMap<ExtensionId, &'static ExtensionRegistration> {
    static FROZEN: LazyLock<FxHashMap<ExtensionId, &'static ExtensionRegistration>> =
        LazyLock::new(|| {
            collect_unique_by(
                inventory::iter::<ExtensionRegistration>
                    .into_iter()
                    .map(|reg| (reg.id, reg, reg.name)),
                "ExtensionRegistration",
            )
        });
    &FROZEN
}

fn frozen_data_type_registry(
) -> &'static FxHashMap<ExtensionDataTypeId, &'static dyn ExtensionDataType> {
    static FROZEN: LazyLock<FxHashMap<ExtensionDataTypeId, &'static dyn ExtensionDataType>> =
        LazyLock::new(|| {
            collect_unique_by(
                inventory::iter::<ExtensionDataTypeRegistration>
                    .into_iter()
                    .map(|reg| (reg.id, reg.vtable, reg.vtable.display_name())),
                "ExtensionDataTypeRegistration",
            )
        });
    &FROZEN
}

fn frozen_bin_op_registry() -> &'static FxHashMap<ExtensionBinOpId, &'static dyn ExtensionBinOp> {
    static FROZEN: LazyLock<FxHashMap<ExtensionBinOpId, &'static dyn ExtensionBinOp>> =
        LazyLock::new(|| {
            collect_unique_by(
                inventory::iter::<ExtensionBinOpRegistration>
                    .into_iter()
                    .map(|reg| (reg.id, reg.vtable, reg.vtable.display_name())),
                "ExtensionBinOpRegistration",
            )
        });
    &FROZEN
}

fn frozen_un_op_registry() -> &'static FxHashMap<ExtensionUnOpId, &'static dyn ExtensionUnOp> {
    static FROZEN: LazyLock<FxHashMap<ExtensionUnOpId, &'static dyn ExtensionUnOp>> =
        LazyLock::new(|| {
            collect_unique_by(
                inventory::iter::<ExtensionUnOpRegistration>
                    .into_iter()
                    .map(|reg| (reg.id, reg.vtable, reg.vtable.display_name())),
                "ExtensionUnOpRegistration",
            )
        });
    &FROZEN
}

fn frozen_atomic_op_registry(
) -> &'static FxHashMap<ExtensionAtomicOpId, &'static dyn ExtensionAtomicOp> {
    static FROZEN: LazyLock<FxHashMap<ExtensionAtomicOpId, &'static dyn ExtensionAtomicOp>> =
        LazyLock::new(|| {
            collect_unique_by(
                inventory::iter::<ExtensionAtomicOpRegistration>
                    .into_iter()
                    .map(|reg| (reg.id, reg.vtable, reg.vtable.display_name())),
                "ExtensionAtomicOpRegistration",
            )
        });
    &FROZEN
}

// ---------------------------------------------------------------------
// Public lookup API. Every function is hot-path safe (one hash + one
// table probe; no allocation; no iteration).
// ---------------------------------------------------------------------

/// Resolve a `DataType::Opaque(id)` to its extension implementation.
///
/// Returns `None` for ids that no linked crate has registered; callers
/// surface a typed error, never a panic.
#[must_use]
pub fn resolve_data_type(id: ExtensionDataTypeId) -> Option<&'static dyn ExtensionDataType> {
    frozen_data_type_registry().get(&id).copied()
}

/// Resolve a `BinOp::Opaque(id)` to its extension implementation.
#[must_use]
pub fn resolve_bin_op(id: ExtensionBinOpId) -> Option<&'static dyn ExtensionBinOp> {
    frozen_bin_op_registry().get(&id).copied()
}

/// Resolve a `UnOp::Opaque(id)` to its extension implementation.
#[must_use]
pub fn resolve_un_op(id: ExtensionUnOpId) -> Option<&'static dyn ExtensionUnOp> {
    frozen_un_op_registry().get(&id).copied()
}

/// Resolve an `AtomicOp::Opaque(id)` to its extension implementation.
#[must_use]
pub fn resolve_atomic_op(id: ExtensionAtomicOpId) -> Option<&'static dyn ExtensionAtomicOp> {
    frozen_atomic_op_registry().get(&id).copied()
}

/// Look up a legacy generic-id registration.
#[must_use]
pub fn find_extension(id: ExtensionId) -> Option<&'static ExtensionRegistration> {
    frozen_generic_registry().get(&id).copied()
}

/// Iterate every legacy registration. Not hot-path; materializes a Vec.
#[must_use]
pub fn registered_extensions() -> Vec<&'static ExtensionRegistration> {
    frozen_generic_registry().values().copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_id_has_high_bit_set() {
        let id = ExtensionId::from_name("example.crate");
        assert_ne!(id.0 & 0x8000_0000, 0);
    }

    #[test]
    fn extension_id_is_deterministic() {
        let a = ExtensionId::from_name("vyre-example-ext");
        let b = ExtensionId::from_name("vyre-example-ext");
        assert_eq!(a, b);
    }

    #[test]
    fn per_kind_resolvers_are_empty_by_default() {
        // vyre-core links no extension crates in its own test binary.
        // Every resolver must return None for any id.
        let data_type_id = ExtensionDataTypeId::from_name("tensor.gather");
        assert!(resolve_data_type(data_type_id).is_none());
        let bin_op_id = ExtensionBinOpId::from_name("bit.parity");
        assert!(resolve_bin_op(bin_op_id).is_none());
        let un_op_id = ExtensionUnOpId::from_name("bit.reverse_nibbles");
        assert!(resolve_un_op(un_op_id).is_none());
        let atomic_id = ExtensionAtomicOpId::from_name("atomic.clamp");
        assert!(resolve_atomic_op(atomic_id).is_none());
    }

    #[test]
    fn generic_registry_is_empty_by_default() {
        assert_eq!(registered_extensions().len(), 0);
    }

    #[test]
    fn duplicate_extension_ids_name_both_registrants() {
        let panic = std::panic::catch_unwind(|| {
            let _: FxHashMap<ExtensionId, usize> = collect_unique_by(
                [
                    (ExtensionId(1), 10usize, "dialect.alpha"),
                    (ExtensionId(1), 20usize, "dialect.beta"),
                ],
                "ExtensionRegistration",
            );
        })
        .expect_err("Fix: duplicate registrations must panic");

        let message = if let Some(message) = panic.downcast_ref::<String>() {
            message.clone()
        } else if let Some(message) = panic.downcast_ref::<&str>() {
            (*message).to_string()
        } else {
            panic!("Fix: duplicate-registration panic payload must be a string");
        };

        assert!(message.contains("dialect.alpha"));
        assert!(message.contains("dialect.beta"));
    }
}
