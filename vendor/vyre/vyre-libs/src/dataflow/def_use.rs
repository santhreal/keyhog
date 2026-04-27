//! DF-11 — Def-use chain query over a constructed SSA form.
//!
//! For a given SSA-renamed definition site (say `%tmp.3 = …`),
//! return the bitset of nodes that USE that definition. This is the
//! canonical "what reads this def" query that CodeQL exposes as
//! `DataFlow::Node::getUses()` and that every taint rule reaches for
//! when answering "did the value defined here reach a sink without
//! being overwritten."
//!
//! Composes:
//!   * [`super::ssa::SsaForm::def_use_chains`] — the per-SSA-version
//!     use list built by Cytron + variable renaming during SSA
//!     construction. We index it by the SSA version of the supplied
//!     definition site and emit a bitset over node ids.
//!
//! Soundness: [`Exact`](super::soundness::Soundness::Exact). The
//! def-use chain is computed by SSA construction, which is sound by
//! construction; this primitive is a pure query against that
//! pre-built table.

use super::ssa::SsaForm;

pub(crate) const OP_ID: &str = "vyre-libs::dataflow::def_use";

/// Look up uses of an SSA definition version. Returns a sorted dense
/// vector of `node_id` values for every use of `def_version`. Returns
/// an empty vector when the version is unknown to `form`.
#[must_use]
pub fn def_use_chain(form: &SsaForm, def_version: u32) -> Vec<u32> {
    let mut uses = form
        .def_use_chains
        .get(&def_version)
        .cloned()
        .unwrap_or_default();
    uses.sort_unstable();
    uses.dedup();
    uses
}

/// Pack the use-set for `def_version` into a bitset over `node_count`.
/// Each bit `i` is `1` iff node `i` is recorded as a use of the
/// supplied definition version. Bits beyond `node_count` are zero.
#[must_use]
pub fn def_use_chain_bitset(form: &SsaForm, def_version: u32, node_count: u32) -> Vec<u32> {
    use vyre_primitives::graph::csr_forward_traverse::bitset_words;
    let words = bitset_words(node_count) as usize;
    let mut bits = vec![0u32; words];
    for use_id in def_use_chain(form, def_version) {
        if use_id < node_count {
            let w = (use_id / 32) as usize;
            let b = use_id % 32;
            bits[w] |= 1u32 << b;
        }
    }
    bits
}

/// Marker type for the def-use dataflow primitive.
pub struct DefUse;

impl DefUse {
    /// Stable operation id for the def-use primitive.
    #[must_use]
    pub const fn op_id(&self) -> &'static str {
        OP_ID
    }
}

impl super::soundness::SoundnessTagged for DefUse {
    fn soundness(&self) -> super::soundness::Soundness {
        super::soundness::Soundness::Exact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn form_with(def_use: &[(u32, &[u32])]) -> SsaForm {
        let mut chains = HashMap::new();
        for (def, uses) in def_use {
            chains.insert(*def, uses.to_vec());
        }
        SsaForm {
            phi_nodes: HashMap::new(),
            renamed_usages: HashMap::new(),
            def_use_chains: chains,
        }
    }

    #[test]
    fn known_definition_returns_sorted_dedup_uses() {
        let form = form_with(&[(7, &[5, 3, 5, 9, 3])]);
        assert_eq!(def_use_chain(&form, 7), vec![3, 5, 9]);
    }

    #[test]
    fn unknown_definition_returns_empty() {
        let form = form_with(&[(7, &[3, 5])]);
        assert!(def_use_chain(&form, 99).is_empty());
    }

    #[test]
    fn bitset_packs_use_ids() {
        let form = form_with(&[(7, &[1, 33, 65])]);
        let bits = def_use_chain_bitset(&form, 7, 96);
        // Bit 1 in word 0; bit 1 in word 1 (offset 33-32); bit 1 in word 2 (65-64).
        assert_eq!(bits, vec![1u32 << 1, 1u32 << 1, 1u32 << 1]);
    }

    #[test]
    fn bitset_skips_uses_beyond_node_count() {
        let form = form_with(&[(7, &[3, 200])]);
        let bits = def_use_chain_bitset(&form, 7, 64);
        // Only bit 3 in word 0 is set; the 200 use exceeds node_count.
        assert_eq!(bits, vec![1u32 << 3, 0]);
    }

    #[test]
    fn empty_form_yields_empty_bitset() {
        let form = form_with(&[]);
        let bits = def_use_chain_bitset(&form, 7, 64);
        assert_eq!(bits, vec![0, 0]);
    }
}
