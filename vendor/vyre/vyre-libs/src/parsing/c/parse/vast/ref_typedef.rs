//! Audit-fix A36 `vast/ref_typedef.rs` extract.

#![allow(missing_docs)] // c-parser feature: A33-A36 split lost some leading doc comments; lint loud, fix surgically when revisiting docs.
use crate::parsing::c::lex::tokens::*;

use super::expr_shape::*;
use super::ref_decode_err::*;
use super::*;

mod annotator;
mod asm_attributes;
mod decl_context;
mod declarations;
mod expressions;
mod identifiers;
mod scopes;
mod typed_kind;

use annotator::*;
use asm_attributes::*;
use decl_context::*;
use declarations::*;
use expressions::*;
use identifiers::*;
use scopes::*;

pub(super) fn kind_at(vast_nodes: &[u32], node_idx: usize) -> u32 {
    expressions::kind_at_impl(vast_nodes, node_idx)
}

pub(super) fn reference_typed_kind(vast_nodes: &[u32], node_idx: usize) -> u32 {
    typed_kind::reference_typed_kind(vast_nodes, node_idx)
}

pub fn try_reference_c11_annotate_typedef_names(
    vast_node_bytes: &[u8],
    haystack: &[u8],
) -> Result<Vec<u8>, CReferenceDecodeError> {
    let raw_vast_nodes = try_vast_words_from_bytes(vast_node_bytes)?;
    Ok(reference_c11_annotate_typedef_names_from_words(
        raw_vast_nodes,
        haystack,
    ))
}

/// CPU oracle for `c11_annotate_typedef_names`.
#[must_use]
pub fn reference_c11_annotate_typedef_names(vast_node_bytes: &[u8], haystack: &[u8]) -> Vec<u8> {
    try_reference_c11_annotate_typedef_names(vast_node_bytes, haystack).unwrap_or_default()
}
