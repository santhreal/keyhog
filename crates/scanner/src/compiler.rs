//! Logic for compiling detector specifications into an efficient scanning engine.

// Submodules live in `compiler/` (native resolution), matching the
// `foo.rs` + `foo/` layout used across the workspace. Names unchanged.
pub(crate) mod compiler_build;
pub(crate) mod compiler_compile;
pub(crate) mod compiler_prefix;

pub(crate) use compiler_build::build_compile_state;
#[cfg(test)]
pub(crate) use compiler_build::{rewrite_alternation_prefix, split_leading_inline_flag};
#[cfg(feature = "gpu")]
pub(crate) use compiler_compile::build_gpu_literals;
pub(crate) use compiler_compile::build_phase2_keyword_ac;
pub(crate) use compiler_compile::log_quality_warnings;
#[cfg(test)]
pub(crate) use compiler_compile::match_proves_keyword_nearby;
pub(crate) use compiler_compile::{
    build_ac_pattern_set, build_prefix_propagation, build_same_prefix_patterns,
};
#[cfg(test)]
pub(crate) use compiler_prefix::is_escaped_literal;
#[cfg(test)]
pub(crate) use compiler_prefix::{
    extract_inner_literals, extract_literal_prefix, extract_literal_prefixes,
};
