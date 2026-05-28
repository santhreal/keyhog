//! Logic for compiling detector specifications into an efficient scanning engine.

#[path = "compiler_build.rs"]
pub mod compiler_build;

#[path = "compiler_compile.rs"]
pub mod compiler_compile;

#[path = "compiler_prefix.rs"]
pub mod compiler_prefix;

pub use compiler_build::{
    build_compile_state, rewrite_alternation_prefix, split_leading_inline_flag, CompileState,
};
pub use compiler_compile::{
    build_ac_pattern_set, build_fallback_keyword_ac, build_gpu_literals, build_prefix_propagation,
    build_same_prefix_patterns, compile_companion, compile_detector_companions,
    compile_detector_pattern, compile_pattern, log_quality_warnings, shared_regex_compile,
    warm_shared_regex_cache,
};
pub use compiler_prefix::{
    extract_inner_literals, extract_literal_prefix, extract_literal_prefixes, is_escaped_literal,
};
