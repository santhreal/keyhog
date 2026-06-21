//! Migrated from src/ #[cfg(test)] modules (KH-GAP-004).

mod bigram_bloom_inline;
mod boundary_inline;
mod caesar_inline;
mod compiler_prefix_inline;
mod decode_structure_inline;
mod entropy_avx512_inline;
mod entropy_fast_inline;
mod entropy_keywords_inline;
mod entropy_scanner_inline;
mod fragment_cache_inline;
mod gpu_inline;
mod hw_probe_inline;
mod jwt_inline;
mod parsers_inline;
mod probabilistic_gate_inline;
mod reverse_inline;
mod shape_canonical_inline;
mod shape_inline;
mod simd_inline;
mod simdsieve_prefilter_inline;
mod static_intern_inline;
mod telemetry_inline;
mod types_inline;
mod util_hash_inline;
