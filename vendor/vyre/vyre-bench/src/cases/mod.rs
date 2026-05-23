#![allow(clippy::unnecessary_cast, clippy::needless_range_loop)]
pub mod adversarial;
pub mod alias_aware_optimizations;
pub mod attention;
pub mod bigint;
pub mod binary_search;
pub mod c_parser;
pub mod conditional_batch;
pub mod conditional_eval;
pub mod cpu_baselines;
pub mod crypto;
pub mod cuda_ptx_patterns;
pub mod dfa_match;
pub mod egraph_saturation;
pub mod elementwise;
pub mod gather;
pub mod hashtable;
pub mod histogram;
pub mod interpreter;
pub mod lower_rewrite_impact;
pub mod matmul;
pub mod megakernel_condition;
pub mod megakernel_latency;
pub mod megakernel_truth;
pub mod optimizer_impact;
pub mod reduce_sum;
pub mod regex_bt;
pub mod release_workloads;
pub mod stencil;
pub mod synthetic;
pub mod transpose;
// `weir_dataflow` directly imports `weir::*` for vyre↔weir parity benches.
// Per the LEGO discipline (vyre never calls anything else), it is gated
// behind the `external-baselines` feature so vyre-bench's default surface
// is vyre-only.
#[cfg(feature = "external-baselines")]
pub mod dataflow_baseline;
