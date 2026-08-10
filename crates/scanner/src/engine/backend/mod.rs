//! Scanner backend state machine and dispatch module.
use super::*;

pub(crate) mod dispatch;
pub(crate) mod prepared;
mod trigger_collection;
pub(crate) mod triggered;

pub(crate) use prepared::PreparedChunk;
#[cfg(feature = "simd")]
pub(crate) use prepared::{
    build_packed_simd_compile_plan, build_simd_compile_plan, SimdPhase1CompilePlan,
    SimdPhase1Prefilter,
};
