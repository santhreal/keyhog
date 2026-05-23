//! Compatibility facade for shared dataflow soundness contracts.
//!
//! `vyre-libs::dataflow` remains as a stable import path for older consumers,
//! but platform crates must not re-export downstream analysis engines. Concrete
//! IFDS, SSA, reaching-definition, callgraph, slicing, range, and related
//! analyses live in their owning engine crates and consume these shared
//! contracts from `vyre-foundation`.

pub use vyre_foundation::soundness::{
    validate_pipeline, validate_primitive, PrecisionContract, PrimitiveSoundness, Soundness,
    SoundnessTagged, SoundnessViolation,
};
