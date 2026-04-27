//! Shader specialization constants (C-B3).
//!
//! Op attributes that are literal `u32` / `i32` / `f32` become
//! naga `Override` specialization constants. The pipeline is
//! compiled once per `(shader, bindings, wg size)` triple and
//! specialized per call via
//! `ComputePipelineDescriptor::constants`.
//!
//! The key insight: two calls to `xor` that differ only by a
//! constant key (e.g., `0xA5` vs `0x5A`) no longer need to compile
//! two distinct shaders. Both share a ComputePipeline; the wgpu
//! `constants` field at pipeline-create time binds the actual
//! value. naga passes this through as an `Override` declaration in
//! the WGSL:
//!
//! ```wgsl
//! override XOR_KEY: u32 = 0;
//! ```
//!
//! This module carries:
//!
//! * `SpecValue` — one scalar attribute value.
//! * `SpecMap` — ordered map of `(name, value)` pairs that lower
//!   into wgpu's `HashMap<String, f64>` constants table.
//! * `SpecCacheKey` — what the pipeline cache hashes on. Extends
//!   the existing `(shader, bindings, wg_size)` key with the spec
//!   values.
//!
//! The pipeline cache layer consumes `SpecCacheKey` to decide
//! cache hit / compile. The naga::Module builder for each op emits
//! an `Override` declaration when its attribute schema marks the
//! slot as specializable.

use std::collections::BTreeMap;

/// One specializable attribute value.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum SpecValue {
    /// Unsigned 32-bit.
    U32(u32),
    /// Signed 32-bit.
    I32(i32),
    /// 32-bit float (bit-pattern hashed for cache key — IEEE-754
    /// NaN is hashed by its bit representation, preserving
    /// distinguishability).
    F32(f32),
    /// Boolean flag.
    Bool(bool),
}

impl SpecValue {
    /// Convert to the `f64` wgpu accepts for pipeline constants.
    ///
    /// wgpu's pipeline-constants API takes `HashMap<String, f64>`;
    /// numeric coercion is lossless for `u32`, `i32`, `f32`, and
    /// `bool` (represented as 0.0 / 1.0).
    #[must_use]
    pub fn as_f64(self) -> f64 {
        match self {
            SpecValue::U32(v) => f64::from(v),
            SpecValue::I32(v) => f64::from(v),
            SpecValue::F32(v) => f64::from(v),
            SpecValue::Bool(b) => {
                if b {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    /// Hash this value into a 64-bit cache key. Floats hash by
    /// bit pattern (including NaN); bool becomes 0 / 1.
    #[must_use]
    pub fn cache_hash(self) -> u64 {
        // Tag-byte + 8 bytes of payload. Lowest byte is the tag;
        // remaining bytes are big-endian packed.
        match self {
            SpecValue::U32(v) => u64::from(v) << 8,
            SpecValue::I32(v) => (1u64) | ((v as u32 as u64) << 8),
            SpecValue::F32(v) => (2u64) | ((v.to_bits() as u64) << 8),
            SpecValue::Bool(b) => (3u64) | (u64::from(u8::from(b)) << 8),
        }
    }
}

/// Ordered map of specialization-constant values.
///
/// Ordering matters for cache keys: `{A=1, B=2}` must hash to the
/// same thing as `{B=2, A=1}`. Using `BTreeMap` guarantees a
/// deterministic traversal order.
#[derive(Debug, Default, Clone)]
pub struct SpecMap {
    entries: BTreeMap<String, SpecValue>,
}

impl SpecMap {
    /// Empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a `(name, value)` pair.
    pub fn insert(&mut self, name: impl Into<String>, value: SpecValue) {
        self.entries.insert(name.into(), value);
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate `(name, value)` pairs in ordered traversal.
    pub fn iter(&self) -> impl Iterator<Item = (&str, SpecValue)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// Convert to the `HashMap<String, f64>` wgpu expects.
    #[must_use]
    pub fn to_wgpu_constants(&self) -> std::collections::HashMap<String, f64> {
        self.entries
            .iter()
            .map(|(k, v)| (k.clone(), v.as_f64()))
            .collect()
    }

    /// Compute the 64-bit cache key contribution.
    ///
    /// Folds every `(name, value)` pair into a single u64 via FNV-1a.
    /// Keys beyond the pipeline's natural identity (shader source,
    /// bindings, workgroup size) are XORed into this hash to form
    /// the pipeline-cache key.
    #[must_use]
    pub fn cache_hash(&self) -> u64 {
        // FNV-1a 64-bit
        let mut h: u64 = 0xcbf29ce484222325;
        for (name, value) in self.iter() {
            for byte in name.as_bytes() {
                h ^= u64::from(*byte);
                h = h.wrapping_mul(0x100000001b3);
            }
            let vh = value.cache_hash();
            for byte in vh.to_le_bytes() {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x100000001b3);
            }
        }
        h
    }
}

/// Cache key extending the baseline pipeline identity with
/// specialization values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpecCacheKey {
    /// Hash of the shader source (produced by the existing pipeline
    /// cache layer).
    pub shader_hash: u64,
    /// Stable signature of the bind-group layout.
    pub binding_sig: u64,
    /// Workgroup size in the dispatch.
    pub workgroup_size: [u32; 3],
    /// Hash of the specialization map.
    pub spec_hash: u64,
}

impl SpecCacheKey {
    /// Fold a `SpecMap` into a cache key.
    #[must_use]
    pub fn new(
        shader_hash: u64,
        binding_sig: u64,
        workgroup_size: [u32; 3],
        specs: &SpecMap,
    ) -> Self {
        Self {
            shader_hash,
            binding_sig,
            workgroup_size,
            spec_hash: specs.cache_hash(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_value_as_f64_preserves_magnitude() {
        assert_eq!(SpecValue::U32(42).as_f64(), 42.0);
        assert_eq!(SpecValue::I32(-7).as_f64(), -7.0);
        assert_eq!(
            SpecValue::F32(std::f32::consts::PI).as_f64(),
            f64::from(std::f32::consts::PI)
        );
        assert_eq!(SpecValue::Bool(true).as_f64(), 1.0);
        assert_eq!(SpecValue::Bool(false).as_f64(), 0.0);
    }

    #[test]
    fn cache_hash_distinguishes_tag_and_value() {
        // U32(0) and I32(0) hash differently because the tag byte
        // differs — prevents collision between semantically-
        // different values that share a bit pattern.
        assert_ne!(
            SpecValue::U32(0).cache_hash(),
            SpecValue::I32(0).cache_hash()
        );
        assert_ne!(
            SpecValue::Bool(false).cache_hash(),
            SpecValue::U32(0).cache_hash()
        );
    }

    #[test]
    fn spec_map_ordering_is_commutative() {
        let mut a = SpecMap::new();
        a.insert("A", SpecValue::U32(1));
        a.insert("B", SpecValue::U32(2));
        let mut b = SpecMap::new();
        b.insert("B", SpecValue::U32(2));
        b.insert("A", SpecValue::U32(1));
        assert_eq!(a.cache_hash(), b.cache_hash());
    }

    #[test]
    fn spec_map_values_affect_hash() {
        let mut a = SpecMap::new();
        a.insert("KEY", SpecValue::U32(0xA5));
        let mut b = SpecMap::new();
        b.insert("KEY", SpecValue::U32(0x5A));
        assert_ne!(a.cache_hash(), b.cache_hash());
    }

    #[test]
    fn to_wgpu_constants_produces_expected_shape() {
        let mut specs = SpecMap::new();
        specs.insert("XOR_KEY", SpecValue::U32(0xA5));
        specs.insert("SHIFT", SpecValue::I32(3));
        let map = specs.to_wgpu_constants();
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("XOR_KEY").copied(), Some(f64::from(0xA5_u32)));
        assert_eq!(map.get("SHIFT").copied(), Some(3.0));
    }

    #[test]
    fn cache_key_differs_by_spec_hash() {
        let mut a = SpecMap::new();
        a.insert("K", SpecValue::U32(1));
        let mut b = SpecMap::new();
        b.insert("K", SpecValue::U32(2));
        let key_a = SpecCacheKey::new(0xdead, 0xbeef, [64, 1, 1], &a);
        let key_b = SpecCacheKey::new(0xdead, 0xbeef, [64, 1, 1], &b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn identical_specs_produce_identical_cache_keys() {
        let mut a = SpecMap::new();
        a.insert("K", SpecValue::U32(1));
        let mut b = SpecMap::new();
        b.insert("K", SpecValue::U32(1));
        let key_a = SpecCacheKey::new(0xdead, 0xbeef, [64, 1, 1], &a);
        let key_b = SpecCacheKey::new(0xdead, 0xbeef, [64, 1, 1], &b);
        assert_eq!(key_a, key_b);
    }
}
