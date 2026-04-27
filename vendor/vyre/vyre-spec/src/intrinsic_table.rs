//! Frozen backend intrinsic-name tables for Category C operations.

/// Backend intrinsic names for a Category C operation in the frozen contract.
///
/// Example: a bit-count operation can record `countOneBits` for WGSL and
/// `popc` for CUDA while leaving missing backends detectable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntrinsicTable {
    /// WGSL intrinsic or built-in spelling.
    pub wgsl: Option<&'static str>,
    /// CUDA intrinsic or PTX instruction spelling.
    pub cuda: Option<&'static str>,
    /// Metal Shading Language intrinsic spelling.
    pub metal: Option<&'static str>,
    /// SPIR-V extended instruction or opcode spelling.
    pub spirv: Option<&'static str>,
}

impl IntrinsicTable {
    /// Return the missing backend names required by Category C.
    pub fn missing_backends(&self) -> impl Iterator<Item = &'static str> + '_ {
        [
            ("wgsl", self.wgsl),
            ("cuda", self.cuda),
            ("metal", self.metal),
            ("spirv", self.spirv),
        ]
        .into_iter()
        .filter_map(|(backend, name)| intrinsic_name_is_empty(name).then_some(backend))
    }
}

fn intrinsic_name_is_empty(value: Option<&str>) -> bool {
    value.map(str::trim).unwrap_or_default().is_empty()
}
