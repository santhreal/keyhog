//! SPIR-V emission via naga::back::spv.

use naga::back::spv;

/// Emit SPIR-V words from a vyre-built naga::Module.
///
/// The caller builds the `naga::Module` through the same builder family
/// that vyre-wgpu uses (so the kernel body is byte-identical across
/// substrates up to the back-end writer); this function validates and
/// writes the SPIR-V blob.
pub struct SpirvBackend;

impl SpirvBackend {
    /// Stable backend identifier.
    pub const BACKEND_ID: &'static str = super::SPIRV_BACKEND_ID;

    /// Construct a new backend instance. Always succeeds.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Emit SPIR-V words from a validated naga::Module.
    ///
    /// # Errors
    /// Returns a human diagnostic when the module fails naga validation or
    /// when the SPIR-V writer rejects a construct.
    pub fn emit_spv(module: &naga::Module) -> Result<Vec<u32>, String> {
        let info = naga::valid::Validator::new(
            naga::valid::ValidationFlags::all(),
            naga::valid::Capabilities::all(),
        )
        .validate(module)
        .map_err(|e| format!("naga validate failed: {e:?}"))?;
        let options = spv::Options::default();
        spv::write_vec(module, &info, &options, None)
            .map_err(|e| format!("spv write failed: {e:?}"))
    }
}

impl Default for SpirvBackend {
    fn default() -> Self {
        Self::new()
    }
}
