//! Lowering stage: thin orchestrator over the `vyre-libs` lowering substrate.

use vyre::ir::Program;
use vyre_libs::parsing::rust::lower as rust_lower;
use vyre_libs::parsing::rust::parse::Module;
use vyre_libs::parsing::rust::sema::Resolution;

use crate::RustFrontendError;

/// Lower a resolved module to Vyre IR via the reusable lowering substrate.
pub fn lower(module: &Module, resolution: &Resolution) -> Result<Program, RustFrontendError> {
    rust_lower::lower(module, resolution).map_err(|e| RustFrontendError::Lower(e.to_string()))
}
