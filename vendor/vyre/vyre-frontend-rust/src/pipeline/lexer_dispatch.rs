//! Lexer dispatch for the Rust frontend pipeline.

use vyre_libs::parsing::rust::lex::lexer::core::{lex as lex_cpu, Token};
use vyre_libs::parsing::rust::lex::lexer::plan::RustLexerPlan;

use crate::pipeline::RustPipelineConfig;
use crate::RustFrontendError;

/// Lex source bytes, preferring GPU if configured and available.
pub fn lex(
    source: &[u8],
    config: &RustPipelineConfig,
    _plan: &RustLexerPlan,
) -> Result<Vec<Token>, RustFrontendError> {
    if config.gpu_lex {
        return Err(RustFrontendError::Backend(
            "Rust GPU lexer dispatch is not wired yet; set `gpu_lex = false` for explicit CPU lexer substrate testing instead of silently falling through"
                .to_string(),
        ));
    }

    lex_cpu(source).map_err(RustFrontendError::Lex)
}
