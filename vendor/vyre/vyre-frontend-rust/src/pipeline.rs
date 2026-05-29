//! Pipeline orchestration: lex -> parse -> resolve -> typeck -> borrow -> lower.

use vyre_libs::parsing::rust::lex::lexer::plan::RustLexerPlan;
use vyre_libs::parsing::rust::parse::Module;

use crate::RustFrontendError;

pub mod borrow_stage;
pub mod lexer_dispatch;
pub mod lower_stage;
pub mod parse_stage;
pub mod resolve_stage;
pub mod typeck_stage;

/// Configuration for the Rust frontend pipeline.
#[derive(Debug, Clone)]
pub struct RustPipelineConfig {
    /// Whether to attempt GPU lexing. Off by default: GPU lexer dispatch is not
    /// wired yet and fails loudly when enabled.
    pub gpu_lex: bool,
    /// Whether to run borrow checking. Off by default: the mutability rule is
    /// implemented, but the conflicting-borrow rules report incomplete.
    pub borrow_check: bool,
    /// Whether to lower to Vyre IR. Off by default: lowering is not wired yet
    /// and fails loudly when enabled.
    pub lower: bool,
}

impl Default for RustPipelineConfig {
    fn default() -> Self {
        // The working envelope today is CPU lex + parse + resolve + typeck.
        // Borrow checking and lowering are opt-in (borrow is partial; lowering
        // is unwired and fails loudly).
        Self {
            gpu_lex: false,
            borrow_check: false,
            lower: false,
        }
    }
}

/// Pipeline state holder. Construct once, compile many files.
pub struct RustPipeline {
    config: RustPipelineConfig,
    lex_plan: RustLexerPlan,
}

impl RustPipeline {
    /// Create a new pipeline.
    pub fn new(config: RustPipelineConfig) -> Self {
        Self {
            config,
            lex_plan: RustLexerPlan::new(),
        }
    }

    /// Run the pipeline on a single source buffer.
    ///
    /// CPU lex, parse, name resolution, and type checking always run. Borrow
    /// checking and lowering are gated on the config. Borrow checking surfaces
    /// real mutability (E0596) errors but reports incomplete for the
    /// conflicting-borrow rules, and lowering fails loudly until wired, so a
    /// caller never receives a success that skipped a requested stage.
    pub fn compile_unit(&self, source: &[u8]) -> Result<CompilationUnit, RustFrontendError> {
        let tokens = self::lexer_dispatch::lex(source, &self.config, &self.lex_plan)?;
        let module: Module = self::parse_stage::parse(source, &tokens)?;
        let resolution = self::resolve_stage::resolve(&module, source)?;
        self::typeck_stage::typeck(&module, source, &resolution)?;
        if self.config.borrow_check {
            self::borrow_stage::borrow_check(&module, &resolution)?;
        }
        let program = if self.config.lower {
            Some(self::lower_stage::lower(&module, &resolution)?)
        } else {
            None
        };

        Ok(CompilationUnit {
            token_count: tokens.len(),
            module,
            program,
        })
    }
}

/// Result of compiling one translation unit.
#[derive(Debug, Clone)]
pub struct CompilationUnit {
    /// Number of tokens lexed.
    pub token_count: usize,
    /// Parsed module.
    pub module: Module,
    /// Lowered Vyre program (if lowering was enabled).
    pub program: Option<vyre::ir::Program>,
}
