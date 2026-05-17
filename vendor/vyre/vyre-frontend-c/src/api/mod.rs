use std::path::PathBuf;

/// Compiler invocation parameters passed from `vyrec`.
/// Strict separation of CLI args from the core pipeline configuration.
#[derive(Debug, Clone, Default)]
pub struct VyreCompileOptions {
    /// `-c` was supplied: emit a `.o` artifact and skip linking.
    pub is_compile_only: bool,
    /// C source files to compile, in CLI order.
    pub input_files: Vec<PathBuf>,
    /// Override for the output path; defaults to `a.out` for link mode and per-input `.o` otherwise.
    pub output_file: Option<PathBuf>,
    /// `-I` directories to add to the include search path.
    pub include_dirs: Vec<PathBuf>,
    /// `-include` files prepended before the translation unit body, in CLI order.
    pub forced_include_files: Vec<PathBuf>,
    /// `-D NAME[=VALUE]` macro definitions; empty value is `Some("")` and `-D NAME` is `None`.
    pub macros: Vec<(String, Option<String>)>,
    /// `-U NAME` macro undefinitions evaluated after `macros`.
    pub undefs: Vec<String>,
}

/// Parser-only C11 evidence emitted by the GPU frontend without object/codegen stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CParseSummary {
    /// Original source byte length.
    pub source_bytes: u64,
    /// Logical token count after keyword promotion and span repair.
    pub token_count: u32,
    /// AST evidence bytes produced by the parser stage.
    pub ast_bytes: u64,
    /// Function-record bytes produced by structure extraction.
    pub function_record_bytes: u64,
    /// Call-record bytes produced by structure extraction.
    pub call_record_bytes: u64,
}

/// Run the GPU C11 spine and emit **Linux ET_REL** `.o` files (embedding `VYRECOB2`), or link with `-nostdlib`.
pub fn compile(options: VyreCompileOptions) -> Result<(), String> {
    if options.input_files.is_empty() {
        return Err("No input files specified.".to_string());
    }
    if options.is_compile_only {
        crate::pipeline::compile_c11_sources(&options)
    } else {
        crate::pipeline::link_c11_executable(&options)
    }
}

/// Run the GPU C parser spine only and return parse evidence metrics.
pub fn parse_source(source: &str) -> Result<CParseSummary, String> {
    crate::pipeline::parse_c11_source(source)
}

/// Run the GPU C syntax parser only and return token/AST evidence metrics.
pub fn parse_syntax_source(source: &str) -> Result<CParseSummary, String> {
    crate::pipeline::parse_c11_syntax_source(source)
}
