use std::path::PathBuf;

/// Compiler invocation parameters passed from `vyrec`.
/// Strict separation of CLI args from the core pipeline configuration.
#[derive(Debug, Clone, Default)]
pub struct VyreCompileOptions {
    pub is_compile_only: bool,
    pub input_files: Vec<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub include_dirs: Vec<PathBuf>,
    pub forced_include_files: Vec<PathBuf>,
    pub macros: Vec<(String, Option<String>)>,
    pub undefs: Vec<String>,
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
