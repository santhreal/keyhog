#![allow(missing_docs)]
pub(crate) fn generate_kernel_rs() -> String {
    r#"pub fn execute(_inputs: &[u8]) -> Vec<u8> {
    compile_error!("kernel not yet implemented - fill this in");
}
"#
    .to_string()
}
