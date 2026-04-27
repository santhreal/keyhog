//! Standalone entry point for the shape-test audit.

#[path = "../lint_shape_tests.rs"]
mod lint_shape_tests;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    lint_shape_tests::run(&args);
}
