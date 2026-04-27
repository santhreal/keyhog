//! Structural C11 parser passes.

/// Declaration specifier + declarator extraction.
pub mod declarations;
/// GNU builtin recognition pass.
pub mod gnu_builtins;
/// `asm` / `__asm__` inline-assembly extraction.
pub mod inline_asm;
/// Function / struct / enum structural pass.
pub mod structure;
/// Token stream to packed VAST rows.
pub mod vast;
mod vast_kinds;
