//! IR transformation passes.
//!
//! Before a `Program` is lowered to backend code, it runs through a series
//! of target-independent optimizations and transformations: call inlining,
//! common-subexpression elimination, dead-code elimination, and visitor
//! utilities. These passes are the vyre analogue of LLVM's mid-level IR
//! passes.

/// Call inlining transforms.
///
/// This pass expands `Expr::Call` nodes into the callee's IR body,
/// eliminating kernel-dispatch overhead for small compositional ops.
pub mod inline;

/// Compiler-oriented IR primitives.
pub mod compiler;

/// Whole-program optimization passes.
///
/// These functions run standard compiler optimizations (CSE, DCE) on vyre
/// IR so that frontends can emit naive code and rely on the core library
/// to clean it up before lowering.
pub mod optimize;
/// Shared-nothing parallel dispatch analysis.
pub mod parallelism;

/// IR visitor utilities.
///
/// Provides iterative traversal functions that walk nodes and expressions
/// without recursion, preventing stack overflow on deeply nested programs.
pub mod visit;
