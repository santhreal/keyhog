# vyre FAQ

## Why not just use LLVM?
LLVM has fixed primitives. vyre is community-extensible: a contributor drops ONE file and their op ships. LLVM requires upstream patches. Plus LLVM has no conformance prover — there is no binary verdict that "my backend is correct."

## Why not just use MLIR?
MLIR is a compiler framework. vyre is a compiler framework PLUS a conformance prover. MLIR dialects are defined; whether a lowering preserves semantics is left to the dialect author. vyre proves it.

## Why GPU-first?
CPUs have a finished abstraction stack. GPUs do not. Every GPU compute project today is bespoke. vyre is the missing IR.

## Do I need to understand all 8 modules to add an op?
No. You touch ONE file: `vyre-core/src/ops/{category}/{name}.rs`. `automod` + `vyre-build-scan` wire it in. `certify()` verifies it.

## What happens if my op is wrong?
`certify()` returns a concrete counterexample with a "Fix: ..." hint. Input bytes, expected output, observed output. You fix the op, rerun.

## Can I use vyre on CPU only?
No. vyre is GPU-first by design. Cat C ops require hardware intrinsics. The CPU reference interpreter lives in the separate `vyre-reference` crate — it is a byte-identity oracle for conformance verification and a small-data fallback, not a production runtime path. Production dispatch requires a GPU backend (e.g. `vyre-wgpu`).

## Which GPU backends are supported?
wgpu (WebGPU) is the reference backend. Metal, CUDA, and WASM are on the 0.5 roadmap. You can implement `VyreBackend` yourself for any GPU.

## Is vyre stable?
vyre 1.0 is not yet shipped. 0.4 is alpha. The 6 frozen trait signatures and 24 `AlgebraicLaw` variants are locked. The module path structure may shift until 1.0. See `STABILITY.md`.

## Can I use it in production?
0.4 is alpha. Treat it as experimental. Consumers pinning to a specific version get reproducible behavior, but breaking changes may happen at minor version bumps until 1.0.

## What are Category A, B, and C?
- **A**: compositional. Your op is defined as a composition of simpler ops. Lowering inlines. Zero overhead.
- **B**: forbidden. Runtime trait-object routing (`typetag`, `inventory`, `downcast`, `Box<dyn Future>`, `async_trait`). Banned by `conform`. Breaks the black-box invariant.
- **C**: hardware intrinsic. Backed by a GPU instruction on a specific backend. Declared per-backend via `IntrinsicTable`.

## How is this not a Python API?
vyre has no runtime trait-object dispatch anywhere. Every extension is compile-time monomorphized. Zero-cost abstractions. Python-level extensibility with Rust-level performance.

## Who funds this?
Santh Project. See the about page at santhsecurity.org.

## Where do I ask a question?
GitHub Discussions at github.com/santhsecurity/vyre/discussions.

## Where do I file a bug?
GitHub Issues. See `.github/ISSUE_TEMPLATE/` for structured templates.

## Can I add my own backend?
Yes. Implement `VyreBackend`, run `certify()` to prove conformance, and publish as a separate crate that depends on `vyre` and `vyre-conform`. See `CONTRIBUTING.md`.

## Can I add a new enforcement gate?
Yes. One file in `vyre-conform/src/enforce/gates/`. See `CONTRIBUTING.md`.

## The name "vyre"?
Short, memorable, available. No hidden meaning.

## Why does correctness matter at the IR level?
Because the hardware is already nondeterministic enough. vyre removes compiler-introduced nondeterminism by restriction: strict IEEE 754 ops cannot be fused, reductions are ordered or canonical-tree, subnormals are preserved, and transcendentals are correctly rounded. The backend either passes `certify()` or it is rejected.

## What if the reference interpreter has a bug?
The reference interpreter is pure Rust, exhaustively tested, and subject to the same adversarial gates as the backends. A bug in the reference is treated as a critical defect and fixed immediately. The entire corpus is re-run after any reference change.

## Does vyre compete with SPIR-V?
No. SPIR-V is a compilation target. vyre is a semantic contract system that happens to compile to SPIR-V, WGSL, Metal, or DXIL as a backend detail. You can think of vyre as the layer that guarantees the SPIR-V you generate is correct.

## How big is the test matrix?
Every op runs against boundary values, adversarial witnesses, mutation classes, algebraic laws, and backend-specific oracles. The `conform_self_audit_must_scream` test fails if coverage drops. There is no such thing as "enough" tests; there is only "more than before."

## What is the final goal?
A local model running on a laptop GPU that writes a minimal Rust compiler as a vyre program — lexer, parser, resolver, trait solver, borrow checker, MIR builder, and codegen — entirely on GPU, zero CPU fallback. When that runs, vyre will have proven that GPU compute abstractions can be zero-overhead, provably correct, and expressive enough to encode a real compiler.
