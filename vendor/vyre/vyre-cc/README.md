# vyre-cc

GPU-first C compilation driver for vyre.

`vyre-cc` takes C source, lowers it to vyre IR via the `vyre-libs`
parsing pipeline, optimises, and emits Linux ET_REL `.o` files that
embed the compiled vyre program as a `VYRECOB2` v3 payload. It is the
library behind the `vyrec` binary at `tools/vyrec/`.

```text
C source
  → lex → digraph rewrite → opt_conditional_mask
  → macro expansion (table passthrough)
  → bracket_match (paren + brace)
  → function shapes → call sites → ABI layout
  → ast_shunting_yard → CFG/goto → opt_lower_elf
  → Linux ET_REL .o  (with .vyrecob2.* section)
```

The full roadmap lives in `docs/COMPILER_E2E_PLAN.md`.

## Invariants

1. **Single-TU entrypoint per run.** `pipeline::compile_unit` takes
   one translation unit and emits one object file. Multi-TU is the
   linker's job (driver-level, not library-level).
2. **Every stage is GPU-reachable.** Lex, bracket match, and
   statement-bounds extraction all run through vyre Programs that the
   backend dispatches; there is no host-only fallback for the hot
   stages. CPU-only host helpers exist strictly for bootstrap and
   debugging.
3. **Emit format is ELF ET_REL with a `.vyrecob2.*` payload section.**
   The payload is the wire-encoded vyre Program + metadata. Consumers
   link normally with `cc -nostdlib`, then a small `_start` stub
   surfaces the GPU entry point.
4. **Bytes are packed little-endian, 4-byte aligned.** Haystack
   packing (`pipeline::pack`) is deterministic and reversible; two
   packs of the same bytes produce byte-identical buffers.
5. **No ABI drift without a VYRECOB version bump.** The payload
   section name encodes the wire version; old tooling sees a new
   section name and refuses to load it rather than misinterpret.

## Boundaries

`vyre-cc` owns:

- The C-source → vyre IR pipeline (`pipeline`).
- Haystack byte packing / statement-bounds extraction.
- Minimal ELF64 relocation generation (`elf_linux`).
- Translation-unit compilation and the in-process lex DFA cache.
- The `api` surface the `vyrec` CLI consumes.

`vyre-cc` does NOT own:

- The C grammar itself — that lives in `vyre-libs/src/parsing/c/`
  and the grammar is shared with every C-consuming crate.
- The GPU backend — `vyre-driver-wgpu` or other backend crates.
- Linking — the CLI (`tools/vyrec`) drives `cc -nostdlib`; the
  library emits the `.o` and stops.
- Runtime concerns (async I/O, pipeline-cache policy, megakernel
  orchestration) — those are `vyre-runtime`.

## Three worked examples

### 1. Compile a single TU to an object file

```rust
use vyre_cc::pipeline;

fn compile_hello(src: &str, out_path: &std::path::Path) -> std::io::Result<()> {
    let object = pipeline::compile_unit(src)?;
    std::fs::write(out_path, object.bytes())?;
    Ok(())
}
```

### 2. Pack a C-source byte buffer for GPU dispatch

```rust
use vyre_cc::pipeline::pack_haystack;

fn to_gpu_buffer(src: &[u8]) -> Vec<u8> {
    pack_haystack(src).bytes
}
```

### 3. Extract statement bounds from pre-lexed tokens

```rust
use vyre_cc::pipeline::{compile_unit, statement_bounds};

fn stmt_ranges(src: &str) -> Vec<std::ops::Range<usize>> {
    let tu = compile_unit(src).expect("compile");
    statement_bounds(&tu)
}
```

## Extension guide — adding a compiler pass

1. Decide whether the pass is host-only (bootstrap/debug) or must
   run on GPU (hot path). Host-only passes live in `pipeline/` as
   ordinary Rust functions; GPU passes emit a vyre `Program` that
   `vyre-driver` dispatches.
2. For a GPU pass, wire it into `compile_unit`'s sequence in
   `pipeline::compile_unit`. Order matters — the lex pass MUST run
   before `bracket_match`, etc. Document the dependency in a comment
   on the pass function.
3. For a host pass, add a test under `tests/` that exercises it on
   a representative TU; for a GPU pass, add a conform fixture under
   `conform/vyre-conform-runner/fixtures` so the backend is diffed
   against the CPU reference.
4. Extend the `.vyrecob2.*` payload section only through a version
   bump. Old tooling MUST refuse to load a new-version payload
   rather than attempt a partial read.
5. Update `docs/COMPILER_E2E_PLAN.md` with the pass's phase number
   and preconditions; that doc is the source of truth for pipeline
   ordering, not individual file comments.

See `pipeline/compile_unit.rs` for the end-to-end driver and
`elf_linux.rs` for the ET_REL emission template.
