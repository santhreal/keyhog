# GPU DFA assembly pipeline

`vyre-std` ships the full pattern-set-to-GPU-DFA compilation pipeline
as five composable stages plus a composite entry point. Each stage is
a pure function; the final `PackedDfa` is POD bytes uploadable to a
`wgpu::Buffer`.

```text
regex source │                      Pattern::Literal      Pattern::Regex
                         │                     │
                         │  dfa_assemble escapes literal  │
                         └──────────────┬─────────────────┘
                                        │
                                 combined regex
                                        │
                                        ▼
                            pattern::regex_to_nfa (Thompson)
                                        │
                                       Nfa
                                        │
                                        ▼
                            pattern::nfa_to_dfa (subset construction,
                                                 dead-state pruning)
                                        │
                                       Dfa
                                        │
                                        ▼
                            pattern::dfa_minimize (Hopcroft)
                                        │
                                   minimal Dfa
                                        │
                                        ▼
                            pattern::dfa_pack (Dense or EquivClass)
                                        │
                                   PackedDfa
```

## Stage 1 — `regex_to_nfa`

Thompson construction. Supports literal bytes, concatenation,
alternation `|`, Kleene star `*`, plus `+`, optional `?`, character
classes `[abc]` with ranges and negation, and escape via `\\`. Anchors
and backreferences are deliberately out of scope — those belong in a
regex frontend rather than in the compilation substrate.

Output is an `Nfa` with:

- `state_count: u32`
- `edges: Vec<NfaEdge>` where `byte: Option<u8>` (None = epsilon)
- `start: NfaStateId`
- `accept: Vec<bool>`

Errors surface as `PatternError::ParseError { offset, message }` with a
`Fix:`-prefixed explanation.

## Stage 2 — `nfa_to_dfa`

Subset construction. Walks epsilon closures, builds deterministic
transition rows keyed by byte, prunes dead states. Returns a `Dfa` with
a dense `transitions: Vec<u32>` laid out row-major at `state * 256 +
byte`. Out-of-table entries are `INVALID_STATE = u32::MAX`.

State-count ceiling is `MAX_DFA_STATES = 65_535`. Explosive closures
surface as `PatternError::StateOverflow`.

## Stage 3 — `dfa_minimize`

Hopcroft's partition refinement. Produces the canonical minimal DFA for
the input's accepted language. The output is idempotent:
`minimize(minimize(d)) == minimize(d)` bytewise after canonical state
renumbering. Conform declares `AlgebraicLaw::Idempotent` on this op.

## Stage 4 — `dfa_pack`

Transition-table compression with two format options.

**`DfaPackFormat::Dense`** — row-major `state × 256 × u32`. Fastest
scan, largest memory. Pick this when GPU memory is abundant relative to
state count.

**`DfaPackFormat::EquivClass`** — byte-equivalence classes collapse
redundant columns. Ships a 256-entry class table (padded to 4-byte
alignment) followed by `state × num_classes × u32`. Wins dramatically
when the effective alphabet is narrow (typical for regex patterns over
ASCII subsets).

Both formats round-trip through `dfa_unpack` back to a `Dfa` for
verification.

## Stage 5 — `dfa_assemble`

The composite entry point. Takes `&[Pattern<'_>]` (literal bytes or
regex source), escapes each literal, joins with `|`, runs the full
pipeline, and returns a `PackedDfa`. `AssembleOptions` picks the format
and whether to minimize (default: minimize).

## Layout invariants

- Literal bytes are escaped via a single-byte regex atom so they cannot
  accidentally be interpreted as metacharacters.
- Non-ASCII literal bytes use a character-class wrapper (`[<byte>]`) so
  the Thompson parser treats them as a single-byte atom.
- Empty pattern sets surface `PatternError::EmptyPatternSet`.
- Malformed regex surfaces `PatternError::ParseError` with the exact
  byte offset.

## Cache

`pattern::cache` wraps `dfa_assemble` with a content-addressed lookup:

```rust
use vyre_std::pattern::cache::load_or_compute;

let packed = load_or_compute(&patterns, options)?;
```

The key is `FNV-1a(CACHE_VERSION ⊕ options ⊕ patterns)`. Cache files
live under `${XDG_CACHE_HOME:-~/.cache}/vyre/dfa/`. `VYRE_NO_CACHE=1`
disables the cache entirely. `cache::clear()` and `cache::size()`
expose cache management to CLI callers.

## Aho-Corasick build

For pure literal-pattern sets where the user wants the classic
Aho-Corasick trie + failure links + output chain directly (not via
regex construction), `pattern::aho_corasick_build` exposes the CPU
reference and WGSL kernel. The output format is documented in the
module: `[state_count][pattern_count][goto_table][fail_links][out_head]
[out_link][pattern_lengths]`. The GOLDEN and KAT fixture vectors are
byte-diffed against this CPU reference on every test run.

## Consumer examples

- `std/examples/std_pattern_compile.rs` — three patterns → packed DFA →
  scan four inputs, runnable via
  `cargo run -p vyre-std --example std_pattern_compile`.
- `std/examples/std_arith_overflow.rs` — saturating vs wrapping at
  boundary cases.
- `std/benches/dfa_assemble_bench.rs` — measures pipeline throughput
  across pattern-set sizes and pack formats.
