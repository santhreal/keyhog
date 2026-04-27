# Match Operations

## The scanner's inner loop

A security scanner's value is determined by one thing: whether it
finds the pattern. Everything else — the rule language, the report
format, the CI integration, the dashboard — is packaging around a
core question: given a byte buffer and a set of patterns, which
patterns appear in the buffer and where?

For decades, the answer has been the deterministic finite automaton.
A DFA is a state machine compiled from a set of patterns. You feed
it bytes one at a time. It transitions between states. When it
reaches an accept state, it has found a pattern. The DFA processes
one byte per cycle, regardless of how many patterns are loaded. A
DFA with 10,000 patterns processes bytes at the same speed as a DFA
with 10. This is the property that makes DFA-based scanners scale.

GPU DFA scanning multiplies this advantage by the GPU's parallelism.
A CPU scans bytes sequentially: byte 0, then byte 1, then byte 2.
A GPU scans from every starting byte simultaneously: invocation 0
starts at byte 0, invocation 1 starts at byte 1, invocation 2
starts at byte 2, and so on. Ten thousand invocations scan from ten
thousand starting positions in parallel. The entire input buffer is
scanned in one pass.

`match.dfa_scan` is this inner loop expressed as a vyre operation.
It is not the DFA engine — the engine (`engine::dfa`) handles
resource management, shader specialization, match deduplication,
and readback. The op is the scanning kernel: the code that each
invocation executes. It is a Layer 2 compound operation because it
composes Layer 1 primitives (byte loads, table lookups, comparisons,
atomic writes) into a complete scanning function.

The distinction between the op and the engine matters for
composability. A user who wants end-to-end scanning uses the engine.
A user who wants to embed DFA scanning into a larger GPU program —
perhaps a decode-then-scan pipeline, or a multi-pass scanner that
runs different DFA tables on different regions — uses the op
directly. The op is the reusable piece; the engine is the
convenience wrapper.

## How DFA scanning works on the GPU

To understand the op, you need to understand the data structures it
consumes. A compiled DFA is four arrays:

### The transition table

A flat `u32` array of length `state_count * 256`. Entry
`state * 256 + byte` contains the next state for the given
(state, byte) pair. The table encodes the entire DFA: every state,
every possible input byte, every transition.

```text
next_state = transitions[current_state * 256 + input_byte]
```

Every entry must be `< state_count`. The DFA compiler (from
`warpstate`, `dfajit`, or any other source) is responsible for
producing a valid table. vyre validates the table at compile time
and rejects tables with out-of-range entries.

The 256-wide stride means each state occupies exactly 256 words
(1KB) in the table. This is a deliberate tradeoff: the table is
large (a DFA with 10,000 states uses 10,000 * 256 * 4 = 10MB) but
the lookup is a single array access with no branching. GPU memory
controllers handle large sequential reads efficiently; the table
fits in GPU VRAM with room to spare for inputs up to millions of
states.

### The accept map

A `u32` array indexed by state. `accept_map[state]` is
`0xFFFFFFFF` for non-accepting states and an output-link index for
accepting states. The sentinel value `0xFFFFFFFF` was chosen because
it is the maximum `u32` value and is unlikely to collide with a
valid output-link index (which counts from 0).

### The output links

A table that maps accepting states to pattern IDs. A single accept
state may match multiple patterns (if the DFA was compiled from
overlapping pattern sets). The output-link structure varies by DFA
compiler; the exposed result is always one match row per
(pattern_id, start, end) tuple.

### The pattern lengths

A `u32` array indexed by pattern ID. `pattern_lengths[pattern_id]`
stores the length of the pattern in bytes. This is necessary for
reconstructing the match start position:

```text
match_end = current_byte_offset + 1
match_start = match_end - pattern_lengths[pattern_id]
```

The DFA scanner knows where a match *ends* (the byte where it
reached an accept state) but not where it *started* (the DFA does
not track start positions during forward scanning). The pattern
length bridges the gap.

## The operation

### match.dfa_scan

**Identifier:** `match.dfa_scan`

**Current state:** Legacy WGSL-only. Production shader defined
inline. Does not implement `Op::program()`.

**Signature:** `(Bytes) -> U32`

The simplified signature understates the actual buffer interface.
The DFA scan requires eight bindings:

| Binding | Name | Access | Purpose |
|---------|------|--------|---------|
| 0 | `input_bytes` | ReadOnly | Packed input bytes |
| 1 | `transitions` | ReadOnly | DFA transition table |
| 2 | `accept_map` | ReadOnly | Per-state accept indicator |
| 3 | `matches` | ReadWrite | Match output rows |
| 4 | `match_count` | ReadWrite | Atomic match counter |
| 5 | `params` | Uniform | `{input_len, state_count, max_matches}` |
| 6 | `output_links` | ReadOnly | Accept state → pattern ID mapping |
| 7 | `pattern_lengths` | ReadOnly | Pattern lengths for start reconstruction |

**Workgroup size:** 256.

**The scanning loop:**

Each invocation starts at a different byte offset and walks forward
through the input until the end:

```text
start_offset = global_invocation_id.x
if start_offset >= input_len: return

state = 0
for pos in start_offset .. input_len:
    byte = read_byte(input_bytes, pos)
    state = transitions[state * 256 + byte]
    if accept_map[state] != 0xFFFFFFFF:
        emit_matches(state, pos)
```

This is the entire inner loop. It is simple by design. The
complexity lives in the DFA compiler (which produces the transition
table); the scanner is just a table walker.

**Why every invocation scans to end-of-input:**

A tempting optimization is to have each invocation scan only a
fixed-size window of bytes. Invocation 0 scans bytes 0–255,
invocation 1 scans bytes 256–511, and so on. This would reduce
redundant work.

It would also miss matches. A pattern that starts at byte 200 and
ends at byte 300 would not be found by invocation 0 (which stops
at byte 255) or by invocation 1 (which starts at byte 256 and
therefore starts the DFA in state 0, missing the prefix at bytes
200–255). The match falls in the gap between windows.

Scanning to end-of-input guarantees completeness: every match is
found by at least the invocation that starts at the match's first
byte. The cost is redundant work — invocations near the start of
the input traverse almost the entire input. For a 1MB input with
256-byte workgroups, the first workgroup's invocations each scan
~1MB. Later invocations scan progressively less.

In practice, the redundant work is not as expensive as it sounds.
The transition table is in GPU cache after the first few invocations
read it. The input buffer is read sequentially by each invocation.
The GPU's memory hierarchy handles both patterns efficiently. And
the alternative — missed matches — is not acceptable for a security
scanner.

**Byte reading:**

Input bytes are packed into `array<u32>` using vyre's standard
`Bytes` encoding. Byte `i` is extracted from word `i / 4`, lane
`i % 4`:

```wgsl
fn read_byte(pos: u32) -> u32 {
    let word = input_bytes[pos / 4u];
    return (word >> ((pos % 4u) * 8u)) & 0xFFu;
}
```

Out-of-bounds reads (pos >= input buffer length in words) return
zero via vyre's OOB policy. The scan loop checks `pos < input_len`
to prevent zero-padding bytes from generating false matches. Without
this check, the DFA would process zero bytes beyond the input, which
could reach accept states for patterns that end with zero bytes.

**Match emission:**

When `accept_map[state] != 0xFFFFFFFF`, the invocation emits match
rows. Each row is three consecutive `u32` values:

```text
matches[idx * 3 + 0] = pattern_id
matches[idx * 3 + 1] = pos + 1 - pattern_lengths[pattern_id]   // start (inclusive)
matches[idx * 3 + 2] = pos + 1                                  // end (exclusive)
```

The index `idx` is obtained by `atomicAdd(&match_count, 1)`. The
atomic ensures that concurrent invocations do not overwrite each
other's match rows. If `idx >= max_matches`, the row is not written,
but the counter continues incrementing. This provides two pieces of
information after readback:

1. The actual match count (including overflow).
2. Whether overflow occurred (`match_count > max_matches`).

The host can use the overflow count to decide whether to re-dispatch
with a larger match buffer.

**Match deduplication:**

Because every invocation scans to end-of-input, the same match may
be discovered by multiple invocations. If a pattern starts at byte
100, invocations 0 through 100 will all discover it (assuming they
all reach the accept state at the same position). The op does NOT
deduplicate — it emits all discoveries. Deduplication is the
engine's responsibility (`engine::dfa` sorts and deduplicates after
readback).

This separation is deliberate. Deduplication on the GPU would
require either a hash set (complex, memory-intensive) or a
sort-then-compact pass (a separate dispatch). Both add complexity
to the scanning kernel. Moving deduplication to the host keeps the
kernel simple and lets the engine choose the most efficient
deduplication strategy for the workload.

**Match ordering:**

Matches are emitted in atomic-append order, which is
nondeterministic (it depends on GPU thread scheduling). The engine
sorts matches into the canonical order `(start, end, pattern_id)`
after readback. This sort is the mechanism that restores determinism
— the same input always produces the same sorted match list,
regardless of the GPU's internal scheduling.

## Beyond security scanning

DFA scanning was motivated by pattern matching in security rules, but DFA
engines are used everywhere patterns must be matched at speed:

- **Log analysis.** Searching terabytes of logs for patterns (error codes,
  IP addresses, timestamps, exception traces) is DFA matching. GPU DFA
  processing turns hours of grep into seconds.

- **Network intrusion detection.** Snort, Suricata, and every IDS/IPS
  matches network packets against thousands of signatures using DFA engines.
  GPU acceleration enables line-rate matching on 100Gbps links.

- **DNA sequence matching.** Genomics tools match short read sequences
  against reference genomes using finite automata. GPU DFA scanning
  parallelizes across millions of reads.

- **Content filtering.** Spam detection, content moderation, and data loss
  prevention all match text against pattern databases. The same DFA op
  powers all of them.

- **Compiler lexing.** Lexical analysis is DFA matching — the lexer walks
  a transition table to classify input characters into tokens. A GPU
  lexer built on `match.dfa_scan` could lex millions of source files
  simultaneously.

The DFA scan op is domain-agnostic. It walks a transition table over bytes.
What the patterns represent — malware signatures, log patterns, DNA
sequences, lexer rules — is determined by the DFA compiler, not by the op.

## Future match operations

The spec envisions additional match operations that extract
predicates from match results:

- **match.proximity** — do two patterns appear within N bytes?
- **match.count** — how many of N specified patterns matched?
- **match.scope** — do two patterns appear in the same syntactic
  scope (brace-balanced region)?
- **match.sequential** — do patterns appear in a specific order?
- **match.contains** — does one match region contain another?

These predicates will be added as standalone Layer 2 ops in the
match_ops domain. Each is a Category A composition of primitives,
usable directly from any vyre Program — for example, a taint
analysis that needs proximity information between sources and
sinks consumes `match.proximity` the same way it consumes any
other op.

## Migration to IR-first

Expressing `match.dfa_scan` as an `ir::Program`:

```text
Program {
    buffers: [input, transitions, accept_map, matches, match_count, params, output_links, pattern_lengths],
    workgroup_size: [256, 1, 1],
    entry: [
        Let("gid", InvocationId(0)),
        If(Lt(Var("gid"), Load(params, "input_len")), [
            Let("state", LitU32(0)),
            Loop("pos", Var("gid"), Load(params, "input_len"), [
                Let("byte", read_byte_expr(Var("pos"))),
                Assign("state", Load(transitions, BinOp(Add, BinOp(Mul, Var("state"), LitU32(256)), Var("byte")))),
                If(Ne(Load(accept_map, Var("state")), LitU32(0xFFFFFFFF)), [
                    // emit match logic using Atomic { op: Add } on match_count
                ]),
            ]),
        ]),
    ],
}
```

Every construct — the loop, the conditional, the table lookup, the
atomic counter, the byte extraction — maps directly to IR nodes and
expressions. The migration is mechanical.

## What the conformance suite will verify

**Empty input:** 0 bytes. Expected: 0 matches.

**Single-byte patterns:** One pattern per ASCII character (256
patterns). Input is "the quick brown fox." Expected: matches at
every character position.

**Overlapping patterns:** Patterns "ab", "abc", "abcd". Input is
"abcde". Expected: three matches starting at position 0.

**No matches:** Input that contains no pattern. Expected: 0 matches.

**Maximum input size:** Input at the GPU buffer size limit. Expected:
successful scan or structured resource-exceeded error.

**Transition table with maximum state count:** Stress test for
table lookup performance and OOB handling.

**Determinism:** Same input, same DFA, 100 runs. Expected: identical
sorted match lists.

## Permanence

The operation identifier `match.dfa_scan` is permanent. The
transition table format (`state_count * 256` entries, each
`< state_count`) is permanent. The `0xFFFFFFFF` sentinel for
non-accepting states is permanent. The match output format
`(pattern_id, start, end)` as three packed `u32` values is
permanent. The byte encoding (`Bytes` layout, byte `i` in word
`i/4` lane `i%4`) is permanent.
