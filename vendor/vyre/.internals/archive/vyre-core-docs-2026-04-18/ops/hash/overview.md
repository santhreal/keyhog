# Hash Operations

Hash operations provide deterministic, composable hashing primitives used
throughout vyre for O(1) lookup, deduplication, and fingerprinting. They are
implemented as IR-first compound ops built entirely from Layer 1 primitives.

## The O(1) lookup that makes scanning possible

A security scanner carries thousands of signatures. Each signature
describes a pattern, a condition, and a severity. When the scanner
encounters a byte sequence in a file, it needs to know: does this
sequence match any of my thousands of signatures? The naive approach
— compare the sequence against each signature — is O(N) per lookup
where N is the signature count. At 10,000 signatures and millions
of byte sequences per file, that is tens of billions of comparisons.
Even on a GPU, this is slow.

Hashing makes it O(1). Hash the byte sequence. Look up the hash in
a table. If the table has an entry, the sequence matches a
signature (modulo collision handling). One hash computation per
sequence, one table lookup per sequence, regardless of how many
signatures are loaded. The signature count drops out of the
per-sequence cost entirely.

This is not a novel insight. Every serious scanning engine uses
hash-based lookup. The insight that matters for vyre is that hashing
is a *composable primitive* — it appears in DFA result processing
(match hashing for deduplication), in decode result processing
(hash decoded payloads for known-bad signature matching), in graph
analysis (hash node labels for efficient comparison), in
tokenization (hash identifier strings for keyword lookup), and in
every other pipeline stage that needs to compare byte sequences
against a known set.

If every pipeline stage reimplements hashing, the implementations
drift. Different hash functions, different seed handling, different
collision behavior. A hash computed in the decode stage is not
comparable to a hash computed in the match stage because they used
different algorithms. The pipeline cannot compose.

vyre provides hash operations as Layer 2 compound ops to eliminate
this drift. One hash function, one implementation, one specification,
used everywhere. A hash computed by `hash.fnv` in the decode stage
is bit-identical to a hash computed by `hash.fnv` in the match stage
for the same input bytes. The pipeline composes because the hashing
is standardized.

## Why hashing is the ideal first IR-first compound op

Hash operations are pure compositions of Layer 1 primitives. FNV-1a
is a loop containing one XOR and one multiply per byte. CRC32 is a
loop containing one XOR and one table lookup per byte. Rolling hash
is a loop containing one add, one subtract, and one multiply per
byte. There are no buffer management complexities, no multi-binding
layouts, no atomic coordination, no barriers.

This makes hash ops the ideal candidates for proving the IR
composition system works at the compound op level. If `hash.fnv`
composes correctly — if a `Call("hash.fnv", [region])` inside
another op's `program()` inlines correctly and the lowered shader
produces the same bytes as a hand-written FNV loop — then the
composition system works for compound ops, and more complex ops
(decode, graph, match) can follow the same pattern with confidence.

## Current state

The hash module (`ops/hash/mod.rs`) contains three implemented
operations — `hash.fnv1a32`, `hash.crc32c`, and `hash.murmur3_32` —
all implemented IR-first with conform specs, CPU references, and WGSL
kernels. Additional hash algorithms (rolling hash, entropy bucketing)
are planned and will follow the same IR-native pattern.

## Planned operations

### hash.fnv

**Planned identifier:** `hash.fnv`

**Planned signature:** `(Bytes) -> U32` for FNV-1a 32-bit

**Specification:** FNV-1a hash as defined by Fowler, Noll, and Vo.
The algorithm processes input bytes one at a time:

```text
hash = 0x811c9dc5          (FNV offset basis for 32-bit)
for each byte b in input:
    hash = hash XOR b
    hash = hash * 0x01000193    (FNV prime for 32-bit)
return hash
```

The algorithm is deterministic, produces a 32-bit output for any
input length, and has no configuration parameters. Two
implementations that follow this specification produce identical
output for identical input. This is the property vyre requires.

**Why FNV-1a and not SHA-256, BLAKE3, xxHash, or MurmurHash:**

FNV-1a has three properties that make it uniquely suitable for
vyre's requirements:

1. **Simplicity.** The algorithm is three operations per byte: XOR,
   multiply, advance. It has no rounds, no mixing functions, no
   finalization steps. This means the IR composition is trivial —
   one `Node::Loop` containing one `BinOp::BitXor` and one
   `BinOp::Mul`. The lowered shader is indistinguishable from a
   hand-written loop. There is no abstraction overhead because there
   is almost no abstraction.

2. **Integer-only.** FNV-1a uses only XOR and wrapping multiply on
   `u32`. No floats, no 64-bit intermediates (for the 32-bit
   variant), no platform-dependent behavior. The GPU produces
   bit-identical results to the CPU for every input because both
   are doing the same modular arithmetic.

3. **No seed or salt.** The offset basis is a fixed constant. There
   is no randomization. The same input always produces the same
   hash on every machine, every run, every backend. This aligns
   with vyre's determinism guarantee — there is no hidden state
   that could cause divergence.

FNV-1a is not cryptographically secure. It is not the fastest hash
for large inputs. It does not have the best avalanche properties.
None of these matter for vyre's use case. vyre needs a hash that is
deterministic, integer-only, simple to compose, and produces
well-distributed values for the byte patterns encountered in
security scanning (identifiers, URLs, file paths, hex strings).
FNV-1a meets all four requirements.

Cryptographic hashing (SHA-256, BLAKE3) may be added as separate
ops if needed for integrity verification or signature matching.
They would be separate identifiers with separate specifications.

**IR composition:**

```text
Program {
    buffers: [
        input: binding 0, ReadOnly, U32 (Bytes layout),
        output: binding 1, ReadWrite, U32,
        params: binding 2, Uniform,   // params.x = byte_length
    ],
    workgroup_size: [64, 1, 1],
    entry: [
        Let("gid", InvocationId(0)),
        If(Lt(Var("gid"), BufLen("output")), [
            Let("hash", LitU32(0x811c9dc5)),
            Loop("i", LitU32(0), Load(params, 0), [
                Let("byte", extract_byte(Load(input, Div(Var("i"), 4)), Mod(Var("i"), 4))),
                Assign("hash", Mul(BitXor(Var("hash"), Var("byte")), LitU32(0x01000193))),
            ]),
            Store("output", Var("gid"), Var("hash")),
        ]),
    ],
}
```

Every operation in this program is a Layer 1 primitive. The
composition is Category A: it inlines completely at lowering time.
The generated WGSL is identical to a hand-written FNV-1a loop. The
abstraction exists at IR construction time and vanishes at shader
emission time.

### hash.rolling

**Planned identifier:** `hash.rolling`

**Planned signature:** `(Bytes) -> U32[]` (one hash per byte
position, for a given window size)

**Specification:** Rabin-Karp style rolling hash. For a window of
size W, compute a hash for every contiguous W-byte substring:

```text
output[i] = hash(input[i .. i + W])
```

The rolling property means each hash can be computed from the
previous hash in O(1) instead of recomputing from scratch:

```text
hash[i+1] = (hash[i] - input[i] * base^(W-1)) * base + input[i+W]
```

The base and modulus are fixed constants (specified in the op). The
`base^(W-1)` value is precomputed and passed as a parameter.

**Why rolling hash:** Rolling hashes enable content-defined chunking
(CDC) for deduplication, sliding-window pattern matching for
approximate search, and efficient plagiarism/similarity detection.
A taint analysis engine that needs to find "code that is similar to
a known-vulnerable pattern" can use rolling hash to identify
candidate regions without comparing every substring character by
character.

### hash.crc

**Planned identifier:** `hash.crc`

**Planned signature:** `(Bytes) -> U32`

**Specification:** CRC32 using the standard polynomial `0xEDB88320`
(reflected form of ISO 3309 / ITU-T V.42 / Ethernet CRC32). The
algorithm uses a 256-entry lookup table:

```text
crc = 0xFFFFFFFF
for each byte b in input:
    crc = table[(crc XOR b) AND 0xFF] XOR (crc >> 8)
return crc XOR 0xFFFFFFFF
```

The table contains precomputed CRC values for each byte value. The
table is constant and is the same for every invocation.

**Why CRC32:** CRC32 appears in ZIP files (each entry has a CRC32
for integrity verification), PNG chunks, Ethernet frames, and many
binary formats. A scanner that verifies archive integrity uses CRC32
to detect tampered or corrupt entries. A scanner that matches on
file content hashes uses CRC32 as a fast first-pass filter before
more expensive matching.

**Calling convention:** V2. The lookup table is the `lookup` buffer.

### hash.entropy

**Planned identifier:** `hash.entropy`

**Planned signature:** `(Bytes) -> U32` (entropy bucket)

**Specification:** Shannon entropy of a byte buffer, quantized into
integer buckets. The algorithm counts the frequency of each byte
value (0–255), computes the Shannon entropy formula
`H = -sum(p_i * log2(p_i))` using fixed-point arithmetic (no
floats), and maps the result to a bucket index.

**Why integer entropy, not float:** GPU floats are nondeterministic
across vendors. A float entropy value of `7.831` on NVIDIA might be
`7.832` on AMD due to different rounding in the `log2`
approximation. vyre cannot accept this because the entropy value
feeds into rule conditions (`if entropy > 7.5 then suspicious`),
and a rule that fires on NVIDIA but not on AMD violates the
determinism promise.

Integer-bucketed entropy eliminates the problem. The bucket
boundaries are fixed constants. A byte buffer either falls in
bucket 7 or bucket 8, and both backends agree because the bucket
assignment uses only integer arithmetic and comparison. The
precision loss (bucket granularity instead of continuous entropy) is
acceptable because security rules do not need sub-bit entropy
precision — they need "is this region high-entropy (encrypted/
compressed/random) or low-entropy (plaintext/code)?"

The bucket boundaries are part of the op specification and are
permanent once defined. They must produce identical bucket
assignments across all backends for identical input bytes.

`hash.entropy` is consumed directly as an IR op — any pipeline
that needs entropy bucketing builds it into a `Program` via
`Expr::Call("hash.entropy", ...)`. There is no separate engine
or runtime to invoke.

## What makes hash ops different from other compound ops

Hash ops are the simplest compound ops in vyre. They have:

- **One input buffer, one output buffer.** No complex multi-binding
  layouts.
- **No atomics.** Each invocation hashes one region and writes one
  output value. No cross-invocation coordination.
- **No barriers.** No workgroup-level synchronization.
- **No workgroup memory.** No shared state between invocations.
- **Deterministic by construction.** Integer arithmetic only. No
  floats, no scheduling dependence, no reduction ordering.
- **Pure Category A composition.** Every hash algorithm is a loop
  of Layer 1 primitives. Nothing to inline but the loop body.

This simplicity is why hash ops are the ideal proving ground for
IR-first compound op development. If the IR composition system
works for hash ops — if `Call("hash.fnv", args)` inlines correctly,
if the lowered shader matches the hand-written equivalent, if the
parity harness passes — then the system works, and more complex
compound ops can follow with confidence.

## Permanence

Operation identifiers listed in this chapter are planned, not yet
permanent. They become permanent when the first conforming
implementation is published and passes the conformance suite.

Once published:

- `hash.fnv`'s offset basis (`0x811c9dc5`) and prime (`0x01000193`)
  are permanent. The same input produces the same hash forever.
- `hash.crc`'s polynomial (`0xEDB88320`) and initialization
  (`0xFFFFFFFF`) are permanent.
- `hash.entropy`'s bucket boundaries are permanent.
- `hash.rolling`'s base and modulus are permanent.

These are mathematical constants. They do not have "versions." They
do not "evolve." A hash function that changes its output for the
same input is not a new version — it is a different function with a
different identifier.

## Implemented hash operations

The following hash operations have conform specs with both CPU references
and real WGSL kernels. They are registered in the conform registry and
pass exhaustive u8 verification.

### `hash.fnv1a32` — FNV-1a 32-bit

The workhorse non-cryptographic hash. Offset basis `0x811c9dc5`, prime
`0x01000193`. One byte at a time: XOR then multiply. Used by warpscan
and keyhog for fast string hashing.

WGSL kernel: processes `input.data[]` via word/byte extraction, pure u32
arithmetic. No lookup tables needed.

### `hash.crc32c` — CRC32C (Castagnoli)

Polynomial `0x82F63B78` (reflected). Initialize `0xFFFFFFFF`, XOR each
byte, 8-bit loop with `select()` for the polynomial conditional, finalize
with `XOR 0xFFFFFFFF`. Used in iSCSI, SCTP, ext4, network protocols.

WGSL kernel: bit-by-bit loop with `select(0u, poly, (crc & 1u) != 0u)`
— branchless on GPU.

### `hash.murmur3_32` — MurmurHash3 x86 32-bit

Body processes aligned 4-byte blocks via `input.data[i]` directly (no
byte extraction needed for the body). Tail handles 1-3 remaining bytes.
Finalization: `fmix32` with two multiply-shift rounds. Seed fixed at 0
for deterministic conformance.

WGSL kernel: handles body + tail + finalization. The tail uses the byte
extraction pattern for unaligned bytes.

## See also

- [Operations Overview](../overview.md)
- [Primitive Overview](../primitive/overview.md)
- [OpSpec Trait](../trait.md)

