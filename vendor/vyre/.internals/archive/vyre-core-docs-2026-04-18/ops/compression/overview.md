# Compression Operations

## The archive problem

A scanner that cannot look inside archives cannot see most of the
software supply chain. npm packages are tarballs inside gzipped
tarballs. Python wheels are ZIP files. Java JARs are ZIP files.
Docker images are layers of tar archives. APK files are ZIP files.
Electron apps bundle entire Node.js installations inside ZIP-like
ASAR archives. At every level of the modern software stack, the code
a scanner needs to examine is compressed inside a container.

The naive approach is to decompress on the CPU, write the
decompressed bytes to disk or memory, and then scan them. This
works but introduces a serial bottleneck: decompression is CPU-bound,
and the GPU sits idle while the CPU unzips. For a scanning workload
that processes thousands of packages per minute, the CPU
decompression time can exceed the GPU scanning time by an order of
magnitude. The GPU is fast enough to scan everything in seconds; the
CPU cannot decompress everything fast enough to feed it.

GPU decompression inverts this bottleneck. The host parses the
archive structure (ZIP central directory, tar headers, LZ4 frame
headers) to identify independent compressed blocks. Each block is
dispatched to a GPU decompression kernel. Thousands of blocks
decompress simultaneously. The decompressed bytes land in GPU
memory, ready for the next pipeline stage — decode, tokenize,
scan — without a round-trip to the CPU.

The parallelism is across blocks, not within blocks. LZ4 and Zstd
are sequential algorithms: each decompressed byte may depend on a
previously decompressed byte (backward references). You cannot
parallelize the decompression of a single block. But you can
parallelize across blocks, and archives contain many blocks. A ZIP
file with 500 entries has 500 independent blocks. A large LZ4 frame
has dozens of independent blocks. The GPU processes all of them at
once.

## What GPU decompression can and cannot do

GPU decompression is effective for algorithms with simple, bounded
control flow and no complex state machines. LZ4 qualifies: its
decompression loop is a simple sequence of literal copies and
backward-reference copies, with lengths encoded in compact token
bytes. The algorithm is small enough to fit in a GPU shader, and the
operations (byte loads, byte stores, memcpy-like copies) are
primitives the GPU handles natively.

Full Zstandard decompression does not qualify — today. Zstd's
compressed blocks use Huffman coding and Finite State Entropy (FSE),
both of which require building and traversing decoding tables that
are specific to each block. These tables have complex construction
algorithms and variable-length entries. Implementing Huffman/FSE
decoding in a GPU shader is technically possible but produces a
shader that is large, slow (branch-heavy, memory-indirect), and
hard to verify for correctness. The performance gain over CPU
decompression would be marginal because the algorithm is not
parallelizable within a single block, and the constant factor of
GPU execution for branch-heavy code is worse than the CPU's.

vyre handles this honestly: `compression.zstd` supports raw blocks
(uncompressed) and RLE blocks (single repeated byte), both of which
are trivial on the GPU. Compressed blocks (Huffman/FSE) are
**rejected** with an explicit error code, and the host falls back
to CPU decompression for those blocks. This is not a failure — it
is a deliberate architectural choice. The GPU handles what it does
well; the host handles what the GPU does not; the system works.

## Operations

### compression.lz4

**Identifier:** `compression.lz4`

**Current state:** Legacy WGSL-only. Production shader defined
inline. Does not implement `Op::program()`.

**Signature:** `(Bytes) -> Bytes`

**What this operation does:** Decompress one independent LZ4 block
per GPU invocation. The input is a compressed block described by a
5-word block descriptor. The output is the decompressed bytes
written to a pre-allocated output region.

**The LZ4 block format:**

An LZ4 block is a sequence of *sequences*. Each sequence has:

1. **A token byte.** The high nibble encodes the literal length
   (0–15). The low nibble encodes the match length minus 4 (0–15,
   so match length is 4–19).

2. **Additional literal length bytes** (if literal length nibble is
   15). Each additional byte adds its value to the literal length.
   A byte less than 255 terminates the chain.

3. **Literal bytes.** Copied directly to the output.

4. **A 2-byte little-endian match offset.** A backward reference
   into the already-decompressed output. Offset 0 is invalid.

5. **Additional match length bytes** (if match length nibble is 15).
   Same encoding as additional literal length.

The decompression loop processes sequences until the input is
exhausted:

```text
while input_pos < compressed_size:
    token = read_byte(input_pos++)
    literal_len = token >> 4
    if literal_len == 15:
        while (extra = read_byte(input_pos++)) == 255:
            literal_len += 255
        literal_len += extra
    copy literal_len bytes from input to output
    if input_pos >= compressed_size: break  // last sequence has no match
    offset = read_u16_le(input_pos); input_pos += 2
    match_len = (token & 0xF) + 4
    if match_len == 19:
        while (extra = read_byte(input_pos++)) == 255:
            match_len += 255
        match_len += extra
    copy match_len bytes from output[output_pos - offset] to output[output_pos]
```

The backward copy may overlap: if `offset < match_len`, the copy
reads bytes that were just written. This is how LZ4 encodes
run-length repetition. The copy must proceed byte-by-byte in this
case (not as a bulk memcpy).

**Block descriptors:**

The host prepares a descriptor buffer with 5 `u32` words per block:

| Word | Content |
|------|---------|
| 0 | Byte offset into `compressed_data` where this block starts |
| 1 | Compressed size in bytes |
| 2 | Byte offset into `decompressed_data` where output should be written |
| 3 | Expected decompressed size in bytes |
| 4 | Flags (bit 0: uncompressed block — copy directly, skip decompression) |

The uncompressed flag (word 4, bit 0) handles LZ4 frames that mark
specific blocks as stored without compression. These blocks are
copied verbatim.

**Error handling:**

Each block writes a 2-word status:

| Word | Content |
|------|---------|
| 0 | Error code |
| 1 | Actual decompressed size (valid even on error, for diagnostics) |

| Error | Code | Meaning |
|-------|------|---------|
| `ERROR_NONE` | 0 | Successful decompression |
| `ERROR_CORRUPT_TOKEN` | 1 | Invalid token byte structure |
| `ERROR_OFFSET_OOB` | 2 | Match offset exceeds available decompressed history |
| `ERROR_OUTPUT_OVERFLOW` | 3 | Decompressed size exceeds expected (descriptor word 3) |
| `ERROR_LITERAL_OVERFLOW` | 4 | Literal run extends past input boundary |
| `ERROR_MATCH_OVERFLOW` | 5 | Match copy extends past output boundary |

Errors do not panic the shader. Every error path writes the error
code, writes the actual output size (which may be partial), and
returns. The host reads the status buffer and decides how to handle
the error — typically by falling back to CPU decompression for the
affected block and flagging the input as potentially corrupt.

**Workgroup size:** 1. Each invocation processes one block. There is
no intra-workgroup cooperation because LZ4 block decompression is
inherently serial — each decompressed byte may depend on a
previously decompressed byte via backward references.

The parallelism is across blocks. A dispatch of 1,000 workgroups
decompresses 1,000 blocks simultaneously. For a ZIP file with 500
entries, each compressed with LZ4, all 500 decompress in one
dispatch.

### compression.zstd

**Identifier:** `compression.zstd`

**Current state:** Legacy WGSL-only. Production shader defined
inline. Does not implement `Op::program()`.

**Signature:** `(Bytes) -> Bytes`

**What this operation does:** Handle Zstandard raw and RLE blocks on
the GPU. Compressed blocks (Huffman/FSE) are rejected with an
explicit error code.

**Why partial support is the right design:**

A compression op that silently produces wrong output for some block
types is worse than a compression op that explicitly rejects what it
cannot handle. The host needs to know which blocks succeeded and
which returned an explicit unsupported-block error. An error code is an honest signal; a
corrupt decompression is a silent data corruption that propagates
through the entire scan pipeline.

vyre will never silently approximate decompression. If a future
version adds Huffman/FSE support to `compression.zstd`, the
decompressed output will be byte-identical to the CPU reference
implementation. Until that guarantee can be made, the block type is
rejected.

**Block types handled:**

| Type | ID | Behavior |
|------|----|----------|
| Raw | 0 | Direct byte copy from input to output. Trivial — no decompression needed. |
| RLE | 1 | Fill output with a single repeated byte. The byte is the first byte of the block payload. |
| Compressed | 2 | **Rejected.** Returns `ERROR_UNSUPPORTED_COMPRESSED_BLOCK`. |

**Error codes:**

| Error | Code | Meaning |
|-------|------|---------|
| `ERROR_NONE` | 0 | Successful handling |
| `ERROR_CORRUPT_BLOCK` | 1 | Invalid block structure |
| `ERROR_OUTPUT_OVERFLOW` | 2 | Output exceeds expected size |
| `ERROR_RLE_PAYLOAD_MISSING` | 3 | RLE block with no payload byte |
| `ERROR_UNSUPPORTED_COMPRESSED_BLOCK` | 4 | Huffman/FSE block (returns explicit error) |

**Block descriptor and status format:** Same as LZ4.

**Workgroup size:** 1.

## Beyond security scanning

Decompression was motivated by scanning inside archives, but compression
is everywhere:

- **Data lakes.** Parquet, ORC, and other columnar formats use LZ4, Zstd,
  and Snappy internally. GPU decompression of columnar pages enables
  GPU-native query processing without CPU decompression bottlenecks.

- **Database storage.** RocksDB, LevelDB, and other LSM-tree databases
  compress SSTables. GPU decompression could accelerate bulk reads.

- **Streaming media.** Video frames are compressed. While video codecs are
  more complex than LZ4, the block-decompression pattern (independent
  blocks processed in parallel) applies to many intermediate formats.

- **Scientific data.** HDF5, NetCDF, and FITS files use various
  compression algorithms internally. GPU decompression enables direct
  GPU-side analysis without CPU decompression passes.

- **Backup and archival.** Restoring from compressed backups is
  decompression-bound. GPU-accelerated restore could reduce recovery time
  from hours to minutes.

The compression ops decompress byte streams. What those bytes represent —
source code, database pages, scientific measurements — is irrelevant to
the decompression algorithm.

## Composition in the pipeline

Compression ops sit at the front of the pipeline, before everything
else:

```text
archive bytes → parse structure (CPU) → GPU decompress → decode → tokenize → DFA scan → eval
```

The host parses the archive structure on the CPU because archive
formats (ZIP, tar, LZ4 frame) have complex variable-length headers
that are not parallelizable. The host extracts block descriptors —
(offset, size, output_offset, expected_size, flags) — and uploads
them to the GPU. The GPU decompresses all blocks in one dispatch.
The decompressed bytes are in GPU memory, ready for the next stage.

**Multi-layer archives:** A ZIP file inside a ZIP file requires two
decompression dispatches. The first dispatch decompresses the outer
ZIP entries. The host parses the decompressed bytes to identify
inner archive entries. The second dispatch decompresses the inner
entries. Each layer is one dispatch. The depth is unlimited in
principle, limited by GPU memory in practice.

**Hybrid CPU/GPU decompression:** For Zstd archives where some
blocks are compressed (Huffman/FSE) and some are raw/RLE, the
pipeline uses a hybrid approach:

1. Dispatch GPU decompression for all blocks.
2. Read back the status buffer.
3. For blocks with `ERROR_UNSUPPORTED_COMPRESSED_BLOCK`, decompress
   on the CPU.
4. Upload the CPU-decompressed bytes to the GPU.
5. Continue the pipeline with all blocks decompressed.

The hybrid approach maximizes GPU utilization for the blocks it can
handle while falling back gracefully for blocks it cannot.

## Migration to IR-first

The LZ4 shader is among the most complex ops to migrate because the
decompression loop has:

- Variable-length token parsing (the literal/match length encoding
  with 255-byte extension chains).
- Backward-reference copies that may overlap.
- Multiple error exit paths.
- Byte-level buffer access at arbitrary offsets.

Expressing this in IR requires:

- `Node::Loop` with a dynamic upper bound (input exhaustion).
- Nested `Node::Loop` for 255-byte extension chains.
- `Node::If` for each error condition.
- `Expr::Load` and `Node::Store` for byte-level access.
- Careful handling of the overlapping backward copy (a byte-by-byte
  loop, not a bulk copy).

The IR supports all of this. The migration will produce a large
`ir::Program` (dozens of nodes), but each node is simple. The
payoff is the same as for all legacy ops: retargeting,
conformance coverage, and the possibility of optimization
(e.g., the IR optimizer could detect non-overlapping backward
copies and replace byte-by-byte loops with bulk copies).

## What the conformance suite will verify

**LZ4:**
- Empty block (0 compressed bytes). Expected: 0 decompressed bytes.
- Block with only literals (no match sequences). Expected: literal
  bytes copied verbatim.
- Block with a match that does not overlap. Expected: correct copy.
- Block with a match that overlaps (offset < match_len). Expected:
  correct byte-by-byte RLE expansion.
- Block with maximum literal length (15 + 255*N). Expected: correct
  extended length parsing.
- Block with maximum match length (19 + 255*N). Expected: correct
  extended length parsing.
- Corrupt block (truncated input, invalid offset). Expected:
  appropriate error code, no panic.
- Uncompressed block (flag bit set). Expected: verbatim copy.

**Zstd:**
- Raw block. Expected: verbatim copy.
- RLE block. Expected: repeated byte fill.
- Compressed block. Expected: `ERROR_UNSUPPORTED_COMPRESSED_BLOCK`.
- Corrupt block. Expected: `ERROR_CORRUPT_BLOCK`, no panic.

**Determinism:** Same blocks, 100 runs. Expected: identical output.

## Permanence

The operation identifiers (`compression.lz4`, `compression.zstd`)
are permanent. The block descriptor format (5 words per block) is
permanent. The error codes are permanent. The status format (2 words
per block) is permanent.

The Zstd limitation (compressed blocks rejected) is documented
behavior. If Huffman/FSE support is added, it will be either a new
op (`compression.zstd_full`) or a new version of the existing op
with an incremented `version()`. The existing behavior — raw/RLE
handled, compressed rejected — will remain available at version 1.
