# Decode Operations

Decode operations transform encoded byte sequences into raw bytes so that
later pipeline stages can scan them without reimplementing parsers. vyre
provides base64, hex, URL percent-encoding, and Unicode escape decoders
as standard Layer 2 compound ops.

## The layer you do not see

Every serious security vulnerability discovered through static
analysis in the last two decades has had a common prerequisite: the
scanner had to read the payload. This sounds trivial. It is not.

A payload that reads `eval(atob("ZG9jdW1lbnQud3JpdGUoIjxpbWcgc3Jj"))` 
does not contain the string `document.write`. A scanner looking for
`document.write` will not find it. The payload is base64-encoded.
The scanner must decode the base64, then scan the decoded bytes, to
discover that the payload contains a DOM XSS sink. If the scanner
cannot decode, the scanner cannot see.

This is not a hypothetical. The majority of real-world malware
payloads, web exploits, and supply-chain attacks use at least one
layer of encoding. Base64 is the most common (JavaScript `atob()`,
email attachments, data URIs, JWT payloads, embedded binaries in
config files). URL percent-encoding is pervasive in web attacks
(SQL injection, XSS, path traversal, SSRF — all commonly
percent-encoded to bypass WAFs). Hex encoding appears in shellcode
(`\x41\x42`), obfuscated scripts, and binary data in text formats.
Unicode escapes hide identifiers in JavaScript
(`\u0065\u0076\u0061\u006c` is `eval`), Java
(`\u0072untime.exec`), and Python. A scanner that cannot decode any
of these is a scanner that cannot see most real attacks.

The question is not whether a scanner decodes. Every scanner decodes.
The question is where the decoding happens.

If decoding lives in the scanner's application code, every scanner
reimplements it. Every reimplementation handles edge cases
differently. Every reimplementation is tested to whatever standard
the scanner author had time for. Every reimplementation is a
potential source of divergence: scanner A decodes a malformed base64
region one way, scanner B decodes it another way, and neither knows
the other exists. The decoded bytes differ, the scan results differ,
and the user has no way to know which is right.

If decoding lives in the substrate — in vyre — it is implemented
once, tested against a specification, verified for byte-identical
output across backends, and inherited by every scanner that uses
vyre. The decode operations become infrastructure in the same way
that `malloc` is infrastructure: nobody thinks about them, nobody
reimplements them, and everybody depends on them being correct.

That is why decode operations are Layer 2 ops in vyre. They are not
security-specific. They are byte transformations with precise
specifications (RFC 4648 for base64, RFC 3986 for percent-encoding,
the Unicode standard for escape sequences). They happen to be
critical for security scanning, but they would be equally useful in
a data pipeline, a network analyzer, or a format converter. The
substrate does not care what you build on it. It provides the
primitive and gets out of the way.

## Why decoding on the GPU

A CPU-based scanner decoding encoded regions has a serial bottleneck.
Each region is decoded one at a time. A source code repository with
100,000 JavaScript files, each containing dozens of encoded strings,
produces millions of decode operations. Decoding them serially on the
CPU takes seconds — seconds that the GPU is idle, waiting for decoded
bytes to scan.

GPU decoding eliminates the bottleneck by exploiting the structure of
the problem. Each encoded region is independent. Base64 decoding
region A has no dependency on base64 decoding region B. They can
execute simultaneously. A GPU with 10,000 active invocations decodes
10,000 regions in the time the CPU decodes one.

The decoded bytes are already in GPU memory when the decode completes.
The DFA engine does not need to wait for a host-to-device transfer.
The pipeline flows: file bytes arrive on GPU → encoded regions are
identified → GPU decode dispatches → decoded bytes are scanned by
DFA → matches are scattered → rules are evaluated. No round-trip to
the CPU. No transfer latency. No serial bottleneck.

This is the performance argument. But there is a subtler argument
that matters more for vyre specifically: determinism. A decode
operation that runs on the CPU is outside vyre's conformance
boundary. vyre cannot prove that two different CPU implementations
of base64 decode produce the same bytes for the same input. If the
decode happens on the GPU through a vyre op, it is inside the
conformance boundary. The parity harness can verify it. The
conformance suite can certify it. The determinism promise extends
from raw bytes through decoding through scanning through evaluation.
The entire pipeline is provably identical across backends.

## Current state and the migration debt

The decode operations are implemented as a mix of IR-first compositions
and legacy WGSL shaders. `decode.base64`, `decode.hex`, `decode.url`,
and `decode.unicode` have conform specs and production WGSL kernels.
Some operations, such as `decode.base32` and `decode.base64url`, are
being migrated from legacy WGSL includes to IR-first `program()`
implementations. The migration path is:

1. Write an `ir::Program` implementation that expresses the decoding
   algorithm using IR constructs (loops, byte loads, lookup tables,
   conditional branches, output stores).
2. Write a CPU reference function that computes the same result in
   plain Rust.
3. Run the parity harness to verify byte-identical output against the
   CPU reference.
4. Wire the op through the `OpSpec` builder pattern and remove the
   legacy WGSL include once all consumers migrate.

What this means concretely:

1. **No IR-level composition.** A decode op cannot be composed with
   a hash op or a DFA scan op at the IR level. You cannot write
   `Call("decode.base64", [region])` inside another op's `program()`
   and have the lowering inline the decoder. Instead, you must
   dispatch the decoder as a separate GPU pass, write the decoded
   bytes to an intermediate buffer, and dispatch the next pass to
   read them. This costs a buffer allocation and a synchronization
   point that IR-level composition would eliminate.

2. **No retargeting.** The decode ops only work on the WGSL/wgpu
   backend. A future SPIR-V backend, CUDA backend, or Metal backend
   would need its own copy of the decoder shader. Without IR, there
   is no single source of truth for the decoder's semantics — each
   backend's shader is a separate implementation that must be
   independently tested for equivalence.

3. **No optimization.** The WGSL string is opaque. The IR optimizer
   cannot constant-fold branches, eliminate dead lookup table
   entries, or fuse adjacent operations. The shader is what it is.

4. **No conformance coverage.** Without `program()`, the decode ops
   cannot participate in the parity harness. There is no CPU
   reference function that the harness can compare against the GPU
   output for every input class. The ops are tested by their own
   integration tests, not by the systematic conformance
   infrastructure that tests primitive ops.

The migration path is straightforward in principle:

1. Write an `ir::Program` implementation for each decode op that
   expresses the decoding algorithm using IR constructs (loops, byte
   loads, lookup tables, conditional branches, output stores).
2. Write a CPU reference function for each decode op that computes
   the same result using plain Rust.
3. Run the parity harness: generate inputs, dispatch the IR-lowered
   shader, run the CPU reference, compare bytes.
4. Verify the IR-lowered WGSL produces byte-identical output to the
   legacy WGSL on a large corpus of real encoded regions.
5. Wire decode ops through the OpSpec builder pattern.
6. Delete the legacy WGSL includes after all consumers migrate.

The migration is not blocked by any IR limitation. The IR supports
loops, byte-level buffer access, lookup tables (V2 convention),
conditional branches, and output stores — everything a decoder
needs. The migration is blocked by engineering bandwidth and by the
priority of stabilizing the IR and conformance harness first. When
the primitives are proven and the harness is trusted, the decode ops
are among the first candidates for migration because they exercise
the IR composition system in a real-world context.

## Operations

### decode.base64

**Identifier:** `decode.base64`

**Signature:** `(Bytes) -> Bytes`

**Specification:** RFC 4648 base64 decode. Each invocation processes
one contiguous region of base64-encoded ASCII bytes and produces the
decoded binary output.

The base64 alphabet maps 64 ASCII characters to 6-bit values. Four
encoded characters produce three decoded bytes. Padding (`=`)
indicates the final group is shorter than four characters.

The decoder handles the full RFC 4648 alphabet (A-Z, a-z, 0-9, +, /)
plus the URL-safe variant (- and _ instead of + and /). Invalid
characters outside both alphabets are treated as zero values,
preserving scan robustness over strict compliance. This is a
deliberate design choice: a malware author who inserts garbage
characters into a base64 payload should not prevent the scanner from
recovering as much of the payload as possible. Strict compliance
would reject the entire region; robust decoding recovers the valid
portions.

**Why base64 specifically:** Base64 is not merely common. It is the
*default* encoding for binary-in-text contexts across the entire
software ecosystem. JavaScript's `atob()` and `btoa()`. Python's
`base64` module. Java's `Base64` class. Every email attachment
(MIME). Every JWT token. Every data URI. Every PEM certificate.
Every embedded binary in JSON or YAML. A scanner without base64
decode is a scanner that cannot read half of the inputs it
encounters in the wild.

**Calling convention:** V1. Input buffer contains packed bytes
(little-endian u32 words per vyre's `Bytes` layout). Output buffer
receives decoded bytes in the same packing.

**GPU dispatch:** One invocation per encoded region. The host
identifies region boundaries (start offset, length) before dispatch.
The boundary identification is a host responsibility because
identifying base64 regions requires heuristics (looking for
contiguous base64 characters between delimiters) that are
domain-specific and vary by file format.

**Dependencies:** None. Base64 decoding is a self-contained lookup
table operation. The lookup table (64 entries mapping ASCII code
points to 6-bit values) fits in registers or local memory. No
external buffer binding is needed beyond V1's input/output/params.

**IR composition (planned):** When migrated to IR-first, the decoder
becomes a bounded loop over input bytes with a lookup table. The
core logic is:

```text
Loop { var: i, from: 0, to: encoded_len, step: 4,
    body: [
        Let { name: "a", value: lookup[Load(input, i+0)] },
        Let { name: "b", value: lookup[Load(input, i+1)] },
        Let { name: "c", value: lookup[Load(input, i+2)] },
        Let { name: "d", value: lookup[Load(input, i+3)] },
        Store(output, j+0, (a << 2) | (b >> 4)),
        Store(output, j+1, ((b & 0xF) << 4) | (c >> 2)),
        Store(output, j+2, ((c & 0x3) << 6) | d),
    ]
}
```

Every operation in the loop body is a Layer 1 primitive: `Shl`,
`Shr`, `BitOr`, `BitAnd`, `Load`, `Store`. The decoder is Category
A — the composition inlines completely at lowering time.

### decode.hex

**Identifier:** `decode.hex`

**Signature:** `(Bytes) -> Bytes`

**Specification:** Hexadecimal byte decode. Each pair of hex ASCII
characters (0-9, a-f, A-F) decodes to one byte. Mixed case is
accepted. Invalid hex characters produce zero nibbles. Odd-length
input treats the final character as the high nibble of the last
byte, zero-extending the low nibble.

**Why hex specifically:** Hex encoding is the language of raw bytes
in source code. Shellcode payloads use `\x41\x42\x43`. Hash
literals are hex strings. Binary data in configuration files is
hex-encoded. Obfuscated JavaScript concatenates hex-encoded strings.
Hex is the second most common encoding after base64, and in
binary-analysis contexts (malware, firmware, shellcode) it is the
most common.

**IR composition (planned):** Two loads per output byte, each
through a 16-entry nibble lookup table. Pure Layer 1 primitives.

### decode.url

**Identifier:** `decode.url`

**Signature:** `(Bytes) -> Bytes`

**Specification:** URL percent-encoding decode per RFC 3986. `%XX`
sequences (where XX is two hex digits) are replaced with the
corresponding byte. Characters that are not percent-encoded pass
through unchanged.

The decoder does not decode `+` as space by default. The `+` as
space convention is specific to `application/x-www-form-urlencoded`
(HTML form submissions), not to RFC 3986 percent-encoding in general.
A future variant op (`decode.url_form`) may handle the form-encoded
convention separately.

**Why URL specifically:** URL encoding is the encoding of the web
attack surface. SQL injection payloads are percent-encoded to bypass
input filters: `' OR 1=1--` becomes `%27%20OR%201%3D1--`. XSS
payloads are percent-encoded: `<script>` becomes
`%3Cscript%3E`. Path traversal uses `%2e%2e%2f` for `../`. SSRF
uses encoded URLs inside URLs. A web security scanner that does not
decode percent-encoding misses the majority of web attack patterns
because the attacker's first defense is always "encode the payload
so the WAF doesn't match it."

**IR composition (planned):** A loop over input bytes. When `%` is
encountered, the next two bytes are decoded as hex nibbles (reusing
the hex nibble lookup from `decode.hex`). Non-`%` bytes pass through.
Pure Layer 1 primitives plus a conditional branch.

### decode.unicode

**Identifier:** `decode.unicode`

**Signature:** `(Bytes) -> Bytes`

**Specification:** Unicode escape sequence decode. Handles:

- `\xNN` — single-byte hex escape (2 hex digits → 1 byte)
- `\uNNNN` — BMP code point (4 hex digits → UTF-8 encoding)
- `\UNNNNNNNN` — full code point (8 hex digits → UTF-8 encoding)

Non-escape bytes pass through unchanged. Invalid escape sequences
(insufficient hex digits after `\x`, `\u`, or `\U`) pass through
unchanged, preserving scan robustness.

**Why unicode specifically:** JavaScript obfuscation is the most
common source of false negatives in web security scanning. The
technique is simple: replace every character in a sensitive
identifier with its Unicode escape. `eval` becomes
`\u0065\u0076\u0061\u006c`. `Function` becomes
`\u0046\u0075\u006e\u0063\u0074\u0069\u006f\u006e`. The obfuscated
code is semantically identical — JavaScript interprets Unicode
escapes at parse time — but a scanner matching on literal strings
sees gibberish.

Java has the same problem: `Runtime.exec` becomes
`R\u0075ntim\u0065.ex\u0065c`. Partial escaping is even harder to
match because the scanner would need to enumerate all possible
escape positions. Unicode decode normalizes the text so the scanner
sees the original identifiers.

**IR composition (planned):** A loop over input bytes with a state
machine tracking whether we are inside an escape sequence and how
many hex digits remain. The UTF-8 encoding of decoded code points
uses shift and mask operations. Complex but entirely Layer 1
primitives.

## Beyond security scanning

The decode operations were motivated by security scanning, but encoding
and decoding are universal problems. Every domain that processes data from
external sources encounters encoded content:

- **Data pipelines.** ETL jobs processing JSON, CSV, and XML routinely
  encounter base64-encoded binary fields, URL-encoded query parameters, and
  Unicode-escaped strings. GPU-accelerated decode removes the serial
  bottleneck from data ingestion.

- **Network analysis.** HTTP traffic contains URL-encoded paths and query
  strings, base64-encoded authentication headers, and Unicode-escaped JSON
  payloads. Decoding at wire speed requires parallelism.

- **Forensics and e-discovery.** Email archives contain millions of MIME
  attachments, each base64-encoded. Decoding them for keyword search at
  GPU speed turns a day-long job into a minutes-long job.

- **Format conversion.** Converting between data formats (JSON to binary,
  text to binary, encoded to raw) is a decode operation. Any format
  converter that processes multiple records can parallelize the decode.

The decode ops are domain-agnostic byte transformations. They happen to be
critical for security scanning because attackers encode payloads. They are
equally useful anywhere encoded data must be processed at scale.

## How decode operations compose in the pipeline

The scan pipeline has a natural ordering, and decode operations sit
between ingestion and pattern matching:

```text
file bytes → identify encoded regions → GPU decode → DFA scan → eval
```

The first step — identifying encoded regions — is a host
responsibility. The host uses heuristics or structural analysis to
find regions that look encoded: contiguous base64 characters between
quotes, hex sequences after `\x` prefixes, `%` followed by hex
digits in URL contexts. These heuristics are domain-specific (a
JavaScript scanner identifies different regions than a network
packet analyzer) and are outside vyre's scope.

The second step — GPU decode — dispatches one invocation per
identified region. All regions decode simultaneously. The decoded
bytes land in GPU memory, ready for the next stage.

The third step — DFA scan — runs over the decoded bytes as if they
were original file content. The DFA engine does not know or care
that the bytes were decoded. It scans bytes and reports matches.
The scanner that identifies `document.write` in decoded base64
output catches the same pattern it would catch in plaintext. The
decode layer is transparent.

**Multi-layer encoding:** Real-world payloads often use multiple
encoding layers. A payload might be base64-encoded, then URL-encoded
for transmission. Decoding requires two passes: `decode.url` first
(to remove the percent-encoding), then `decode.base64` (to decode
the base64). The pipeline handles arbitrary nesting by chaining
decode dispatches. Each dispatch reads the previous stage's output
and writes to a new output buffer. The depth is limited only by GPU
memory for intermediate buffers.

**Decode-then-hash composition (future):** When decode ops gain
`program()` implementations, a single composed program can decode a
region and hash the decoded bytes without an intermediate buffer.
The IR inlines both operations into one shader: the decode loop
feeds its output directly into the hash accumulator. This eliminates
the buffer write, the buffer read, and the synchronization between
dispatches. It is the concrete payoff of IR-first architecture for
compound ops.

## What the conformance suite will verify

When decode ops are migrated to IR-first, they participate in the
parity harness with the following input classes:

**For base64:**
- Empty input (0 bytes). Expected output: empty.
- Input that is a multiple of 4 characters. Clean decode, no
  padding issues.
- Input with 1, 2, or 3 padding characters. Tests padding handling.
- Input with invalid characters interspersed. Tests robust decoding
  (invalid characters produce zero nibbles, not decode failure).
- Input of every length from 0 to 256. Tests boundary handling
  around the 4-character group boundary.
- Input containing only `=` characters. Degenerate case.
- Input alternating between valid and invalid characters. Stress
  test for the nibble lookup.

**For hex:**
- Odd-length input. Tests the final-nibble handling.
- Mixed-case input (alternating upper and lower hex characters).
- All 256 possible byte values encoded as hex pairs. Exhaustive
  coverage of the decode table.
- Input containing non-hex characters. Tests robust decoding.

**For url:**
- Input with no percent-encoded characters. Pass-through test.
- Input that is 100% percent-encoded. Worst-case decode.
- `%` at the end of input (incomplete sequence). Robust handling.
- `%` followed by one hex digit (incomplete sequence).
- All 256 possible bytes as `%XX` sequences.
- Nested percent-encoding (`%2525` → `%25` → `%`).

**For unicode:**
- `\x` followed by 0, 1, or 2 hex digits. Tests incomplete
  sequences.
- `\u` followed by 0-4 hex digits.
- Valid BMP code points that encode to 1, 2, or 3 UTF-8 bytes.
- Code points above U+FFFF that require 4 UTF-8 bytes.
- A mix of escaped and unescaped characters.
- `\\x41` (escaped backslash followed by `x41`) — should NOT
  decode because the backslash is escaped.

Each input class generates hundreds of concrete inputs via the
harness. The CPU reference function processes each input. The GPU
shader processes the same input. The outputs are compared
byte-for-byte. Any divergence is a conformance failure.

## Permanence

The operation identifiers (`decode.base64`, `decode.hex`,
`decode.url`, `decode.unicode`) are permanent. Their signatures
(`(Bytes) -> Bytes`) are permanent. The semantics described in this
chapter are permanent.

Robust decoding behavior (invalid characters produce zero or
pass-through rather than decode failure) is permanent. This is a
deliberate design choice, not a workaround, and it will not be
changed to strict decoding in a future version. If strict decoding
is needed, it will be a new operation (`decode.base64_strict`) with
different semantics.

Future decode operations (e.g., `decode.html_entity`,
`decode.jwt`, `decode.protobuf`, `decode.msgpack`) will be added as
new identifiers with new specifications. They will follow the same
pattern: `(Bytes) -> Bytes`, one invocation per region, robust by
default, strict as a separate op if needed.

## See also

- [Operations Overview](../overview.md)
- [Hash Operations](../hash/overview.md)
- [OpSpec Trait](../trait.md)

