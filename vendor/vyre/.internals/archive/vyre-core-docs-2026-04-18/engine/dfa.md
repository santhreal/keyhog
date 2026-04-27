# DFA Engine

## Overview

The DFA engine scans byte input against a precompiled deterministic finite
automaton. Each GPU invocation starts at one byte offset and walks forward
through the transition table until it reaches the end of input or an engine limit
chosen by the compiled scanner.

## Tables

The transition table is a flat `u32` array of length `state_count * 256`.

```text
transition_index = state * 256 + byte
next_state = transitions[transition_index]
```

Every transition entry must be `< state_count`. Invalid states are compile-time
errors.

Accept states are represented as a dense accept map indexed by state. A value of
`0xFFFFFFFF` means non-accepting. Any other value is an output-link index.

Output links map accepting states to pattern IDs. A state may represent one
pattern directly or a linked list/span of pattern outputs, depending on the
compiler. The exposed result is always one row per reported pattern match.

Pattern lengths are stored as `pattern_lengths[pattern_id]`. They are required
for start offset reconstruction:

```text
end = current_offset + 1
start = end - pattern_lengths[pattern_id]
```

## Input Encoding

Input bytes are packed into `array<u32>` using the `Bytes` encoding from
`ir/types.md`. Byte `i` is read from word `i / 4` and lane `i % 4`.
Out-of-bounds byte reads return zero, but the DFA scan must still check
`offset < input_len` so padding bytes do not create matches.

## Dispatch

The standard dispatch is one-dimensional with workgroup size `256`. Invocation
`gid.x` starts scanning at byte offset `gid.x`.

```text
start_offset = global_invocation_id.x
if start_offset >= input_len: return
state = 0
for pos in start_offset..input_len:
    byte = input[pos]
    state = transitions[state * 256 + byte]
    if accept[state] != NO_ACCEPT:
        emit matches for that accept state
```

## Match Output

Each emitted match row has:

```text
(pattern_id: u32, start: u32, end: u32)
```

The match output buffer is tightly packed as sequential little-endian rows:

```text
offset + 0: pattern_id: u32
offset + 4: start:      u32
offset + 8: end:        u32
row size: 12 bytes
```

`start` is inclusive. `end` is exclusive. The separate `match_count` buffer
stores the observed match count in its first 4 bytes as a little-endian `u32`.
Rows may be produced in nondeterministic atomic order internally; readback must
sort rows into deterministic order before returning them. The stable ordering is
`(start, end, pattern_id)` unless a caller requests a stricter product order.

The match counter is an atomic `u32`. If more matches are observed than the
allocated match buffer can hold, the counter may exceed capacity, but only the
first `max_matches` rows are captured. The reported overflow count remains useful
for diagnostics.

## Reusable ScanResources

`ScanResources` owns input, match, count, params, and readback buffers sized for
a maximum input length and maximum match count. A compiled DFA may reuse these
buffers across scans on the same device. Reuse is allowed only when the new input
fits the resource capacity; otherwise larger resources must be allocated.

Resources are tied to the GPU device used to compile the DFA. Scanning with a
different device is an error: `Fix: scan with the same wgpu::Device and Queue
used to compile the DFA.`

## Validation

Compilation must reject empty state sets, transition lengths other than
`state_count * 256`, transition targets outside the state set, accept states
outside the state set, output links outside their table, and pattern IDs without
lengths.
