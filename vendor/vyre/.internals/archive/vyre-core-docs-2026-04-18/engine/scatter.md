# Scatter Engine

## Overview

The scatter engine converts raw match events into rule-local state used by
rule evaluation programs. It is the bridge between pattern matching and rule conditions.

Input match rows have at least:

```text
pattern_id: u32
start: u32
end: u32
```

The implementation may carry auxiliary fields such as entropy bucket or source
file ID.

## Pattern-To-Rule Mapping

`pattern_to_rules[pattern_id] = vec2(start, count)` points into flattened mapping
arrays:

```text
rule_id = rule_list[start + i]
string_id = string_local_ids[start + i]
```

One pattern can feed many rules. A pattern ID outside `pattern_to_rules` is
ignored. A mapping offset outside the flattened arrays is ignored to preserve
safe OOB behavior, but validation should reject malformed mapping tables.

## Outputs

The scatter pass writes:

- `rule_bitmaps`: per-rule bitset of matched local strings,
- `rule_counts`: per-rule, per-string match counts,
- `rule_positions`: bounded cached start offsets,
- `rule_match_aux`: cached length and packed auxiliary metadata,
- optional count summaries for diagnostics.

Bitmap layout is word-based:

```text
word_idx = string_id / 32
bit_idx = string_id % 32
rule_bitmaps[rule_id * words_per_rule + word_idx] |= 1 << bit_idx
```

## Atomics

Each match is independent, so scatter uses atomics:

- `atomicOr` sets the bitmap bit for a matched string.
- `atomicAdd` increments the match count and returns the old slot index.
- cached positions are written only when `old_count < max_cached_positions`.

Atomic order does not affect counts or bitmaps. Cached positions may be captured
in atomic order; consumers must treat cached positions as an unordered bounded
sample unless a subsequent stable sort is specified.

## Dispatch

Scatter uses one invocation per match row:

```text
match_index = global_invocation_id.x
if match_index >= match_count: return
row = matches[match_index]
for each mapped rule/local string:
    atomicOr bitmap
    old = atomicAdd count
    if old < max_cached_positions: store position and aux
```

## Validation

The engine must validate rule count, max string count, words per bitmap, flattened
mapping sizes, cached position capacity, and output buffer sizes before dispatch.
Errors must identify the requested size and the required fix.
