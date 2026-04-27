# Google RE2

Google RE2 is a regular expression engine designed around guaranteed linear-time
matching. It rejects features that require backtracking semantics, such as
backreferences and some lookaround forms, because those features can produce
exponential behavior in traditional backtracking engines. RE2's core value is
predictable CPU regex matching for untrusted patterns and inputs.

vyre's relevant surface is the `match_ops` domain, especially `dfa_scan`.

## Where RE2 is stronger

RE2 is a complete regex engine. It parses regex syntax, compiles automata,
handles captures under its supported semantics, exposes a stable API, and is
widely deployed. It focuses on safety through algorithmic guarantees: matching
time is linear in input size for the accepted language subset.

RE2 also has a mature user-facing contract. Developers can reason about which
regular expression constructs are supported and why unsupported constructs are
rejected.

## Where vyre differs

vyre does not aim to be a regex engine in `core`. The `match_ops` layer should
contain GPU-composable matching operations. A downstream regex frontend can
compile a safe regex subset into a DFA table and then use vyre's scan domain as
the GPU execution substrate. That keeps syntax, product policy, and user-facing
regex APIs outside the IR crate.

`dfa_scan` is lower level than RE2's public API. It consumes tables and buffers,
not regex strings. That is the right boundary for vyre: the operation is an IR
composition over buffers and primitives, so it can be serialized, validated,
lowered, and conformance-tested like the rest of the standard library.

RE2's safety property is linear-time CPU execution for a regex subset. vyre's
safety property is deterministic GPU execution for a bounded IR composition. The
two properties are compatible but not identical. A downstream tool could choose
RE2-like syntax restrictions and compile the accepted language into vyre tables.

## Comparison target

RE2 should remain the semantic comparison for safe regex expressiveness and
linear matching guarantees. Hyperscan should remain the performance comparison
for high-throughput multi-pattern CPU scanning. vyre should compete by providing
a GPU-native execution substrate for matching domains while keeping parsing and
policy outside `core`.
