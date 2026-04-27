# Intel Hyperscan

Intel Hyperscan is a high-performance multiple-pattern matching library. Its
core strength is compiling regular expressions and literal sets into optimized
automata and running them efficiently on CPU targets, especially x86 systems
with SIMD support. It is an engine, not an IR substrate.

vyre's `match_ops::dfa_scan` domain overlaps with Hyperscan at the workload
level: scan bytes, follow automata transitions, and report matches. The
architectural target is different.

## Where Hyperscan is stronger today

Hyperscan has a mature compiler for pattern databases and a production runtime
for scanning streams, blocks, and vectored input. It has years of CPU-specific
engineering around literal acceleration, SIMD utilization, state compression,
prefilters, streaming state, and match reporting. For CPU regex and multi-pattern
matching, vyre should assume Hyperscan is the performance baseline to beat.

Hyperscan also owns the full user-facing pattern lifecycle: parse regex syntax,
compile a database, allocate scratch space, scan data, and invoke match
callbacks. vyre's current DFA scan operation does not own that whole lifecycle.

## Where vyre compares

`DfaScan::program()` expresses the scan kernel as vyre IR. It reads packed input
bytes, transition tables, accept maps, output links, pattern lengths, and params;
then it reports match triples into output buffers. That shape is intentionally
backend-neutral. The same IR can be validated, serialized, and lowered to any
conforming GPU backend.

Hyperscan is an optimized CPU matching engine. vyre is a way to define a GPU
matching operation inside a broader compute IR. The useful comparison is not
"regex library versus regex library"; it is "CPU-specialized compiled database
versus conformance-gated GPU operation composition."

Where vyre can beat Hyperscan is throughput for large, parallel scans where GPU
memory bandwidth and thread parallelism dominate CPU branch and cache behavior.
Where Hyperscan will remain hard to beat is latency-sensitive CPU scanning,
small inputs, streaming mode with complex state, and regex features whose
compiled form is not a straightforward DFA table.

## What vyre must add before claiming parity

vyre needs a complete pattern compilation path into transition tables, output
links, accept maps, and pattern-length buffers. It also needs conformance cases
for overlapping matches, leftmost policies if supported, empty patterns if
allowed, bounded output behavior, malformed table rejection, and deterministic
match ordering.

Until those exist, `dfa_scan` should be described as the GPU IR kernel contract,
not a complete Hyperscan replacement.
