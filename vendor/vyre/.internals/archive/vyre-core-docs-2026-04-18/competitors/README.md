# Competitor Notes

This directory records technical comparisons between vyre and adjacent systems.
The purpose is scope control, not marketing.

vyre is a GPU compute IR with a standard operation library, a stable wire
format, WGSL as the reference lowering, and a conformance suite. The comparison
baseline is therefore narrow:

- Does the system define a semantic IR contract?
- Does it target GPU compute directly?
- Does it allow runtime interpretation or fallback execution?
- Does it expose domain libraries as IR compositions?
- Does it make wire-format round trips lossless and testable?

The files in this directory should be updated when vyre adds a backend,
conformance rule, or standard operation domain that changes one of those
answers.
