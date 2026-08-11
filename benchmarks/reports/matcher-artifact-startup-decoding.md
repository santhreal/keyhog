# Matcher artifact startup decoding

MatcherArtifact cache hits now validate section ranges and hydrate directly from one capped file buffer. The public owned-section loader remains byte-compatible.

| Startup operation | Legacy | Candidate | Change |
|---|---:|---:|---:|
| Complete section allocations | 3 | 0 | 100% eliminated |
| Complete section bytes copied | 2,894,852 | 0 | 100% eliminated |
| Backing artifact buffers | 1 | 1 | unchanged |

The measured production CPU artifact is 2,895,472 bytes: a 36,181-byte literal index, 2,858,486-byte regex program, and 185-byte suppression policy. Its SHA-256 is bound in the JSON receipt. Seven legacy warm hits had a 120 ms median wall time and 44,264 KiB median maximum RSS; those values establish workload scale only. No end-to-end speedup is claimed because JSON envelope decoding and scanner construction remain required.

The focused regression proves every section slice points inside the one capped artifact buffer, preserves exact section bytes, and keeps the public owned loader compatible. Identity and content digests are checked before hydration; malformed lengths, trailing bytes, foreign identities, and content mismatches still fail closed.

Receipt: [`matcher-artifact-startup-decoding.json`](matcher-artifact-startup-decoding.json)
