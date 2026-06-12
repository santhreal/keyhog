# 90 — Security audit: keyhog-as-target (the AV15 hunts)

keyhog ingests hostile input (untrusted repos, binaries, archives, web responses,
crafted secrets) and runs with the operator's privileges. Every audit-hunt vector
from CLAUDE.md applies to keyhog itself. The bar: every parser/decoder fuzzed to a
PoC or a disk-documented kill; every audit class closed with a fail-closed test.
Hardest-first: the parser/decoder fuzzing campaign is RESEARCH and leads. No
overclaim — only a reproduced PoC counts.

Numbers: KH-L-0920 … KH-L-1059.

## Fuzzing campaign (targeted, oracle-backed, structure-aware)

- KH-L-0920 [VR1,VR-targeted,AV15][DECODE][RESEARCH] Stand up structure-aware fuzz harnesses for every decoder (base64/url/hex/unicode-escape/quoted-printable/mime/html-entity/json/caesar/reverse) — one sink, one oracle, differential vs a reference. Proof: a `fuzz/` dir with a target per decoder + corpus.
- KH-L-0921 [VR1,AV15][STRUCTURED][RESEARCH] Fuzz the structured parsers (json/yaml/toml/env/xml) for panics/OOM/hangs on malformed input. Proof: per-parser fuzz targets, no crash under ASan.
- KH-L-0922 [VR1,AV15][SOURCES][RESEARCH] Fuzz the binary parsers (ELF/PE/Mach-O sections/strings) + archive handling (zip/tar/gzip) for memory-safety + bombs. Proof: per-format fuzz targets, bounded.
- KH-L-0923 [VR1,AV15][DAEMON][L] Fuzz the daemon wire protocol + the megakernel catalog wire format. Proof: protocol + catalog fuzz targets, fail-closed.
- KH-L-0924 [VR4,AV15][DECODE][L] The decode recursion: fuzz for the fan-out/depth/bomb edge (a single chunk can't blow the budget). Proof: a decode-bomb corpus, bounded RSS+time, loud cap.
- KH-L-0925 [VR9,VR10][ALL][M] Triage discipline: a crash from the harness's own setup is a harness bug, not a finding; DCHECK/OOM-by-design/timeout are not memory-corruption findings. Proof: a triage protocol doc + only real PoCs in the ledger.

## Audit-hunt classes (AV15 checklist, each → a fail-closed test)

- KH-L-0926 [AV15][SOURCES][M] Decompression bombs (zip/gzip/tar nested) — bounded ratio + size, loud on hit. Proof: a bomb corpus.
- KH-L-0927 [AV15][SCANNER][M] Algorithmic DoS: a crafted input can't drive the regex/decoder/multiline path quadratic/exponential. Proof: a ReDoS/quadratic corpus, bounded time.
- KH-L-0928 [AV15][SOURCES][M] Path traversal + symlink races (covered in 50; cross-linked here). Proof: shared traversal corpus.
- KH-L-0929 [AV15][SOURCES][L] SSRF / DNS-rebinding / proxy-bypass across sources + verifier (covered in 50/60; the unified corpus lives here). Proof: one SSRF corpus all fetchers pass.
- KH-L-0930 [AV15][CLI][M] Arg injection + shell quoting: keyhog never shells out unsafely (hook install, git invocation, ghidra). Proof: an arg-injection audit + tests.
- KH-L-0931 [AV15][CLI][M] CRLF / control-char injection into reports/logs (a secret/path with newlines can't forge log lines or break SARIF). Proof: a control-char corpus.
- KH-L-0932 [AV15,ENG][CORE][M] Weak crypto/RNG audit: hashing is SHA-256, any randomness is CSPRNG, no MD5/SHA1 for security decisions. Proof: a crypto-primitive audit.
- KH-L-0933 [AV15,ENG][VERIFIER][M] Constant-time gaps where secrets are compared (verifier, checksum). Proof: a constant-time audit.
- KH-L-0934 [AV15,VR9][SCANNER][M] TOCTOU on cache files (`~/.cache/keyhog`), config, baseline — atomic read/write, no race. Proof: a cache-race test.
- KH-L-0935 [AV15][CLI][M] Privilege: `scan_system` + daemon drop/limit privileges where possible; never write outside declared paths. Proof: a privilege-scope test.
- KH-L-0936 [AV15,L10][CORE][M] Secret handling: plaintext secrets never hit disk (cache, baseline, logs) — only hash+preview. Proof: a `no_plaintext_on_disk` e2e over every artifact.
- KH-L-0937 [AV15][CORE][M] Supply chain: dependency audit (`cargo audit`/`cargo deny`) green; no yanked/vulnerable deps. Proof: a `cargo deny` CI gate.
- KH-L-0938 [AV15][CLI][M] The installer + update channel can't be MITM'd (checksum/sig verify — see KH-L-0712). Proof: cross-linked install-integrity test.

## keyhog's own threat model + hardening posture

- KH-L-0939 [SCR,AV15][ALL][L] Write keyhog's threat model: untrusted-input boundaries, trust levels, the fail-closed contract per boundary. Proof: `docs/THREAT_MODEL.md` + each boundary mapped to a test.
- KH-L-0940 [VR-radio-silence][ALL][RESEARCH] Long-horizon: treat keyhog as an audited target — keep a disk coverage ledger (which sinks/inputs covered), never declare "clean". Proof: a coverage ledger that only grows.
- KH-L-0941 [AV15,L10][SCANNER][M] Resource limits are enforced + operator-visible: every cap (decode, memory, time, fan-out, match-count) is configurable (Tier-A) + logged on hit. Proof: a cap-inventory + per-cap loud-hit test.
- KH-L-0942 [SECURITY][CI][M] `cargo-fuzz` runs in CI (short) + nightly (long) with corpus persistence; new crashes file automatically. Proof: a fuzz CI lane + corpus artifact.

(Breadth: each parser/decoder/source × each audit class is an item; the fuzz
campaign generates findings that become items. ~140 as the campaign runs.)
