# 50 — Sources: every backend, hardened + complete

~20 source backends. Each must be: complete (no half-wired capability), hardened
(SSRF/traversal/bomb-safe), scale-bounded, and dogfooded on real inputs. Domain
logic stays out of transport. Hardest-first: git-history-at-scale and the binary
(Ghidra/strings) path lead.

Numbers: KH-L-0500 … KH-L-0619.

## Filesystem + walking

- KH-L-0500 [VR1,AV15][SOURCES][L] Symlink-race / TOCTOU audit of the filesystem walker (`extract.rs` 761 L): a symlink swapped mid-walk can't escape the root or read outside scope. Proof: a symlink-race test, fail-closed.
- KH-L-0501 [AV15][SOURCES][M] Path-traversal: `../`, absolute-symlink, and unicode-normalization paths can't escape the scan root. Proof: a traversal corpus, all contained.
- KH-L-0502 [L10][SOURCES][M] `.gitignore`/`.keyhogignore` honored correctly; a skipped file is recorded (not silently dropped) under `--explain`. Proof: an ignore-attribution test.
- KH-L-0503 [AV13][SOURCES][M] Non-UTF-8 paths + filenames (the `MatchLocation` encode contract) round-trip on every OS. Proof: a non-UTF-8 path fixture per OS in dogfood-all-os.
- KH-L-0504 [L7,AV1][SOURCES][M] mmap vs read thresholds tuned; large-file windowing correct on every OS (Windows mmap quirks). Proof: a per-OS large-file test.

## Git (history + diff)

- KH-L-0505 [AV3,AV1][SOURCES][RESEARCH] Git-history scan recovers secrets from deleted/rewritten commits at scale, incrementally (merkle-keyed), bounded memory. Proof: a large-history recall + scale bench.
- KH-L-0506 [AV3][SOURCES][M] Git-diff (pre-commit hook) scans only the staged delta, correctly attributing line/commit. Proof: a staged-diff e2e with line assertions.
- KH-L-0507 [L6][SOURCES][M] History attribution (commit/author/date in `MatchLocation`) is correct across merges/rebases. Proof: a multi-branch history fixture.
- KH-L-0508 [VR1,AV15][SOURCES][M] Malicious repo input (giant blob, pathological history, ref cycles) is bounded + safe. Proof: an adversarial-repo corpus.

## Remote (S3 / GitHub-org / web / slack / http) — SSRF + auth

- KH-L-0509 [VR1,AV15,ENG][SOURCES][L] SSRF: every remote fetcher (web, http, s3, github_org, slack, har URLs) routes through the SSRF guard (bogon/domain-allowlist/redirect-pinning) — no fetcher bypasses it. Proof: an SSRF-bypass corpus, all blocked; a `no_raw_fetch` gate.
- KH-L-0510 [AV15][SOURCES][M] DNS-rebinding + redirect-to-internal protection on every remote source. Proof: a rebinding test (pinned-IP fetch).
- KH-L-0511 [ENG,L10][SOURCES][M] Credentials/tokens for remote sources are never logged; auth failures are loud + actionable. Proof: `no_secret_in_logs` over the sources crate.
- KH-L-0512 [AV3][SOURCES][M] S3 listing + auth (`s3/mod.rs` 542 L) paginates correctly + handles large buckets bounded. Proof: a paginated-listing test (mock).
- KH-L-0513 [AV3][SOURCES][M] GitHub-org enumeration (`github_org.rs` 507 L) respects rate limits + paginates; partial failure is loud. Proof: a rate-limit-handling test.
- KH-L-0514 [AV3][SOURCES][M] HAR + web sources extract secrets from request/response bodies, headers, cookies, query. Proof: a HAR fixture with secrets in each location.
- KH-L-0515 [VR1,AV15][SOURCES][M] Proxy/bypass: respect `HTTP(S)_PROXY` + `NO_PROXY` without leaking through a bypass. Proof: a proxy-honoring test.

## Binary (Ghidra / strings / sections / literals / docker)

- KH-L-0516 [AV3,SCR][SOURCES][RESEARCH] Binary secret extraction (`strings`/`sections`/`literals`) finds secrets in ELF/PE/Mach-O; the Ghidra path is complete + optional. Proof: a per-format binary fixture with planted secrets.
- KH-L-0517 [AV5,L11][SOURCES][M] The Ghidra integration is fully wired (not half-built) or feature-gated cleanly; if dead, remove. Proof: a Ghidra e2e or a clean removal.
- KH-L-0518 [AV3][SOURCES][M] Docker image/layer scanning extracts secrets from layers + env + history. Proof: a Docker-image fixture.
- KH-L-0519 [VR1,AV15][SOURCES][M] Malformed binary input (truncated ELF, huge sections) is bounded + safe. Proof: a malformed-binary corpus.

## stdin + lossy input + redaction

- KH-L-0520 [L10,AV13][SOURCES][M] Lossy binary stdin (the dogfood-all-os `[cli]` case) scans without panic + with correct exit code. Proof: the lossy-stdin e2e per OS.
- KH-L-0521 [SCR][SOURCES][M] Redact/sanitize: `--redact` output never contains the plaintext secret, only hash+preview (the `to_redacted` contract). Proof: a `no_plaintext_in_redacted` e2e.
- KH-L-0522 [AV3][SOURCES][M] Timeouts: every source honors a per-source deadline + a global budget; a hung source is loud, not silent. Proof: a timeout-injection test per source.

## Source contract + parity

- KH-L-0523 [L5,AV8][SOURCES][M] Every source implements one `Source` trait through one boundary; adding a backend is a single-file change. Proof: a trait-conformance test for each.
- KH-L-0524 [TC,AV12][SOURCES][L] Each source has positive(finds), negative(clean), error(exit code), scale, and adversarial coverage. Proof: a per-source test matrix.
- KH-L-0525 [AV9][SOURCES][M] Source-selection flags reach behavior + e2e (every `--source`/auto-detect path tested). Proof: per-source CLI e2e.

(Breadth: 20 backends × {positive, negative, error, scale, adversarial, SSRF
where remote} ≈ 100+ items, enumerated per-backend as each is dogfooded.)
