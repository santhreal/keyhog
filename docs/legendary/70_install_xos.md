# 70 — Install / update / cross-OS / racing

A scanner is only as good as its install. Seed finding: doctor flags a PATH
shadow (`~/.local/bin/keyhog` ahead of a fresh build). The bar: install→doctor→
scan→SARIF→rollback proven byte-identical-correct on Linux x86_64, Linux aarch64,
macOS arm64, and Windows, every release, with every race + partial-failure path
handled. Hardest-first: the 3-OS byte-identical proof + the install-race lane lead.

Numbers: KH-L-0710 … KH-L-0829.

## Install correctness + UX

- KH-L-0710 [AV13,L10][INSTALL][L] PATH-shadow: `install`/`update` detect + loudly resolve an older keyhog ahead on PATH (doctor already warns — make install fix or refuse). Proof: a shadow-install e2e that ends with one resolvable keyhog.
- KH-L-0711 [VR1,AV15][INSTALL][L] Install race: two concurrent installs/updates can't corrupt the binary or the cache (atomic rename, lockfile). Proof: a concurrent-install stress test.
- KH-L-0712 [AV15][INSTALL][M] `install.sh` / PowerShell installer verify the download (checksum/signature) before exec; a tampered artifact is refused. Proof: a tampered-artifact rejection test.
- KH-L-0713 [L10][INSTALL][M] Partial-install failure (disk full, perms, network drop) rolls back cleanly, never a half-installed binary. Proof: a fault-injection install test.
- KH-L-0714 [AV13][INSTALL][M] `uninstall` removes the binary + cache + PATH entry + completions, leaving no orphan. Proof: an install→uninstall→clean-tree e2e.
- KH-L-0715 [AV13][INSTALL][M] `update` is idempotent + atomic; updating to the same version is a no-op, to a newer version is atomic. Proof: an update-idempotency e2e.
- KH-L-0716 [AV10][INSTALL][M] The README install commands (Linux/macOS/Windows/source) all work verbatim on a clean machine. Proof: each README install snippet run on the matching OS in dogfood-all-os.

## Cross-OS byte-identical correctness

- KH-L-0717 [AV13,SCALE][CLI][XL] The SAME scan over the SAME tree yields byte-identical findings (modulo paths) on Linux x86_64, Linux aarch64, macOS arm64, Windows. Proof: a cross-OS golden-output diff in dogfood-all-os.
- KH-L-0718 [AV13][SCANNER][L] `#[cfg(unix)]` / `#[cfg(windows)]` routes (mmap, path handling, TTY) each have a per-OS test; no OS-only silent divergence. Proof: per-cfg-route tests run on the matching OS.
- KH-L-0719 [AV13][CLI][M] Line-ending (CRLF/LF) + encoding (UTF-8/UTF-16/latin1) handling identical across OSes; a CRLF file finds the same secrets. Proof: a CRLF/encoding fixture per OS.
- KH-L-0720 [AV13][INSTALL][L] macOS: the `portable` (no-Hyperscan, vyre-CPU) build installs + scans + the wgpu/Metal path probes safely (no PIPELINE_CACHE crash). Proof: macbook dogfood PASS incl. GPU-probe-safe.
- KH-L-0721 [AV13][INSTALL][L] Windows: portable build installs via PowerShell + scans + handles backslash paths, drive letters, long paths, reserved names. Proof: windows-thinkpad dogfood PASS.
- KH-L-0722 [AV13][INSTALL][M] Linux aarch64 (raspberry/graviton-class) builds + scans (musl static too). Proof: an aarch64 + musl dogfood (qemu or a real host).
- KH-L-0723 [L8,AV13][INSTALL][M] musl static build has NO GPU/Hyperscan link + a safe doctor (exit 0); the shipped portable binary is provably safe. Proof: a musl `doctor` exit-0 gate.

## doctor + self-test

- KH-L-0724 [AV9,L10][CLI][M] `doctor` detects + reports every real defect (PATH shadow, missing GPU, wrong perms, stale cache) with the fix; each warning is actionable. Proof: a doctor-warning matrix (inject each defect).
- KH-L-0725 [L8][CLI][M] `doctor` GPU self-test runs the real AC kernel on the host's backend (CUDA/wgpu/Metal) + reports which; a GPU-less host says so, not "fail". Proof: doctor on a GPU host + a GPU-less host, both sensible.
- KH-L-0726 [AV9][CLI][M] `--self-test` JSON carries provenance (commit, detector digest, ML version, backend, degrade reason) for support. Proof: a self-test-JSON schema test.

## TUI (cross-OS, via PTY)

- KH-L-0727 [AV13,L7][TUI][M] `keyhog tui` idle sits at ~0% CPU (frozen clock, needs_redraw gate — done) on every OS; verify via PTY in dogfood-all-os. Proof: per-OS idle-CPU assertion.
- KH-L-0728 [L6][TUI][M] TUI live feed == `keyhog scan` deduped output (done — gate it cross-surface) + resize/scroll/quit work over a PTY. Proof: a TUI-feed-parity + interaction test per OS.
- KH-L-0729 [AV13][TUI][M] TUI compiled OUT of portable builds (feature-gated) — prove portable has no ratatui/crossterm link. Proof: a portable-no-tui gate.

## hook / daemon / watch (background modes)

- KH-L-0730 [AV3][CLI][M] `keyhog hook` (pre-commit) installs into git, blocks a commit with a secret, passes a clean commit, on every OS. Proof: a pre-commit e2e per OS.
- KH-L-0731 [VR1,AV15][DAEMON][L] Daemon IPC (`daemon/protocol.rs`, frames) is bounded + auth'd; a malformed/oversized frame can't crash or hang the daemon. Proof: a daemon-fuzz harness.
- KH-L-0732 [L10][DAEMON][M] Daemon never serves stale results after a detector-set/version change (merkle-keyed invalidation). Proof: a daemon-staleness test.
- KH-L-0733 [AV13][CLI][M] `watch` mode (filesystem events) is correct + bounded on each OS's notify backend; no missed/duplicate events. Proof: a per-OS watch e2e.
- KH-L-0734 [AV9][CLI][M] `scan_system` (system-wide triage) respects scope + perms + is bounded; never reads outside its declared scope. Proof: a scoped-system-scan test.

## dogfood-all-os infra

- KH-L-0735 [AV13,L10][INSTALL][L] Extend `dogfood-all-os.sh`: add aarch64 + musl + the GPU row + the golden-output cross-OS diff + the install-race case; unreachable hosts SKIP loudly. Proof: the extended matrix green/loud-skip.
- KH-L-0736 [SCALE][INSTALL][M] `dogfood-all-os.sh` runs in CI on a schedule (self-hosted runners per OS) + on every release. Proof: a scheduled cross-OS CI job.
- KH-L-0737 [VR9][INSTALL][M] dogfood findings each become a regression test (the dogfood→fix pipeline), not just a log line. Proof: each cross-OS bug has a reproducing test.
