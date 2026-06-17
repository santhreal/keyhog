# keyhog cross-OS status

What an actual cross-OS dogfood of the keyhog source at HEAD found, run from the
work-linux hub over SSH against every host in `~/.ssh/config`. Every line below
is a command that was really run and its real output — nothing here is inferred.

Driver: `scripts/dogfood-all-os.sh` (build + CLI + installer matrix) plus the
focused payloads recorded in this doc. Source-level contracts that pin these
findings live in `crates/cli/tests/target_spec/cross_os_contracts.rs`.

Last run: 2026-06-15.

## Host reachability (probed `ssh -o ConnectTimeout=8 <host> 'uname -a || ver'`)

| Host             | Alias(es)              | State        | Evidence |
|------------------|------------------------|--------------|----------|
| tt-macbook       | macbook-pro            | **UP**       | `Darwin Mac.lan 25.3.0 ... arm64`, macOS 26.3, rustc/cargo 1.94.1 |
| windows-thinkpad | thinkpad-win           | **UP**       | `Microsoft Windows [Version 10.0.26200.8655]`, rustc/cargo 1.94.1 |
| santhserver      | santh-server           | **DOWN**     | SSH connect hangs to timeout (rc 124); no banner, no refusal |
| axiomexec        | axiom-exec             | **DOWN**     | SSH connect hangs to timeout (rc 124); no banner, no refusal |
| thamiya          | thamiya-desktop        | **DOWN**     | `ssh: connect to host 100.85.80.41 port 22: Connection timed out` |

LOUD, not a silent skip (Law 10): santhserver was the expected primary Linux
build host and it is **unreachable** — the Linux leg of this run was NOT
exercised on the fleet (only the work-linux hub, which is the source tree
itself). axiomexec and thamiya are likewise down. A green macOS+Windows matrix
here does NOT clear Linux-on-fleet; it is "not run on those hosts this round."

## macOS (tt-macbook, Darwin arm64) — REACHED, built, dogfooded

Build: `cargo build --profile release-fast -p keyhog --no-default-features
--features portable` → **rc 0** in 1m10s (only 3 pre-existing dead-code warnings
in `crates/scanner/src/engine/fallback.rs`). Binary: 22,982,728 bytes.

Operator path (real binary, real temp inputs):

| Surface                              | Result        |
|--------------------------------------|---------------|
| `keyhog --version`                   | rc 0 (`KeyHog v0.5.40`, Build Target `aarch64-macos`) |
| `keyhog doctor`                      | rc 0 (healthy) |
| seeded scan (`leak.env`, json)       | rc 1, detector `aws-access-key` fired |
| clean scan                           | rc 0 |
| SARIF (`--format sarif`)             | well-formed `2.1.0`, `"results"` present, 1 `ruleId` |
| `scan --git-history` on non-repo     | rc 2 (fail-closed) |
| `uninstall` (dry run)                | rc 0 |
| `uninstall --yes`                    | **rc 0, binary REMOVED** (kernel unlinks the running exe) |

Installer proof (`tests/install/install_from_local_build.sh`): **11 / 11 PASS**
— `--from-file` install, binary placed, `--version`, `doctor` exit 0, seeded
scan exit 1, empty scan exit 0, SARIF well-formed, correct/tampered `.sha256`
gate, missing-file error path, and the `expect`-driven interactive wizard.

## Windows (windows-thinkpad, Windows 10.0.26200) — REACHED, built, dogfooded

The Santh NFS share is **not** mounted on Windows (`Test-Path Z:\... = False`),
so the only build path is an offline source ship. The previous source package
failed there because the Vyre dependencies escaped the repo tree; this is now
resolved by exact crates.io `=0.6.2` Vyre pins. The last full Windows dogfood
build recorded below was run before that pin cleanup:

Build: `cargo build --profile release-fast -p keyhog --no-default-features
--features portable` → **rc 0** in 4m42s (same 3 dead-code warnings). Binary:
`C:\cargo-target\release-fast\keyhog.exe`, 20,632,576 bytes.

Operator path (`scripts/dogfood-windows.ps1` payload):

| Surface                              | Result        |
|--------------------------------------|---------------|
| `keyhog --version`                   | rc 0 (`KeyHog v0.5.40`) |
| `keyhog doctor`                      | rc 0 (healthy) |
| seeded scan (`leak.env`, json)       | rc 1, detector `aws-access-key` fired |
| clean scan                           | rc 0 |
| SARIF (`--format sarif`)             | well-formed `2.1.0`, `"results"` present, 1 `ruleId` |
| `scan --git-history` on non-repo     | rc 2 (fail-closed) |
| `uninstall` (dry run)                | rc 0 |
| `uninstall --yes`                    | **rc 2, binary STILL PRESENT** (Windows can't delete a running .exe) |

Every surface is exit-code-identical to macOS **except `uninstall --yes`** — the
single deliberate divergence (next section).

## Findings

### F1 — DELIBERATE divergence: `uninstall --yes` exit code (0 unix / 2 windows)

Not a bug — a documented, intentional platform difference, now proven live on
both OSes and pinned so it can never silently change:

* Unix (`crates/cli/src/subcommands/uninstall.rs`, `#[cfg(unix)]`):
  `std::fs::remove_file(exe)` succeeds on a running executable → `run()` returns
  `Ok(SUCCESS)` → **exit 0**, binary gone.
* Windows (`#[cfg(windows)]`): the OS refuses to delete a running `.exe`, so
  `remove_binary` returns `Err(anyhow!("Windows can't delete a running .exe.
  After this process exits, remove: …"))`. That error is not an `io::Error`, so
  `crates/cli/src/main.rs` maps it to `EXIT_USER_ERROR = 2` → **exit 2**, binary
  stays. This is a fail-closed, loudly-surfaced error (Law 10), not a silent
  no-op success.

Pinned by:
* `crates/cli/tests/target_spec/cross_os_contracts.rs::uninstall_remove_binary_is_per_os_and_windows_fails_closed`
  (GREEN, every OS — source-level: both `#[cfg]` arms, Windows fails closed, no
  `remove_file` on the Windows arm).
* `crates/cli/tests/target_spec/cross_os_contracts.rs::main_defines_exit_user_error_two_for_windows_uninstall_path`
  (GREEN — pins `EXIT_USER_ERROR = 2`).
* `scripts/dogfood-windows.ps1` phase 5 (live end-to-end: asserts exit 2 + the
  binary persists; verified PASS on windows-thinkpad).

### F2 — CROSS-OS BUILD BLOCKER (RESOLVED): old Vyre path override escaped the repo tree

Reproduced on windows-thinkpad (no NFS share). `tar`-shipping ONLY the keyhog
source and running `cargo metadata` there:

```
error: failed to load manifest for workspace member `C:\keyhog-xos\src\crates\core`
referenced by workspace at `C:\keyhog-xos\src\Cargo.toml`
Caused by:
  failed to load manifest for dependency `vyre-libs`
```

Resolved 2026-06-17: the root `Cargo.toml` now pins all five runtime `vyre*`
crates to exact `=0.6.2` crates.io versions. That keeps
`vyre_libs::scan::build_regex_dfa_unanchored` available without requiring the
Santh NFS share or any local Vyre source mirror, so an offline source
distribution can build on a share-less host.

Pinned GREEN by
`crates/cli/tests/target_spec/cross_os_contracts.rs::vyre_pins_are_self_contained_for_offline_cross_os_build`
and `crates/cli/tests/vyre_pin_coherence_lane3.rs::all_five_vyre_pins_present_exact_registry_and_lockstep`.

The remaining cleanup target is separate: the stale `vendor/vyre` reference
snapshot is not a build input and stays excluded until an explicit
operator-approved cleanup removes or refreshes it.
