# adversarial.md — hostile-input testing

## What goes here

Tests that prove the crate **survives** hostile, malformed, or
extreme input without panicking, corrupting state, or consuming
unbounded resources. The adversarial tier is the crate's armor.

## Checklist — every adversarial test suite covers

### Input shape

- [ ] Empty input (`&[]`, empty `Program`, zero-entry vec, 0-byte buffer)
- [ ] Null / zero-sized / single-byte / single-element — boundary of 1
- [ ] Maximum documented size — consumed correctly, not rejected
- [ ] One byte past maximum — rejected cleanly with `Fix:`-bearing error
- [ ] Non-UTF-8 bytes in string positions (invalid continuation byte,
  surrogate pair halves, BOM-only, overlong encoding)
- [ ] Unicode edge cases in identifiers (zero-width joiner, RTL
  override, combining marks, normalization forms NFC vs NFD)
- [ ] Null bytes embedded in `Ident`, buffer names, op ids (must be
  rejected by validator, never silently truncate)

### Numeric edges

- [ ] `u32::MAX`, `i32::MIN`, `u64::MAX`
- [ ] `f32::NAN`, `f32::INFINITY`, `f32::NEG_INFINITY`, `-0.0`,
  denormal values
- [ ] Integer overflow on every arithmetic path (add, mul,
  shift-by-width, div-by-zero)
- [ ] Off-by-one on every bound check (`len`, `cap`, `size_class`)

### Adversarial structure

- [ ] Deeply nested expressions / nodes (stack-safety check: 10 000
  levels must not overflow the native stack — the walker is explicit)
- [ ] Cycle in a graph where graphs are allowed (decoder must detect
  and reject)
- [ ] Duplicate keys, bindings, op ids
- [ ] Forward references before definitions
- [ ] Mismatched open/close pairs (Block without end, If without
  otherwise when required)

### Resource exhaustion

- [ ] Extremely large allocation requested — must fail with
  structured error, not OOM-panic
- [ ] Many small allocations in a loop — must not leak
- [ ] Bounded cache under pressure — must evict, never grow
  unbounded
- [ ] Thread-pool saturation — caller blocks or queues, never
  allocates OS-thread-per-request

### Concurrency (when applicable)

- [ ] Two threads dispatch against the same backend / registry /
  cache simultaneously → no data race, no deadlock, no lost writes
- [ ] Reader while writer swaps (arc-swap semantics) → reader
  finishes against its snapshot
- [ ] Mutex poisoning — test path where a thread panics inside a
  lock; the next caller surfaces a structured error, not a
  second panic

### IO / filesystem / env (for crates that touch them)

- [ ] Read-only filesystem (cache dir not writable) — structured
  fallback
- [ ] Disk full — clean error, no partial-write corruption
- [ ] Env var with invalid UTF-8 — rejected, not panicked
- [ ] Interrupted IO (truncated read / write) — detected

### Decode / deserialize

- [ ] Random bytes fed to the decoder — must not panic, must return
  a structured error
- [ ] Valid magic + truncated payload
- [ ] Oversized length prefix pointing past EOF
- [ ] Unknown tag in reserved range vs unallocated range — clean
  error, tag and context reported
- [ ] Encoder + decoder round-trip on every KAT program

## Template

```rust
//! Adversarial tests for `<crate>`.
//!
//! See `../../.internals/skills/testing/adversarial.md` for the category contract
//! and `tests/SKILL.md` for this crate's specific invariants.

use <crate>::*;

#[test]
fn empty_input_does_not_panic() {
    let result = decode(&[]);
    assert!(result.is_err(), "empty input must surface a structured error, not panic");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("Fix:"), "error message must carry actionable Fix: prefix");
}

#[test]
fn oversized_length_prefix_rejected() {
    let mut bytes = magic_bytes();
    bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // claim 4 GB payload
    let result = decode(&bytes);
    assert!(result.is_err());
}

// ... etc.
```

## Anti-patterns

- **Catching panics with `catch_unwind`** just to make the test green.
  A panic is a finding — report it as a bug and fix the engine.
- **Weakening an assertion** to make the test pass ("it's usually
  correct; allow a delta of 10%"). Weakening = deleting the test.
- **Testing only the happy path** with a file named `adversarial.rs`.
  Half a test is a lie.
- **Random input without a seed**. Every failing proptest case is
  reproducible; every adversarial fuzz case has a deterministic
  seed.

## Proptest + adversarial

Simple per-case adversarial assertions live in
`tests/adversarial.rs`. Pattern-level hostile-input generation —
every shape of invalid program — lives in
`tests/property.rs` under `proptest!` blocks. Use whichever fits;
write both when the invariant is load-bearing.
