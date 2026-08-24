# KeyHog: a Rust secret scanner

KeyHog scans repositories, Git history, CI workspaces, hosted Git collections,
cloud object inventories, archives, and local systems for leaked credentials.
You can start with one command, then choose a source boundary, detection policy,
and execution route that match the job.

The sample below comes from a `portable,simd` build. The default crates.io
install reports the pure-Rust CPU route instead; host labels and backend lines
are evidence from the running binary, not universal defaults.

```text
$ keyhog scan . --progress
    K E Y H O G
    ───────────
    v0.5.84 · secret scanner · 934 detectors
    by santh

  16 cores | SIMD: AVX-512 | Hyperscan | 934 detectors (5820 patterns) io_uring | backend=simd-regex | gpu=none

  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/.env.staging:14
  │ Evidence:   likely/vendor-pattern  ■■■■■■ 100%
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 secret found · 1 unverified

Scan complete. Found 1 secret in 1.42s.
```

## What it does

KeyHog walks working trees, Git history, Docker images, Git provider
collections, cloud buckets, URL lists, and local systems. Each finding has:

- a **detector** that fired (`stripe-secret-key`, `aws-access-key`, …)
- a **location** (file, line, offset, optionally commit hash and author)
- an exact **evidence tier and reason code**, plus entropy and evidence score when measured
- an optional **live verification** result if you pass `--verify`

KeyHog also supports Git provider inventories, S3, GCS, and Azure Blob objects,
Docker images, whole-system audits, CPU, Hyperscan, CUDA, Metal, and WGPU execution, and
an optional Unix daemon for repeated eligible inputs. [Choose a scanning
workflow](./capabilities.md) starts with the operator task and links each
capability to the chapter that owns its contract.

The detector corpus ships as TOML files under `detectors/`. Run
`keyhog detectors --format json` to inspect the exact corpus embedded in the
installed binary. A custom `--detectors <DIR>` remains an explicit replacement
by default, so there is never a hidden merge with embedded rules. Reviewed
extensions can opt into `--detectors-mode overlay`; detector-ID collisions
then fail closed rather than shadowing shipped rules.

## What it doesn't do

- **No telemetry.** Findings stay local. The scanner never phones home.
- **No hosted scanning agent.** Findings are not uploaded to a KeyHog service.
  A local daemon exists for eligible stdin and single-file requests on Unix.
  Starting it is explicit and it stays on your machine; after you start a
  compatible daemon, the ordinary Unix scan default (`--daemon=auto`) uses it
  for eligible requests. Use `--daemon=off` to force the in-process path.
- **No remote "AI-powered" detection.** Service detectors use TOML regexes and
  structural validators; generic detectors compose assignment shape, entropy,
  BPE token efficiency, context, and local confidence policy. The small
  on-device MoE scores ambiguous candidates without sending content away.
  Verification is optional and is the only detection-adjacent step that calls a
  service endpoint.

## Why another scanner

Three things, in order of how much they matter:

1. **Precision.** A scanner that emits one false positive per ten findings
   teaches developers to ignore it. KeyHog suppresses example credentials
   (the Stripe docs key, the AWS sample key, the RFC 7519 specimen JWT),
   vendored bundles (minified jQuery, node_modules), and CI workflow
   `${{ secrets.NAME }}` references by default. Repository dogfood and
   detector-specific negative twins keep those decisions exercised through the
   same scanner path users run.

2. **Recall.** The detector corpus is built service-by-service. For every
   detector, the test suite carries positive shapes (env-var, JSON,
   YAML, header, URL), negative shapes (placeholder, EXAMPLE marker),
   and adversarial evasions (split across lines, hex/base64-encoded,
   reversed via Caesar cipher). If a shape isn't in the suite, the
   detector isn't shipped.

3. **Speed.** Hyperscan SIMD prefilter, vectorized entropy, and a GPU
   region-presence route can accelerate different workloads. The winning route
   depends on the binary, detector/config digest, source shape, candidate
   density, cache state, CPU, GPU, driver, and storage. KeyHog records
   fastest-correct calibration for the installed host instead of treating a
   benchmark from another machine as a routing threshold.

   Published benchmark panels separate full-process startup, warm daemon
   requests, detection policy, cache state, backend diagnostics, scan workers,
   filesystem readers, corpus size, storage class, and concurrent partitions.
   Each panel labels development-host evidence that cannot support a
   clean-source release routing claim. See
   [Backends and routing](./backends.md) and the
   [reproducible benchmark harness](https://github.com/santhreal/keyhog/tree/main/benchmarks).

## Get going

Install the current release from crates.io:

```sh
cargo install --locked keyhog
keyhog --version
keyhog scan .
```

KeyHog requires Rust 1.89 or newer. The [Install](./install.md) guide shows
exact-version, portable, CI-only, and checked-out source builds. [Your first
scan](./first-scan.md) gives you a safe synthetic finding to confirm output,
redaction, and exit status before you scan a repository.

## Where things live

- **Source:** [github.com/santhreal/keyhog](https://github.com/santhreal/keyhog)
- **Issues:** [github.com/santhreal/keyhog/issues](https://github.com/santhreal/keyhog/issues)
- **Published crates:** [crates.io/crates/keyhog](https://crates.io/crates/keyhog)
- **Security:** use [GitHub private vulnerability reporting](https://github.com/santhreal/keyhog/security/advisories/new) first. If the form is unavailable, email `security@santh.dev`; PGP is not required. See the [security policy](https://github.com/santhreal/keyhog/blob/main/SECURITY.md).

License: MIT OR Apache-2.0.
Read the [MIT terms](https://github.com/santhreal/keyhog/blob/main/LICENSE-MIT) and
[Apache-2.0 terms](https://github.com/santhreal/keyhog/blob/main/LICENSE-APACHE).
