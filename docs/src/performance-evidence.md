# Performance evidence

Treat a timing as comparable only when the executable, detector corpus, configuration, workload, host, and route are recorded. A table without those identities is historical context, not release evidence.

## Canonical receipts

The repository owns two canonical generated evidence surfaces:

- [`readme-matrix.json`](https://github.com/santhreal/keyhog/blob/main/benchmarks/reports/readme-matrix.json) records scanner configuration, executable SHA-256, detector-corpus SHA-256, workload SHA-256, host resources, findings, precision, recall, wall time, throughput, and peak RSS. It also binds the generated README tables to the workload-catalog digest. `make -C benchmarks readme-matrix-check` rejects prose or table bytes that do not match the receipt.
- [`readme-scaling.json`](https://github.com/santhreal/keyhog/blob/main/benchmarks/reports/readme-scaling.json) records thread and process scaling with every trial, effective core count, page-cache state, storage class, workload size, findings, wall time, and peak RSS.

The benchmark index in [`benchmarks/README.md`](https://github.com/santhreal/keyhog/blob/main/benchmarks/README.md) owns focused receipts for Bloom filtering, autoroute, daemon routing, recovery, and competitive accuracy. Read the linked JSON receipt before quoting a generated Markdown report.

## Comparison boundary

Match all of these fields before comparing two rows:

1. executable digest and stamped commit;
2. detector-corpus digest and detector count;
3. resolved configuration, including backend, cache, daemon, verification, decode, and confidence policy;
4. workload digest, bytes, file count, and input shape;
5. host CPU, GPU, memory, operating system, affinity, and cgroup quota;
6. warm or cold page-cache and process state;
7. trial count, aggregation rule, exit code, scan status, findings, and coverage gaps.

A backend override is diagnostic. It does not prove automatic routing. Autoroute evidence is valid only when calibration authenticated the exact workload class, binary, detector/config state, host, accelerator state, and selected route.

## Reproduce the generated tables

Run:

```console
make -C benchmarks readme-matrix-check
make -C benchmarks readme-scaling-check
```

To collect new measurements, follow the command in the focused report or benchmark index. Keep raw host-local results outside tracked reports until the run records immutable executable and workload identities and exact finding parity.

## Interpret older reports

`benchmarks/reports/perf.md`, `cross-device.md`, and `workload-matrix.json` predate the complete canonical receipt contract. They remain useful for investigation, but their rows must not replace the generated README matrix or scaling receipt. In particular, an absolute path, a mutable binary path, a missing executable digest, or an unattested working tree prevents a release claim.

Daemon measurements have a separate boundary. One-shot process time includes scanner construction; warm daemon request time does not. Resident daemon RSS belongs to the server. Compare daemon rows only with the same request class and lifecycle.
