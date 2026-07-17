# Changelog

## Unreleased

- Add detector-owned `plausibility.keyword_free_operator_margin`, validate it
  only for the `keyword-free` entropy role, and bind it into detector identity.

- Add an opt-in source ordering contract for contiguous chunk identities so
  dispatchers can split routing batches without assuming concrete source types.

- Add shared overflow-safe median and paired confidence primitives for
  autoroute calibration and release crossover evidence.

## 0.2.1

- Align package metadata with the Santh Standard.
- Keep detector specification, allowlist, reporting, and shared type APIs available for the 0.2 line.
