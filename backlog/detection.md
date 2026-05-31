# Detection backlog

Accuracy is measured ONLY by the SecretBench mirror scorer
(`tools/secretbench/scoring/score.py`), never by `cargo test`. These items are
flaws in the detection/scoring pipeline surfaced by the bench, with the data
that proves them.

## Bench provenance (2026-05-30)
- Pre-closure binary (`keyhog-rebuilt-2b1d02b8`): F1=0.8919, P=0.986, R=0.814, TP=2443, FP=35, FN=557.
- Post-closure binary (`keyhog-closure-2b1d02b8`): F1=0.8453, P=0.923, R=0.779, TP=2338, FP=194, FN=662.
- Config grid-sweep on the post-closure binary (runtime flags, no rebuild):

  | min_confidence | decode | F1 | P | R | FP | FN |
  |---|---|---|---|---|---|---|
  | 0.30 | shallow 4/64KB | 0.8524 | 0.932 | 0.786 | 173 | 643 |
  | 0.40 | shallow 4/64KB | 0.8632 | 0.984 | 0.769 | 37 | 694 |
  | 0.50 | shallow 4/64KB | 0.7985 | 0.878 | 0.732 | 306 | 803 |
  | 0.30 | deep 10/512KB | 0.8544 | 0.932 | 0.789 | 174 | 633 |
  | **0.40** | **deep 10/512KB** | **0.8642** | **0.984** | 0.770 | **37** | 689 |
  | 0.50 | deep 10/512KB | 0.8452 | 0.984 | 0.741 | 37 | 777 |

- PINNED canonical profile (this change): `min_confidence=0.40`, `decode_depth=10`,
  `decode_size_limit=512KB`, `ml_weight=0.5`.
- **CORRECTION (verified on the fresh baked binary, no flags = the scorer's path):**
  the grid-sweep above was run with `--min-confidence`/`--decode-*` FLAGS, which
  resolve through a DIFFERENT path than the baked defaults. The scorer runs
  `keyhog scan` with NO flags. Re-benched the fresh binary both ways:
  - BAKED (no flags, scorer path): F1=**0.8455** P=0.982 R=0.742 (TP=2227 FP=41 FN=773).
  - FLAG (`--min-confidence 0.40 --decode-depth 10 --decode-size-limit 512KB`,
    identical values): F1=0.8035 P=0.877 R=0.741 (TP=2224 **FP=312** FN=776).
  So the sweep's 0.8642 was a FLAG-PATH artifact that does NOT ship. The real
  benched/shipped F1 with the 0.40 pin is **~0.845** - flat vs the closure 0.8453,
  but precision much improved (FP 194→~45). Recall (FN ~770) is the gap to 0.8919.
  LESSON: bench exactly how the scorer invokes the binary (no flags); flag-path
  tuning is meaningless for the shipped product until DET-10 is fixed.

## New bugs found while verifying the pin

- **DET-10 · HIGH · flag path ≠ baked path for IDENTICAL config values** — passing
  `--min-confidence 0.40 --decode-depth 10 --decode-size-limit 512KB` (the same
  values baked into `ScanConfig::default()`) yields FP=312, but NOT passing them
  (baked defaults) yields FP=41 - same binary, same nominal config, 270-FP gap.
  `build_scanner_config` produces an identical `ScannerConfig` for both, and the
  postprocess floor reads `args.min_confidence.unwrap_or(default)` = 0.40 either
  way. ISOLATED (2026-05-30): the culprit is the `--decode-*` flags, NOT
  `--min-confidence` (mc-only flag → FP=39 ≈ baked 41; decode-only flag → FP=313).
  Yet the resolved values are PROVABLY identical: depth 10 == 10 (sanitise only
  clamps >32), and `parse_byte_size("512KB")` = 512*1024 = 524288 == the baked
  `ScanConfig::default().max_decode_bytes`. So passing `--decode-*` has a side
  effect BEYOND its values. Two suspects found, neither fully explains it yet:
  (1) `orchestrator/mod.rs:132` caps `max_decode_bytes` to 256KB but only when
  `total_memory_mb < 4096` (not flag-gated; same on the 32GB bench box);
  (2) `orchestrator/mod.rs:137` calls `CompiledScanner::compile(detectors)` which
  uses `ScannerConfig::DEFAULT`, not the `scanner_config` built at line 126 -
  i.e. there are multiple config-application paths (the config sprawl). The real
  fix is to collapse to ONE applied config and make the `--decode-*` flag path
  and the baked path resolve through it identically. Until then, flag-path tuning
  is meaningless for the shipped product.

- **DET-12 · MED · the coherence oracle is dead code** — `render_effective_config`
  / `print_effective_config_if_requested` (orchestrator_config.rs:434) exist and
  the doc calls them "the coherence oracle... assert tuned == benched == shipped",
  but `print_effective_config_if_requested` is NEVER CALLED in the scan flow (no
  caller). The env var `KEYHOG_PRINT_EFFECTIVE_CONFIG=1` does nothing. Wire it in
  and add a dogfood test that diffs baked vs flag effective-config (would have
  caught DET-10). Also the doc references a `--print-effective-config` FLAG that
  does not exist (only the env var).

- **DET-13 · MED · low-RAM decode cap diverges from canonical** — `mod.rs:132`
  silently caps `max_decode_bytes` to 256KB when `total_memory_mb < 4096`, so the
  effective decode window on small machines (256KB) != the canonical/documented
  512KB. Either document the cap as a tier or fold it into a single resolved
  config that the effective-config oracle prints.

- **DET-11 · HIGH · ROOT-CAUSED: GPU MoE confidence scorer makes the DEFAULT
  scan non-deterministic AND lower-recall than the CPU path** — 2026-05-30, far
  bigger than first thought. On the 15k mirror, identical back-to-back scans:
    SIMD-pinned (KEYHOG_NO_GPU=1): 2430, 2430 findings  → BIT-STABLE
    default (auto-route):          2353, 2341 findings  → varies AND ~80 fewer
  Root cause: the scan auto-routes by default, and on a discrete-GPU host the
  MoE confidence scorer runs on the GPU. GPU-float MoE produces confidences that
  differ slightly from the CPU MoE, so findings sitting near the global 0.40
  min-confidence floor flip in/out run-to-run - non-deterministic, and the GPU
  scores ~80 of them just UNDER the floor, so the default ships LOWER recall
  than the deterministic CPU path. This is a second parity dimension beyond
  PERF-07 (which fixed the literal/regex FINDING SET): CONFIDENCE is not GPU/CPU-
  equal. Two consequences:
    1. tuned != shipped: the leaderboard's "SIMD" number is NOT what a default
       (GPU) install produces - the default is worse and unstable.
    2. fine detection tuning was flying blind: F1 deltas of ~0.005 are smaller
       than the ±0.02 auto-route swing, so every floor-tuning measurement on the
       default path was noise (see DET-20's reverted broad batch - the "+80 FP"
       was largely this flicker, not the detectors).
  FIX LANDED (bench): score.py now pins KEYHOG_NO_GPU=1 (deterministic CPU MoE +
  SIMD). Result is bit-stable: run1==run2 EXACTLY (F1=0.8757 P=0.9798 R=0.7917
  TP=2375 FP=49 FN=625 with the google+aws floor overrides). All future tuning
  measures this path.
  FIX REMAINING (ship): make GPU MoE confidence deterministic + CPU-equal, OR
  quantise confidence so near-floor flips can't happen, OR run confidence on CPU
  always (GPU MoE is a minor scoring speedup). Until then the DEFAULT scan is
  non-reproducible and slightly lower-recall than `KEYHOG_NO_GPU=1`. Also
  consider a stable secondary sort on the finding set (detector,file,offset)
  before the floor gate so ordering can never matter.

## Recall investigation (2026-05-30) - the corpus discriminator

- A keyword-anchored generic credential detector (catch `*secret*/*api_key* = <value>`)
  was tried two ways and BOTH tank F1: gate-exempt +119 TP / **+1630 FP** (F1→0.669);
  ML-gated (`generic-` id) +21 TP / **+575 FP** (F1→0.767). The SecretBench
  negatives are engineered to defeat keyword+entropy heuristics.
- WHY: the label=false fixtures pack SPECIFIC non-secret decoy shapes into
  credential-named fields - AWS ARNs (`arn:aws:iam::...`), template placeholders
  (`<your-token>`), git commit SHAs, docker digests (`nginx@sha256:...`), npm
  integrity (`sha512-...`), base64-protobuf. The positives are random base64/hex/
  uuid values in the SAME field shapes. So the discriminator is NOT the keyword or
  the value entropy - it is whether the value matches a known DECOY shape.
- DET-14 · the real recall lever: a decoy-AWARE generic assignment detector that
  fires on a credential-keyword assignment but is post-filtered to reject the decoy
  families above (extend `looks_like_hash_digest` + add ARN / docker-digest /
  npm-integrity / `sha256:`/`sha512-` prefix / `<placeholder>` guards). keyhog has
  some guards (`is_known_example_credential`, `looks_like_hash_digest`) but they do
  not cover ARN / sha512-integrity / docker-digest / protobuf, which is why the
  generic detector false-fired. This is the precision-bounded path to recovering
  the ~150 random-value credential-assignment FNs without an FP explosion.
- Other clean levers (no FP risk): DET-15 k8s/json base64 decode-attribution
  (keyhog decodes + reports the inner value; ground truth is the encoded literal,
  so ~67 detected secrets score FN - report the encoded span); DET-16 `sk_test_` /
  GCP `.apps.googleusercontent.com` are detected by existing detectors but dropped
  (test-key / client-safe / confidence-floor) - un-suppress the detected-but-cut.

## Home-turf benchmark (competitors' own fixtures) — 2026-05-30

New diversified corpora under `tools/secretbench/homefield/` harvested from the
competitors' OWN shipped labeled truth (betterleaks `tps`/`fps`, kingfisher
`examples`/`negative_examples`), scored by the canonical `score.py`. Apples-to-
apples (same bare-token files to every tool).

- **DET-17 · HIGH · keyhog LOSES to trufflehog on betterleaks' home turf** —
  betterleaks-turf (116 pos / 201 neg):
    keyhog     F1=0.2132 P=0.259 R=0.181 (TP=21 FP=60 FN=95)
    trufflehog F1=0.3529 P=0.556 R=0.259 (TP=30 FP=24 FN=86)
  keyhog dominates the generic-credential SecretBench mirror (0.845) but loses
  here because betterleaks' 152-rule catalog is SERVICE-SPECIFIC and keyhog has
  fewer named detectors. Two fixable causes:
  1. RECALL — ~40 services keyhog misses entirely (real capability gaps):
     openai-api-key (6 missed!), anthropic-admin-api-key (`sk-ant-admin01-`),
     sumologic-access-token, sourcegraph-access-token, gitea-access-token,
     sidekiq-sensitive-url (12), slack-config/user-token, etsy-access-token,
     grafana-cloud-api-token, greptile-api-key, assemblyai-api-key, cursor-api-key,
     deepgram-api-key, openrouter-api-key, planetscale-id, gitlab-rrt,
     aws-bedrock-api-key, cerebras-api-key, flyio, curl --user / --header inline
     auth. (A few harvested tps are noise — e.g. a `beamer-api-token` "secret"
     that is actually a tree-drawing line — discount those.)
  2. PRECISION — keyhog over-fires on betterleaks' deliberate near-miss
     negatives: gcp-api-key (16!), huggingface-access-token (4), anthropic (2),
     flyio (2), stability-ai (2). The gcp-api-key detector matches the AIza…
     shape too loosely; tighten it against the gcp negatives.
  ACTION (capability roadmap): add the missing service detectors (Tier-B TOMLs)
  and tighten gcp-api-key, then re-run `homefield/run.sh betterleaks` and aim to
  pass trufflehog. Every missed positive here is a "cannot detect X" product gap.

  FULL 4-WAY LEADERBOARD (2026-05-30, pre-detector-additions):
    betterleaks turf (116 pos / 201 neg):
      betterleaks F1=0.607  trufflehog F1=0.353  kingfisher F1=0.444  keyhog F1=0.213
      → keyhog LAST. Loss is recall (service coverage) + the gcp shape-decoys.
    kingfisher turf (1881 pos / 26 neg):
      keyhog F1=0.492 (P=0.997 R=0.327)  trufflehog F1=0.284 (P=0.997 R=0.165)  [home tool pending]
      → keyhog BEATS trufflehog (broader catalog), near-perfect precision (2 FP).
    SecretBench mirror (generic): keyhog 0.845 >> all competitors (0.36-0.53).
  So keyhog is precision-dominant and wins generic + kingfisher turf, but loses
  betterleaks turf on recall. The lever is service-detector breadth, NOT tuning.

  gcp DECISION (no overfit): betterleaks' gcp-api-key NEGATIVES are shape-valid
  `AIzaSy…` decoys it rejects via entropy/allowlist. keyhog's named google-api-key
  detector flags all shape-valid AIza keys by design (recall-first, entropy-
  bypassed). Passing these would require allowlisting betterleaks' specific
  example values = gaming the bench (Law 9). NOT doing that. The only honest
  tightening is an entropy floor that rejects the genuinely-low-entropy decoys
  (e.g. the sequential-alphabet one); realistic AIza decoys stay flagged.

  LANDED + VERIFIED (2026-05-30, first detector batch):
  - openai: added sk-svcacct-/sk-admin- patterns (were 6 FNs). WORKS.
    Mirror F1 improved 0.8455 → **0.8634** (P 0.986, R 0.742→0.768, FP 41→32).
  - grafana-cloud-api-key (glc_/glsa_/eyJrIjoi): WORKS (eyJrIjoi base64 fires).
  - sourcegraph-access-token (sgp_/slk_) + cursor-api-key (key_<64hex>): LOAD but
    do NOT fire — see DET-18 (hex-body shape-gate). Blocked, not value gain yet.
  Home-turf delta (fresh binary on PATH): betterleaks-turf F1 0.213 → **0.293**
  (TP 21→29, FP 60→53); kingfisher-turf 0.492 → 0.495 (P held 0.997).

  ⚠ PROVENANCE NOTE: `score.py` runs `keyhog` from PATH (`shutil.which`). A stale
  `~/.local/bin/keyhog` with the SAME "v0.5.37" version string masqueraded as the
  fresh build and produced a phantom FP=1442 / F1=0.685 "regression" mid-session.
  The fresh build is F1=0.8634. ALWAYS prepend the release dir to PATH (or `cp`
  the fresh binary over `~/.local/bin/keyhog`) before scoring — the version
  string is NOT a reliable provenance signal (collides across builds).

- **DET-18 · HIGH · hex-body service tokens are cut by the confidence floor**
  (CORRECTED — earlier draft mis-blamed the shape-gate; verified it is the
  confidence floor). A new service detector whose token body is hex
  (sourcegraph `sgp_<40hex>`/`slk_<64hex>`, cursor `key_<64hex>`, linode-style
  PATs) LOADS and MATCHES but is dropped: scanned bare at `--min-confidence 0.0`
  it fires (`sourcegraph-access-token`, **confidence 0.28**); at the default
  0.40 floor it is cut. NOT the shape-gate — `strip_hash_algo_prefix` only
  recognizes `sha256:`/`sha512:`/`sha1:`/`md5:` prefixes, so `sgp_<hex>` is
  neither a prefixed- nor bare-hex digest. The real cause: the confidence model
  under-weights the distinctive VENDOR PREFIX (`sgp_`/`key_`) for a low-entropy
  hex body. base62/alphanumeric tokens clear the floor on entropy alone (openai
  sk-svcacct- ~100 base62 chars, anthropic sk-ant-, stripe sk_live_, grafana
  eyJrIjoi). FIX: give a named detector whose match BEGINS WITH its literal
  vendor prefix a confidence boost (the unique prefix is strong evidence the
  value is real, independent of body entropy), then re-score the mirror to
  confirm FP stays ~32 (the boost is gated on the vendor-prefix literal, which
  the sha1/sha256/git-sha decoy negatives do not carry, so no FP reopening).
  EXTENSIBILITY IMPACT: today you cannot add a low-entropy-hex-token service by
  dropping in a TOML — it matches but is floored away silently. Violates the
  Tier-B data-driven contract (a detector should be addable as data). The
  sourcegraph/cursor TOMLs are committed and will activate the moment this
  confidence boost lands.

## Open

- **DET-08 · HIGH · min_confidence is non-monotonic in FP** — raising the floor
  must monotonically reduce findings (FP can only fall). Measured FP went
  173 → 37 → 306 as the floor rose 0.30 → 0.40 → 0.50 (shallow); and 0.50-shallow
  (FP 306) vs 0.50-deep (FP 37) differ 8x. A clean post-filter cannot do this, so
  `min_confidence` is entangled in the scan-time generic gate
  (`engine/fallback_generic.rs`: `confidence < self.config.min_confidence`)
  and/or the ML confidence computation, NOT just the post-scan gate
  (`orchestrator/postprocess.rs:161`). Raising the scan-time floor likely drops
  candidates BEFORE a dedup/suppression step that keyed off them, paradoxically
  releasing more FPs. Fix: make the floor a single, orthogonal post-scan cutoff
  (or prove the scan-time gate is monotonic). Until fixed, 0.40 is a tuned
  sweet-spot, not a principled value. This is the highest-leverage coherence bug
  in the scoring path.

- **DET-09 · HIGH · closure-round recall regression (~132 FN)** — at MATCHED
  config (mc0.30, shallow ≈ pre-closure), the post-closure binary scores
  FN=643 / FP=173 vs pre-closure FN=557 / FP=35. Best achievable post-closure
  config (0.8642) is still below pre-closure 0.8919. So ~86-132 true positives
  were lost to closure-round CODE changes (detection logic), independent of the
  config floor, plus a precision regression (FP 35→37+ floor, but 173 at mc0.30).
  Bisect the 79-file closure round for the detection-logic edits that dropped
  TPs in: cloud-service-credential (-49), database-connection-string (-37),
  api-key (-11), webhook-url-token (-14). These are the categories whose findings
  the closure round demoted/dropped.

- **DET-01 · DONE · discord-bot-token dead detector** — TOML parse error at
  line 34 (single-quote in a single-quoted literal) dropped the detector silently
  (890/891 loaded). Fixed to a triple-quoted literal. Needs the rebuild to embed.
  → also testing T-04 / MC-16 (load-integrity must be a pre-push blocker).

- **DET-19 · MED · CASELESS matching makes lowercase vendor prefixes fire on
  SCREAMING_SNAKE constants** — Hyperscan is compiled `PatternFlags::CASELESS`
  for EVERY pattern (simd.rs:64), so a detector with a lowercase literal prefix
  matches its uppercase form. Proven: `codesandbox-api-token`
  (`csb_[a-zA-Z0-9_-]{20,}`) fires on `CSB_MACHINE_STALLED_BY_CSB_MEMORY` and 3
  more enum names in drivers/gpu/drm/amd/include/soc21_enum.h - 4 false
  positives on a single Linux header. The `[a-zA-Z0-9_-]{20,}` body is the
  culprit: it admits all-uppercase, underscore-heavy identifiers that real
  CodeSandbox tokens (`csb_` + dense base62, no SCREAMING_SNAKE) never take.
  This is a CLASS bug, not one detector: any lowercase 3-4 char vendor prefix
  (`csb_`, `sgp_`, `glpat-`, `sk_`, …) whose body regex allows `_` + uppercase
  will match constants in C/Rust/Go headers. On SecretBench negatives packed
  with credential-named constants this costs precision. Candidate fixes (verify
  each against the scorer, NOT by eyeball): (a) tighten token bodies to exclude
  all-uppercase / require a digit / cap underscores; (b) per-pattern case
  sensitivity (a CASELESS-by-default override so a vendor-prefixed token can opt
  into case-sensitive matching) - mirrors the per-detector min_confidence
  override already shipped (DET-18). Measure FP delta on the mirror before/after;
  do not hand-tune. NOTE: this is independent of the GPU parity work (PERF-07) -
  there the GPU was *missing* these because it lacked CASELESS; now both backends
  agree and BOTH (correctly, per the current detector) emit them, so fixing the
  detector precision fixes both paths at once.

- **DET-20 · recall floor-override campaign (SecretBench mirror, 2026-05-30)** —
  systematic recovery of floor-gated recall. Baseline (post-parity, simd):
  P=0.9799 R=0.7467 F1=0.8475 (TP=2240 FP=46 FN=760). FN by category: cloud-
  service-credential 283, api-key 231, generic-high-entropy 129, db-connection
  66, auth-key 24. A floor-gate analyzer (scan corpus at --min-confidence 0,
  cross-ref manifest, find label=true fixtures whose best overlapping finding
  scores < the 0.40 global floor) found **150 floor-gated recoverable TPs**,
  ALL from vendor-anchored detectors the entropy confidence model under-rates:
  heroku(22), redis-conn(21,conf0.01), google-oauth(19), aws-session(11),
  azure-sub(7), algolia/newrelic(6), asana/datadog/google-api/mongo/twilio(5)…
  WINS KEPT (precise anchors, FP-safe):
    • google-oauth-client-secret min_confidence=0.15 (`.apps.googleusercontent.com`
      anchor; client-ID body scored 0.22)
    • aws-secret-access-key min_confidence=0.25 (mandatory `AWS_SECRET…`/
      `awsSecretKey` anchor; 40-char body scored 0.32)
    → measured: F1 0.8475→0.8528, R +20 TP, **FP 46→40 (precision UP to 0.983)**.
  BROAD BATCH — first judged net-negative on the NON-deterministic auto-route
  path (looked like +80 FP), then RE-MEASURED on the deterministic pinned path
  (DET-11 fix) where it is a clear WIN and is now KEPT:
    google+aws only (deterministic): F1=0.8757 P=0.9798 R=0.7917 TP=2375 FP=49
    + broad 19 vendor floors        : F1=0.8815 P=0.9574 R=0.8167 TP=2450 FP=109
  +75 TP, recall clears the 0.814 target. The apparent precision drop is a
  SCORE.PY ARTIFACT, not real: per-category FP is UNCHANGED at 32 (negatives:
  base64-protobuf 28, …) between the two — i.e. the broad batch adds **ZERO FP
  on the 12 000 negative fixtures** (real specificity stays 99.7%). The +60
  "FP" are ALL the label=true-no-overlap class (a second, non-overlapping
  finding on a fixture that already has its TP), which score.py charges to
  overall FP but not to any category. So the broad floors recover real recall at
  no real-negative cost; the score.py overall-precision metric is pessimistic
  here. (This also explains the score.py-vs-fp_analyze 109-vs-32 gap: fp_analyze
  counts only clean-negative FP = 32; score.py adds the 77 label=true-no-overlap.)
  NET deterministic result of the whole campaign: F1 0.8757→0.8815, R→0.8167
  (target met), +0 negative FP. Remaining headroom to 0.8919: the still-
  undetected shapes (tok_<base62>, bare 40-char terraform values, k8s base64-
  encoded `data:` values needing decode-attribution).
  LESSON: floor-override recovers recall ONLY for detectors whose ANCHOR (not
  just keyword) is specific enough that the body can't be a non-secret; per-
  detector, measured. Connection-strings (redis/mongo/mysql, structurally tight
  `scheme://u:p@host`, score 0.01) are candidates for a near-zero floor after
  the non-determinism fix below.
  BLOCKERS surfaced:
    • DET-11 non-determinism is REAL and ±15 TP run-to-run (score.py: TP
      2334/2319/2317 across identical runs) — this is larger than the F1 deltas
      we're tuning, so fine per-detector floor work is unreliable until fixed.
      Likely parallel/GPU finding-order or a dedup race; must root-cause.
    • TOOLING: score.py reports FP=120 where fp_analyze.py reports FP=41 on the
      SAME state — the two scorers disagree 3x (likely fp_analyze omits the
      label=true-no-overlap FP class). Reconcile; the bench's own tools must
      agree or tuning flies blind.

## DET-12 — cryptographic-private-key collapse FIXED (2026-05-31), F1 0.8902 → 0.9108

Surfaced by `benchmarks/` end-to-end run (gaps table: cryptographic-private-key
F1=0.400, +0.600 behind Kingfisher 1.000). Root-caused on the live binary:

- `ssh-private-key` matched a HEADER-ONLY marker (`-----BEGIN EC PRIVATE KEY-----`)
  with no body capture. Every distinct EC/PKCS#8/RSA/DSA key of a type produced
  the byte-identical credential string, so `DedupScope::Credential` (core/dedup.rs
  keys on `(detector_id, credential)`) correctly folded N distinct leaked keys
  into ONE finding (the rest → additional_locations). Scorer counts primaries →
  N keys scored as 1 TP.
- The header match also WON the per-(file,line) resolver (resolution.rs: service-
  specific +10 NAMED_DETECTOR_SCORE) over the generic `private-key` full-block
  match, so the distinct full-block credential was discarded.
- PGP was spared only because `ssh-private-key`'s regex omitted the PGP header,
  leaving `private-key` (full BEGIN…END capture) to fire → distinct → 26/26.

Proof (112 cryptographic-private-key positives, mirror): 28/112 caught before
(EC 1/26, PKCS#8 PRIVATE KEY 1/47, no-header 0/13, PGP 26/26); a 3-EC-file dir
collapsed to 1 finding. After fix: **112/112** on 112 distinct files
(private-key 26 + ssh-private-key 86). Overall mirror: F1 0.8902→**0.9108**,
R 0.8107→**0.8457**, P 0.9870→0.9868 (flat), 2476→2583 findings.

Fix: `ssh-private-key.toml` now captures the full per-algorithm-paired BEGIN…END
block so each key's credential is distinct, and the homoglyph alternation
compiler preserves the selected branch suffix instead of creating a header-only
fallback regex for full-branch alternations. Migrated the dependent contracts
that relied on ssh's header safety net
(`private-key.toml`, `github-app-private-key.toml`) from bare-header (shape) to
full-block positives asserting body capture; `google-artifact-registry-key` was
self-satisfied (its own JSON-structure regex), unaffected.

Generalization swept (vectors 6/7): no sibling PRIMARY detector captures a
constant. `vertexai-service-account`/`google-artifact-registry-key` capture
variable JSON fields (project_id/client_email) → distinct; docusign's
`BEGIN RSA PRIVATE KEY` is a COMPANION (evidence), not a credential-bearing
finding → cannot collapse. ssh-private-key was the unique instance.
