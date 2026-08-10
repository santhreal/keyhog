# keyhog benchmarking framework - entrypoints.
#
# Every target is a thin wrapper over `python3 -m bench ...` so the logic
# lives in the tested package, not the Makefile. Paths resolve relative to
# this file so it works from any cwd.
#
#   make test              # pytest the bench package
#   make host              # print host hardware JSON
#   make mirror            # generate the 15k synthetic mirror corpus if absent
#   make ioc-recovery-corpus  # generate the 4,368-file P0-P12 recovery corpus
#   make ioc-recovery         # compare all four KeyHog presets on recovery phases
#   make ioc-recovery-axes    # score value/certificate/detector/span/mechanism axes
#   make agentre-corpus       # verify sources and build the pinned Linux binaries
#   make leakage-audit        # prove train/calibration/sealed-test split isolation
#   make creddata          # fetch, repair, and validate pinned Samsung/CredData
#   make bloom             # measure Bloom rejection + bypass parity on CredData F/X records
#   make canonical         # rerun the exact KH-020 mirror run set with Bloom linkage
#   make kernel-info       # print perf corpus info
#   make run               # run SCANNER=keyhog CORPUS=mirror once
#   make analyze           # print top FP/FN examples for SCANNER on CORPUS
#   make bench             # run all SCANNERS over CORPUS -> results/<host>/
#   make leaderboard       # alias of bench (run SCANNERS over CORPUS into OUT)
#   make report            # render reports/ + inject the leaderboard into ../README.md
#   make report-check      # CI gate: fail if the README tables are stale
#   make readme-matrix      # measure CPU/SIMD/GPU/presets/cache/daemon and inject panels
#   make readme-matrix-check # fail if committed matrix reports or README panels drift
#   make readme-scaling     # measure CPU/storage/size/partition scaling and inject tables
#   make readme-scaling-check # fail if committed scaling evidence or README tables drift
#   make org-audit         # fail on stale claims and generated organization bloat
#   make gate              # regression + differential gate (keyhog must lead + not regress)
#   make cross-device-gate # require 10x speed dominance vs Betterleaks/Kingfisher on every OS
#   make loop              # full improvement loop: corpus->leaderboard->calibrate->report->gate
#   make keyhog            # build the release binary (run in background; cargo is slow)

BENCH_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO_ROOT := $(abspath $(BENCH_DIR)/..)
PY        ?= python3
export PYTHONDONTWRITEBYTECODE := 1

# Optional explicit binary override. If unset, the KeyHog adapter resolves the
# freshly built release binary from CARGO_TARGET_DIR, cargo config, repo target,
# then PATH.
SCANNER          ?= keyhog
SCANNERS         ?= keyhog,betterleaks,kingfisher,noseyparker,trufflehog,titus
CANONICAL_SCANNERS ?= keyhog,betterleaks,kingfisher
CANONICAL_BLOOM_RESULT ?= results/bloom-creddata-fx-record-spans-v1.json
CANONICAL_BLOOM_REPORT ?= reports/bloom-creddata-fx-record-spans-v1.md
CANONICAL_BLOOM_STAGED_REPORT ?= results/.bloom-creddata-fx-record-spans-v1.md
CORPUS           ?= mirror
OUTPUT           ?= -
OUT              ?= results
ANALYZE_TOP      ?= 15
IOC_RECOVERY_SAMPLES ?= 336
IOC_RECOVERY_OUT ?= results-ioc-recovery
IOC_RECOVERY_MODE ?= deep
IOC_RECOVERY_AXES_OUT ?= results-ioc-recovery/axes.json
CREDDATA_JOBS ?= 8
LEAKAGE_MANIFEST ?=
LEAKAGE_CONTENT_ROOT ?=
LEAKAGE_RECEIPT ?= reports/leakage-receipt.json
README_MATRIX_CONFIG_OUT ?= results-readme-config
README_MATRIX_DAEMON_OUT ?= results-readme-daemon
README_MATRIX_DAEMON_CORPUS ?= corpora/daemon-file-8mib.txt
README_MATRIX_SNAPSHOT ?= reports/readme-matrix.json
README_MATRIX_AUTOROUTE_CACHE ?=
README_MATRIX_SOURCE_STATE ?= clean
README_SCALING_ROOT ?= corpora/readme-scaling
README_SCALING_SNAPSHOT ?= reports/readme-scaling.json
README_SCALING_TRIALS ?= 3
README_SCALING_WARMUPS ?= 1
README_SCALING_BACKEND ?= simd
README_SCALING_SOURCE_STATE ?= clean
README_SCALING_STORAGE_ARGS ?=
README_SCALING_THREAD_POINTS ?=
README_SCALING_READER_POINTS ?=
README_SCALING_PARTITION_POINTS ?=
README_SCALING_THREAD_ARG = $(if $(strip $(README_SCALING_THREAD_POINTS)),--thread-points "$(README_SCALING_THREAD_POINTS)",)
README_SCALING_READER_ARG = $(if $(strip $(README_SCALING_READER_POINTS)),--reader-points "$(README_SCALING_READER_POINTS)",)
README_SCALING_PARTITION_ARG = $(if $(strip $(README_SCALING_PARTITION_POINTS)),--partition-points "$(README_SCALING_PARTITION_POINTS)",)
README_SCALING_OPTIONAL_ARGS = $(strip $(README_SCALING_STORAGE_ARGS) $(README_SCALING_THREAD_ARG) $(README_SCALING_READER_ARG) $(README_SCALING_PARTITION_ARG))
REPORT_RUN_SET ?= $(if $(filter results,$(OUT)),run-sets/canonical.toml,)
REPORT_RUN_SET_ARG = $(if $(strip $(REPORT_RUN_SET)),--run-set "$(REPORT_RUN_SET)",)

# Gate / loop knobs. The loop measures every available scanner but gates
# keyhog against the required competitors plus the committed regression anchor;
# EPSILON is the allowed F1 slack.
GATE_SCANNERS    ?= keyhog,betterleaks,kingfisher
REQUIRE_COMPETITORS ?= betterleaks,kingfisher
BASELINE         ?= baselines
EPSILON          ?= 0.005
CALIBRATION_OUT  ?= reports/calibration.toml

ifneq ($(strip $(KEYHOG_BIN)),)
export KEYHOG_BIN
endif

.PHONY: help test targets host mirror ioc-recovery-corpus ioc-recovery agentre-corpus leakage-audit creddata bloom canonical readme-matrix-corpus readme-scaling readme-scaling-check readme-matrix readme-matrix-check require-clean-tree kernel-info run analyze bench leaderboard report report-check org-audit gate cross-device-gate loop keyhog clean

help:
	@grep -E '^#   make ' $(lastword $(MAKEFILE_LIST)) | sed 's/^#   /  /'

test:
	cd $(BENCH_DIR) && PYTHONDONTWRITEBYTECODE=1 $(PY) -B -m pytest -p no:cacheprovider -q -m 'not target_spec' bench/tests

targets:
	cd $(BENCH_DIR) && PYTHONDONTWRITEBYTECODE=1 $(PY) -B -m pytest -p no:cacheprovider -q -m target_spec bench/tests

host:
	cd $(BENCH_DIR) && $(PY) -m bench host

mirror:
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.mirror --ensure

ioc-recovery-corpus:
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.ioc_recovery --ensure --samples "$(IOC_RECOVERY_SAMPLES)"

ioc-recovery: ioc-recovery-corpus
	cd $(BENCH_DIR) && $(PY) -m bench leaderboard --corpus ioc-recovery \
		--scanners keyhog --matrix mode --out "$(IOC_RECOVERY_OUT)" --require-available

# Five independent exact axes (value, certificate, detector family, span,
# mechanism) over the phase, holdout, and metamorphic fixture classes. Runs with
# --dedup none because the corpus reuses one value across all thirteen phases of
# a sample, and the default credential dedup would collapse P1-P12 into whichever
# phase the walker reached first.
ioc-recovery-axes: ioc-recovery-corpus
	@test -n "$(KEYHOG_BIN)" || { echo "KEYHOG_BIN is required for the recovery axes" >&2; exit 2; }
	cd $(BENCH_DIR) && $(PY) -m bench.ioc_recovery_axes --keyhog "$(KEYHOG_BIN)" \
		--mode "$(IOC_RECOVERY_MODE)" --out "$(IOC_RECOVERY_AXES_OUT)"

agentre-corpus:
	cd $(BENCH_DIR) && $(PY) -m bench.agentre_build --ensure

leakage-audit:
	@test -n "$(LEAKAGE_MANIFEST)" || { echo "LEAKAGE_MANIFEST is required" >&2; exit 2; }
	@test -n "$(LEAKAGE_CONTENT_ROOT)" || { echo "LEAKAGE_CONTENT_ROOT is required" >&2; exit 2; }
	cd $(BENCH_DIR) && $(PY) -m bench.leakage_guard "$(LEAKAGE_MANIFEST)" \
		--content-root "$(LEAKAGE_CONTENT_ROOT)" --receipt "$(LEAKAGE_RECEIPT)"

creddata:
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.creddata --download --jobs "$(CREDDATA_JOBS)"

bloom:
	@test -n "$(KEYHOG_BIN)" || { echo "KEYHOG_BIN is required for the Bloom differential" >&2; exit 2; }
	cd $(BENCH_DIR) && $(PY) -m bench.bloom --keyhog "$(KEYHOG_BIN)"

canonical:
	@test -n "$(KEYHOG_BIN)" || { echo "KEYHOG_BIN is required for the canonical benchmark" >&2; exit 2; }
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.mirror --ensure
	cd $(BENCH_DIR) && $(PY) -m bench.bloom --keyhog "$(KEYHOG_BIN)" \
		--report "$(CANONICAL_BLOOM_STAGED_REPORT)"
	cd $(BENCH_DIR) && KEYHOG_BENCH_BLOOM_RESULT="$(BENCH_DIR)/$(CANONICAL_BLOOM_RESULT)" \
		$(PY) -m bench leaderboard --corpus mirror --scanners "$(CANONICAL_SCANNERS)" \
		--out results --require-available
	cd $(BENCH_DIR) && $(PY) -m bench.report --results results --corpus mirror \
		--run-set run-sets/canonical.toml --refresh-run-set
	cp "$(BENCH_DIR)/$(CANONICAL_BLOOM_STAGED_REPORT)" "$(BENCH_DIR)/$(CANONICAL_BLOOM_REPORT)"

readme-matrix-corpus:
	cd $(BENCH_DIR) && $(PY) -m bench.readme_matrix \
		--generate-daemon-corpus "$(README_MATRIX_DAEMON_CORPUS)"

# `readme-scaling` is deliberately NOT a prerequisite. It rewrites README.md and
# reports/readme-scaling.json, and the leaderboard below refuses to scan with a
# binary whose tracked workspace is dirty, so chaining them failed every one of
# this target's forty rows with "the tracked KeyHog workspace has uncommitted
# changes" whenever it was run from a clean tree, which is the only tree it can
# run on. Regenerate and commit the scaling evidence first, then run this;
# Commit the scaling refresh first, then run this on the clean tree.
readme-matrix: require-clean-tree readme-matrix-corpus
	cd $(BENCH_DIR) && KEYHOG_BENCH_AUTOROUTE_CACHE="$(README_MATRIX_AUTOROUTE_CACHE)" \
		$(PY) -m bench leaderboard --corpus mirror \
		--scanners keyhog --tier perf --out "$(README_MATRIX_CONFIG_OUT)" --require-available
	cd $(BENCH_DIR) && KEYHOG_BENCH_AUTOROUTE_CACHE="$(README_MATRIX_AUTOROUTE_CACHE)" \
		$(PY) -m bench leaderboard --corpus daemon-file \
		--corpus-root "$(README_MATRIX_DAEMON_CORPUS)" --scanners keyhog --tier perf \
		--out "$(README_MATRIX_DAEMON_OUT)" --require-available
	cd $(BENCH_DIR) && $(PY) -m bench.readme_matrix \
		--config-results "$(README_MATRIX_CONFIG_OUT)" \
		--daemon-results "$(README_MATRIX_DAEMON_OUT)" \
		--daemon-corpus "$(README_MATRIX_DAEMON_CORPUS)" \
		--source-state "$(README_MATRIX_SOURCE_STATE)" --snapshot "$(README_MATRIX_SNAPSHOT)" \
		--reports reports --readme ../README.md --inject

readme-scaling:
	cd $(BENCH_DIR) && $(PY) -m bench.scaling_matrix measure \
		--workspace-root "$(README_SCALING_ROOT)" \
		--snapshot "$(README_SCALING_SNAPSHOT)" --readme ../README.md \
		--trials "$(README_SCALING_TRIALS)" --warmups "$(README_SCALING_WARMUPS)" \
		--backend "$(README_SCALING_BACKEND)" \
		--source-state "$(README_SCALING_SOURCE_STATE)" $(README_SCALING_OPTIONAL_ARGS)

# Every measured row refuses to scan with a binary whose tracked workspace is
# dirty, so say that once, up front, instead of forty times after the work.
require-clean-tree:
	@cd $(REPO_ROOT) && test -z "$$(git status --porcelain -- ':!BACKLOG.md')" || { \
		echo "benchmarks: the tracked workspace is dirty, so no measured row can prove"; \
		echo "  which source its binary came from. Commit or stash, rebuild the binary,"; \
		echo "  then rerun. Regenerating README evidence goes scaling first (it rewrites"; \
		echo "  README.md and reports/readme-scaling.json), commit, then readme-matrix."; \
		cd $(REPO_ROOT) && git status --porcelain -- ':!BACKLOG.md'; \
		exit 1; }

readme-scaling-check:
	cd $(BENCH_DIR) && $(PY) -m bench.scaling_matrix check \
		--snapshot "$(README_SCALING_SNAPSHOT)" --readme ../README.md

readme-matrix-check: readme-scaling-check
	cd $(BENCH_DIR) && $(PY) -m bench.readme_matrix \
		--snapshot "$(README_MATRIX_SNAPSHOT)" --reports reports \
		--readme ../README.md --check

kernel-info:
	cd $(BENCH_DIR) && $(PY) -m bench corpus kernel

run:
	cd $(BENCH_DIR) && $(PY) -m bench run "$(SCANNER)" "$(CORPUS)" --output "$(OUTPUT)"

analyze:
	cd $(BENCH_DIR) && $(PY) -m bench analyze --scanner "$(SCANNER)" --corpus "$(CORPUS)" --top "$(ANALYZE_TOP)"

bench leaderboard:
	cd $(BENCH_DIR) && $(PY) -m bench leaderboard --corpus "$(CORPUS)" --scanners "$(SCANNERS)" --out "$(OUT)" --require-available

report:
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)" $(REPORT_RUN_SET_ARG) --inject

report-check: readme-matrix-check
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)" $(REPORT_RUN_SET_ARG) --check

org-audit:
	cd $(REPO_ROOT) && $(PY) scripts/org_audit.py

# Regression + differential gate. Consumes the existing results/ (run `make
# leaderboard` first, or `make loop` to do the whole chain). Fails non-zero if
# keyhog doesn't lead every available competitor or regresses past BASELINE.
gate:
	cd $(BENCH_DIR) && $(PY) -m bench gate --corpus "$(CORPUS)" --results "$(OUT)" \
		--scanners "$(GATE_SCANNERS)" --baseline "$(BASELINE)" --epsilon "$(EPSILON)" \
		--require-competitors "$(REQUIRE_COMPETITORS)"

cross-device-gate:
	cd $(BENCH_DIR) && $(PY) -m bench cross-device --corpus "$(CORPUS)" \
		--root results-cross-device --dominance-gate --factor 10 \
		--required-oses linux,macos,windows

# Production continuous-improvement loop. One command runs the whole chain:
# scorer self-tests -> ensure corpus -> measure every scanner (detection + speed)
# -> recalibrate per-detector floors -> regenerate README tables -> GATE. A
# regression (competitor overtakes keyhog, or F1 drops past the committed
# baseline) fails the target non-zero. This is the local mirror of the
# bench-nightly + differential-bench workflows.
loop:
	cd $(BENCH_DIR) && PYTHONDONTWRITEBYTECODE=1 $(PY) -B -m pytest -p no:cacheprovider -q -m 'not target_spec' bench/tests
	cd $(BENCH_DIR) && $(PY) -m bench.corpora.mirror --ensure
	cd $(BENCH_DIR) && $(PY) -m bench leaderboard --corpus "$(CORPUS)" --scanners "$(SCANNERS)" --out "$(OUT)" --require-available
	cd $(BENCH_DIR) && $(PY) -m bench calibrate --corpus "$(CORPUS)" --emit-toml "$(CALIBRATION_OUT)"
	cd $(BENCH_DIR) && $(PY) -m bench report --results "$(OUT)" --reports reports --corpus "$(CORPUS)" $(REPORT_RUN_SET_ARG)
	cd $(BENCH_DIR) && $(PY) -m bench gate --corpus "$(CORPUS)" --results "$(OUT)" \
		--scanners "$(GATE_SCANNERS)" --baseline "$(BASELINE)" --epsilon "$(EPSILON)" \
		--require-competitors "$(REQUIRE_COMPETITORS)"
	@echo "loop OK. README injection is a deliberate full-scanner step: make report"

# Build is intentionally NOT auto-run by other targets: cargo workspace
# builds are slow and the harness wants them backgrounded.
keyhog:
	cd $(REPO_ROOT) && cargo build --release -p keyhog --bin keyhog --no-default-features --features ci-lean

clean:
	# Make uses /bin/sh, so use POSIX find instead of a bash globstar. Clean both
	# the importable package and generator modules at every nesting depth.
	cd $(BENCH_DIR) && find bench generators -type d -name __pycache__ -prune -exec rm -rf {} +; rm -rf .pytest_cache
