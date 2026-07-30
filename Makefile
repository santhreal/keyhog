.PHONY: release-check release-prepare docs-check docs-build

VERSION ?=
DATE ?= $(shell date -u +%Y-%m-%d)

release-check:
	@test -n "$(VERSION)" || { echo 'usage: make release-check VERSION=X.Y.Z [DATE=YYYY-MM-DD]' >&2; exit 2; }
	python3 -B -m unittest scripts.tests.test_prepare_release scripts.tests.test_bump_doc_versions scripts.tests.test_release_notes
	python3 -B scripts/prepare_release.py --version "$(VERSION)" --date "$(DATE)"

release-prepare: release-check
	python3 -B scripts/prepare_release.py --version "$(VERSION)" --date "$(DATE)" --apply

# Keep generated README evidence, operator contracts, and mdBook links coherent.
docs-check:
	python3 -B scripts/gates/docs_truth.py
	python3 -B scripts/gates/action_docs_contract.py
	python3 -B scripts/gates/workflow_docs_boundaries.py
	python3 -B -m unittest scripts.tests.test_action_docs_contract scripts.tests.test_workflow_docs_boundaries
	$(MAKE) -C benchmarks readme-matrix-check
	$(MAKE) -C benchmarks readme-scaling-check
	cd docs && mdbook test && mdbook build
	python3 -B scripts/gates/docs_links.py docs/book --site-prefix /keyhog/

docs-build: docs-check
	python3 -B scripts/docs_site.py docs/book
